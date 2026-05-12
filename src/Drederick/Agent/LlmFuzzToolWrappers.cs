using System.ComponentModel;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

/// <summary>
/// GAP-051 / htb-llm-vhost-fuzz-surface: LLM-facing wrappers for the six
/// HTTP/DNS fuzz tools (<c>vhost_fuzz</c>, <c>subdomain_fuzz</c>,
/// <c>header_fuzz</c>, <c>web_param_fuzz</c>, <c>api_endpoint_fuzz</c>,
/// <c>graphql_fuzz</c>). Each wrapper:
/// <list type="number">
///   <item><description>Validates argument shape (URL is absolute, apex/host
///     is RFC-1123-ish).</description></item>
///   <item><description>As its first authorization act, calls
///     <see cref="Scope.Scope.Require(string)"/> on the IP target — for
///     hostnames, DNS-resolves first and requires at least one resolved IP
///     to be in scope. Belt + braces — the underlying
///     <see cref="IFuzzTool"/> re-checks scope inside its
///     <c>ProbeAsync</c>.</description></item>
///   <item><description>Records an <c>llm.fuzz.&lt;name&gt;.invoked</c>
///     audit event with the SHA-256 digest of the canonical argument blob;
///     no plaintext wordlist names or tokens are logged — only the
///     digest.</description></item>
///   <item><description>Dispatches to the underlying tool via the
///     <see cref="FuzzToolbox"/>, which meters per-target + global call
///     budgets. Budget exhaustion is surfaced as a structured envelope
///     <c>{ error = "budget_exceeded" }</c>; <see cref="ScopeException"/>
///     surfaces as <c>{ error = "scope_refused" }</c>.</description></item>
/// </list>
/// <para>
/// Compared with the prior <c>LlmFuzzTools</c> surface, these wrappers
/// accept named-wordlist hints (e.g. <c>"subdomains-top1m-5000.txt"</c>)
/// that are resolved against common SecLists install locations, and they
/// own the scope check explicitly rather than deferring entirely to the
/// inner tool. The network-fuzz subsystem (<c>ProtocolFuzzTool</c>) is
/// intentionally NOT exposed here because it can crash services and
/// requires <c>RunPermissions.AllowDestructive</c>.
/// </para>
/// </summary>
public sealed class LlmFuzzToolWrappers
{
    private static readonly string[] SeclistsRoots =
    {
        "/usr/share/seclists",
        "/usr/share/wordlists/seclists",
        "/opt/seclists",
        Path.Combine(
            Environment.GetEnvironmentVariable("HOME") ?? string.Empty,
            "seclists"),
    };

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly FuzzToolbox _fuzz;

    public LlmFuzzToolWrappers(Scope.Scope scope, AuditLog audit, FuzzToolbox fuzz)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);
        ArgumentNullException.ThrowIfNull(fuzz);
        _scope = scope;
        _audit = audit;
        _fuzz = fuzz;
    }

    /// <summary>
    /// Build the six AIFunction descriptors. Each wrapper is null-gated on
    /// the corresponding tool being registered in the toolbox so that
    /// partial deployments (e.g. no <c>kr</c> binary → no
    /// <c>api-endpoint-fuzz</c> tool) do not advertise tools that cannot
    /// run.
    /// </summary>
    public IReadOnlyList<AIFunction> BuildAiFunctions()
    {
        var list = new List<AIFunction>();
        if (_fuzz.GetByName("vhost-fuzz") is VhostFuzzTool)
            list.Add(AIFunctionFactory.Create(VhostFuzz, name: "vhost_fuzz"));
        if (_fuzz.GetByName("subdomain-fuzz") is SubdomainFuzzTool)
            list.Add(AIFunctionFactory.Create(SubdomainFuzz, name: "subdomain_fuzz"));
        if (_fuzz.GetByName("header-fuzz") is HeaderFuzzTool)
            list.Add(AIFunctionFactory.Create(HeaderFuzz, name: "header_fuzz"));
        if (_fuzz.GetByName("web-param-fuzz") is WebParamFuzzTool)
            list.Add(AIFunctionFactory.Create(WebParamFuzz, name: "web_param_fuzz"));
        if (_fuzz.GetByName("api-endpoint-fuzz") is ApiEndpointFuzzTool)
            list.Add(AIFunctionFactory.Create(ApiEndpointFuzz, name: "api_endpoint_fuzz"));
        if (_fuzz.GetByName("graphql-fuzz") is GraphqlFuzzTool)
            list.Add(AIFunctionFactory.Create(GraphqlFuzz, name: "graphql_fuzz"));
        return list;
    }

    // ---------------------------------------------------------------------
    // 1. vhost_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Discover hidden virtual hosts on the apex domain via ffuf Host-" +
        "header fuzzing. 'target' is the in-scope IP or URL the panel " +
        "lives on; 'apex_domain' is the DNS apex to brute (e.g. " +
        "'pterodactyl.htb'); 'wordlist_name' optionally selects a " +
        "SecLists-relative wordlist file name (default " +
        "'subdomains-top1m-5000.txt').")]
    public object VhostFuzz(
        [Description("Target URL or IP (must resolve in scope).")] string target,
        [Description("Apex domain to brute (e.g. 'pterodactyl.htb').")] string apex_domain,
        [Description("Optional SecLists-relative wordlist name.")] string? wordlist_name = null)
    {
        return InvokeWithHost("vhost-fuzz", target, new
        {
            target,
            apex_domain,
            wordlist_name,
        }, () =>
        {
            var url = NormalizeUrl(target);
            var opts = new VhostFuzzOptions
            {
                CustomWordlist = ResolveWordlist(wordlist_name),
            };
            if (_fuzz.GetByName("vhost-fuzz") is not VhostFuzzTool t)
                return new { error = "not_wired", tool = "vhost-fuzz" };
            var r = t.ProbeAsync(url, apex_domain, opts).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                hits = r.Hits,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // 2. subdomain_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Brute-force DNS subdomains of the apex via gobuster (dnsx fallback). " +
        "Apex must resolve to an in-scope IP. 'wordlist_name' optionally " +
        "selects a SecLists-relative wordlist file name.")]
    public object SubdomainFuzz(
        [Description("Apex domain (e.g. 'pterodactyl.htb').")] string apex_domain,
        [Description("Optional SecLists-relative wordlist name.")] string? wordlist_name = null)
    {
        return InvokeWithHost("subdomain-fuzz", apex_domain, new
        {
            apex_domain,
            wordlist_name,
        }, () =>
        {
            var opts = new SubdomainFuzzOptions
            {
                CustomWordlist = ResolveWordlist(wordlist_name),
            };
            if (_fuzz.GetByName("subdomain-fuzz") is not SubdomainFuzzTool t)
                return new { error = "not_wired", tool = "subdomain-fuzz" };
            var r = t.ProbeAsync(apex_domain, opts).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                subdomains = r.Subdomains,
                words_tried = r.WordsTried,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // 3. header_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Probe an HTTP target for header-injection / cache-key / smuggling / " +
        "host-header oddities. URL host must be in scope. 'header_wordlist' " +
        "is currently accepted for forward-compatibility but the underlying " +
        "tool selects a curated header probe set; the wordlist name is " +
        "recorded in the audit digest only.")]
    public object HeaderFuzz(
        [Description("Absolute URL (http(s)://host[:port]/path).")] string url,
        [Description("Optional SecLists-relative header wordlist name.")] string? header_wordlist = null)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new { error = "invalid_argument", reason = "url must be absolute" };
        return InvokeWithHost("header-fuzz", uri.Host, new
        {
            url,
            header_wordlist,
        }, () =>
        {
            if (_fuzz.GetByName("header-fuzz") is not HeaderFuzzTool t)
                return new { error = "not_wired", tool = "header-fuzz" };
            var r = t.ProbeAsync(url).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                findings = r.Findings,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // 4. web_param_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Discover hidden / reflected query and form parameters on an HTTP " +
        "endpoint via ffuf / arjun / x8. URL host must be in scope. " +
        "'param_wordlist' optionally selects a SecLists-relative wordlist " +
        "file name passed through to the underlying tool.")]
    public object WebParamFuzz(
        [Description("Absolute URL of the target endpoint.")] string url,
        [Description("Optional SecLists-relative param wordlist name.")] string? param_wordlist = null)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new { error = "invalid_argument", reason = "url must be absolute" };
        return InvokeWithHost("web-param-fuzz", uri.Host, new
        {
            url,
            param_wordlist,
        }, () =>
        {
            if (_fuzz.GetByName("web-param-fuzz") is not WebParamFuzzTool t)
                return new { error = "not_wired", tool = "web-param-fuzz" };
            var opts = new WebParamFuzzTool.ParamFuzzOptions
            {
                CustomWordlist = ResolveWordlist(param_wordlist),
            };
            var r = t.ProbeAsync(url, opts).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                discovered_parameters = r.DiscoveredParameters,
                requests_sent = r.RequestsSent,
                reflected_count = r.ReflectedCount,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // 5. api_endpoint_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Brute-force REST/JSON API endpoints under a base URL. URL host " +
        "must be in scope. 'openapi_hint' is an optional path to an " +
        "OpenAPI/Swagger / kiterunner kite file to seed the endpoint set; " +
        "absent → tool uses its built-in defaults.")]
    public object ApiEndpointFuzz(
        [Description("Absolute base URL of the API (e.g. 'http://target/api/').")] string base_url,
        [Description("Optional path to OpenAPI spec or kiterunner '.kite' file.")] string? openapi_hint = null)
    {
        if (!Uri.TryCreate(base_url, UriKind.Absolute, out var uri))
            return new { error = "invalid_argument", reason = "base_url must be absolute" };
        return InvokeWithHost("api-endpoint-fuzz", uri.Host, new
        {
            base_url,
            openapi_hint,
        }, () =>
        {
            if (_fuzz.GetByName("api-endpoint-fuzz") is not ApiEndpointFuzzTool t)
                return new { error = "not_wired", tool = "api-endpoint-fuzz" };
            ApiFuzzOptions? opts = null;
            if (!string.IsNullOrWhiteSpace(openapi_hint))
            {
                if (openapi_hint.Contains("..", StringComparison.Ordinal))
                    return new { error = "invalid_argument", reason = "openapi_hint contains '..'" };
                if (!File.Exists(openapi_hint))
                    return new { error = "invalid_argument", reason = "openapi_hint not found" };
                opts = new ApiFuzzOptions { KiteFile = openapi_hint };
            }
            var r = t.ProbeAsync(base_url, opts).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                hits = r.Hits,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // 6. graphql_fuzz
    // ---------------------------------------------------------------------
    [Description(
        "Probe a GraphQL endpoint: introspection, schema digest, " +
        "mutations/queries enumeration, GraphQL-Cop checks. URL host must " +
        "be in scope.")]
    public object GraphqlFuzz(
        [Description("Absolute URL of the GraphQL endpoint (e.g. 'http://host/graphql').")] string endpoint_url)
    {
        if (!Uri.TryCreate(endpoint_url, UriKind.Absolute, out var uri))
            return new { error = "invalid_argument", reason = "endpoint_url must be absolute" };
        return InvokeWithHost("graphql-fuzz", uri.Host, new
        {
            endpoint_url,
        }, () =>
        {
            if (_fuzz.GetByName("graphql-fuzz") is not GraphqlFuzzTool t)
                return new { error = "not_wired", tool = "graphql-fuzz" };
            var r = t.ProbeAsync(endpoint_url).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                introspection_enabled = r.IntrospectionEnabled,
                schema_digest = r.SchemaDigest,
                mutations = r.Mutations,
                queries = r.Queries,
                cop_findings = r.CopFindings,
                error = r.Error,
            };
        });
    }

    // ---------------------------------------------------------------------
    // Shared invocation pipeline.
    // ---------------------------------------------------------------------
    private object InvokeWithHost(
        string toolName,
        string hostOrTarget,
        object argBlob,
        Func<object> body)
    {
        // 1. First authorization act: scope-require the host. IP literals
        //    hit Scope.Require directly; hostnames are DNS-resolved and at
        //    least one resolved IP must be in scope.
        string scopeTarget;
        try
        {
            scopeTarget = RequireHostInScope(hostOrTarget);
        }
        catch (ScopeException ex)
        {
            _audit.Record($"llm.fuzz.{toolName}.invoked", new Dictionary<string, object?>
            {
                ["tool"] = toolName,
                ["arg_digest"] = ComputeArgDigest(argBlob),
                ["outcome"] = "scope_refused",
            });
            return new { error = "scope_refused", reason = ex.Message };
        }
        catch (ArgumentException ex)
        {
            return new { error = "invalid_argument", reason = ex.Message };
        }

        // 2. Audit the invocation. ONLY the SHA-256 digest of the
        //    argument blob is logged — no plaintext wordlist names or
        //    URLs (URL host is OK; we record only the digest + tool).
        _audit.Record($"llm.fuzz.{toolName}.invoked", new Dictionary<string, object?>
        {
            ["tool"] = toolName,
            ["arg_digest"] = ComputeArgDigest(argBlob),
            ["scope_target"] = scopeTarget,
        });

        // 3. Budget-meter the call. Exhaustion → structured envelope.
        try
        {
            _fuzz.RecordCall(toolName, scopeTarget);
        }
        catch (InvalidOperationException ex)
        {
            return new { error = "budget_exceeded", reason = ex.Message };
        }

        // 4. Dispatch. The inner ProbeAsync re-checks scope as its first
        //    statement — invariant @scope-in-every-tool.
        try
        {
            return body();
        }
        catch (ScopeException ex)
        {
            return new { error = "scope_refused", reason = ex.Message };
        }
        catch (ArgumentException ex)
        {
            return new { error = "invalid_argument", reason = ex.Message };
        }
        catch (Exception ex)
        {
            return new { error = "tool_error", reason = ex.GetType().Name, message = ex.Message };
        }
    }

    /// <summary>
    /// Resolve a host (IP literal or RFC-1123 hostname) to a scope-required
    /// IP literal string. For IPs: <see cref="Scope.Scope.Require(string)"/>
    /// directly. For hostnames: DNS lookup, then require any resolved IP.
    /// Throws <see cref="ScopeException"/> if neither path yields an
    /// in-scope IP.
    /// </summary>
    private string RequireHostInScope(string hostOrTarget)
    {
        if (string.IsNullOrWhiteSpace(hostOrTarget))
            throw new ArgumentException("host must be a non-empty string.", nameof(hostOrTarget));

        // Strip URL wrapping if the caller handed us a URL by mistake.
        var host = hostOrTarget.Trim();
        if (Uri.TryCreate(host, UriKind.Absolute, out var asUri))
        {
            host = asUri.Host;
        }
        host = host.Trim().Trim('[', ']');

        if (IPAddress.TryParse(host, out _))
        {
            _scope.Require(host);
            return host;
        }

        IPAddress[] addresses;
        try
        {
            addresses = Dns.GetHostAddresses(host);
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"DNS lookup for '{host}' failed; cannot scope-check: {ex.Message}");
        }
        if (addresses.Length == 0)
        {
            throw new ScopeException($"'{host}' did not resolve to any IP addresses.");
        }
        // Require at least one resolved IP to be in scope; record that
        // specific IP as the scope target so budgeting/audit pin to it.
        ScopeException? last = null;
        foreach (var ip in addresses)
        {
            try
            {
                _scope.Require(ip.ToString());
                return ip.ToString();
            }
            catch (ScopeException ex)
            {
                last = ex;
            }
        }
        throw last ?? new ScopeException($"'{host}' resolved to no in-scope IPs.");
    }

    /// <summary>
    /// Map a SecLists-relative wordlist filename to an absolute path,
    /// searching the common SecLists install roots. Returns <c>null</c> if
    /// no candidate exists so the underlying tool falls back to its
    /// built-in defaults. Rejects path traversal and shell metachars.
    /// </summary>
    internal static string? ResolveWordlist(string? wordlistName)
    {
        if (string.IsNullOrWhiteSpace(wordlistName)) return null;
        var name = wordlistName.Trim();
        if (name.Contains("..", StringComparison.Ordinal)) return null;
        if (name.IndexOfAny(new[] { ';', '&', '|', '`', '$', '<', '>', '\n', '\r' }) >= 0) return null;

        // If caller gave us an absolute path that exists, accept verbatim.
        if (Path.IsPathRooted(name) && File.Exists(name)) return name;

        foreach (var root in SeclistsRoots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            if (!Directory.Exists(root)) continue;
            // Common subtree layout: <root>/Discovery/DNS/<name>,
            // <root>/Discovery/Web-Content/<name>, etc. Recursive search
            // is bounded by the SecLists root being small.
            try
            {
                var matches = Directory.EnumerateFiles(root, name, SearchOption.AllDirectories);
                var hit = matches.FirstOrDefault();
                if (hit is not null) return hit;
            }
            catch
            {
                // Permission / IO error — fall through to next root.
            }
        }
        return null;
    }

    /// <summary>
    /// SHA-256 of the canonical JSON form of the argument blob. Used as
    /// the audit fingerprint so plaintext args (which may include URL
    /// paths or wordlist names) are not echoed into <c>audit.jsonl</c>.
    /// </summary>
    internal static string ComputeArgDigest(object argBlob)
    {
        var json = JsonSerializer.Serialize(argBlob);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string NormalizeUrl(string target)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var u)) return u.ToString();
        if (IPAddress.TryParse(target, out _)) return $"http://{target}/";
        return $"http://{target}/";
    }
}
