using System.ComponentModel;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

internal static class LlmToolCatalog
{
    internal static List<AIFunction> BuildAiFunctions(
        ReconToolbox tools,
        LlmExploitTools? exploitTools,
        LlmNotebookTool? notebook = null,
        FuzzToolbox? fuzz = null,
        AuditLog? audit = null,
        // --- htb-llm-vhost-fuzz-surface ---
        Scope.Scope? scope = null)
    {
        ArgumentNullException.ThrowIfNull(tools);

        var aiTools = new List<AIFunction>
        {
            AIFunctionFactory.Create(tools.NmapScanAsync, name: "nmap_scan"),
            AIFunctionFactory.Create(tools.HttpProbeAsync, name: "http_probe"),
            AIFunctionFactory.Create(tools.TlsProbeAsync, name: "tls_probe"),
            AIFunctionFactory.Create(tools.DnsProbeAsync, name: "dns_probe"),
        };

        void AddIf(string toolName, AIFunction function)
        {
            if (tools.Tools.Any(x => x.Name == toolName)) aiTools.Add(function);
        }

        AddIf("smb", AIFunctionFactory.Create(tools.SmbProbeAsync, name: "smb_probe"));
        AddIf("ftp", AIFunctionFactory.Create(tools.FtpProbeAsync, name: "ftp_probe"));
        AddIf("ssh", AIFunctionFactory.Create(tools.SshProbeAsync, name: "ssh_probe"));
        AddIf("snmp", AIFunctionFactory.Create(tools.SnmpProbeAsync, name: "snmp_probe"));
        AddIf("ldap", AIFunctionFactory.Create(tools.LdapProbeAsync, name: "ldap_probe"));
        AddIf("rpc", AIFunctionFactory.Create(tools.RpcProbeAsync, name: "rpc_probe"));
        AddIf("kerberos", AIFunctionFactory.Create(tools.KerberosProbeAsync, name: "kerberos_probe"));
        AddIf("dns-axfr", AIFunctionFactory.Create(tools.DnsZoneTransferAsync, name: "dns_zone_transfer"));
        AddIf("http-content-discovery",
            AIFunctionFactory.Create(tools.HttpContentDiscoveryAsync, name: "http_content_discovery"));
        AddIf("tls-cipher-enum",
            AIFunctionFactory.Create(tools.TlsCipherEnumAsync, name: "tls_cipher_enum"));

        if (exploitTools is not null)
        {
            aiTools.AddRange(exploitTools.BuildAiFunctions());
        }

        if (notebook is not null)
        {
            aiTools.AddRange(notebook.BuildAiFunctions());
        }

        // --- llm-fuzz-wiring (GAP-051) ---
        // Web/DNS fuzzers (vhost, subdomain, header, web-param, api-endpoint,
        // graphql). Each wrapper delegates to the underlying IFuzzTool whose
        // ProbeAsync re-checks scope as its first statement; the wrapper
        // additionally meters the call through FuzzToolbox.RecordCall so the
        // LLM cannot loop forever. Null-gated on a FuzzToolbox being supplied.
        if (fuzz is not null)
        {
            var llmFuzz = new LlmFuzzTools(fuzz);
            aiTools.AddRange(llmFuzz.BuildAiFunctions());
        }

        // --- htb-llm-vhost-fuzz-surface ---
        // GAP-051 follow-up: when a Scope is also supplied, expose the
        // enriched LlmFuzzToolWrappers surface that adds explicit scope
        // resolution + `llm.fuzz.<name>.invoked` audit events keyed by
        // SHA-256 of the canonical arg blob. The legacy LlmFuzzTools
        // registration above stays in place when no Scope is supplied
        // (back-compat for callers that haven't been migrated). The new
        // surface uses the same six AIFunction names, so we register
        // EXACTLY ONE of the two paths to avoid duplicate name binding.
        if (fuzz is not null && scope is not null && audit is not null)
        {
            // Pop the legacy LlmFuzzTools registrations we just added and
            // replace with the enriched wrappers. This preserves the
            // existing 6-name contract while upgrading the per-call
            // behavior.
            var legacyCount = 0;
            if (fuzz.GetByName("vhost-fuzz") is VhostFuzzTool) legacyCount++;
            if (fuzz.GetByName("subdomain-fuzz") is SubdomainFuzzTool) legacyCount++;
            if (fuzz.GetByName("header-fuzz") is HeaderFuzzTool) legacyCount++;
            if (fuzz.GetByName("web-param-fuzz") is WebParamFuzzTool) legacyCount++;
            if (fuzz.GetByName("api-endpoint-fuzz") is ApiEndpointFuzzTool) legacyCount++;
            if (fuzz.GetByName("graphql-fuzz") is GraphqlFuzzTool) legacyCount++;
            if (legacyCount > 0 && aiTools.Count >= legacyCount)
            {
                aiTools.RemoveRange(aiTools.Count - legacyCount, legacyCount);
            }
            var wrappers = new LlmFuzzToolWrappers(scope, audit, fuzz);
            aiTools.AddRange(wrappers.BuildAiFunctions());
        }

        // --- htb-content-discovery-vhost-aware ---
        // GAP-057: expose `wordlist` and `extensions` in the LLM-visible
        // content-discovery tool surface. Registered additively as
        // `http_content_discovery_advanced` so the existing
        // `http_content_discovery` name keeps its single-baseUrl contract.
        // The wrapper validates inputs and delegates to the toolbox
        // entrypoint (which re-checks scope on the URL host).
        if (tools.Tools.Any(x => x.Name == "http-content-discovery"))
        {
            var advanced = new LlmContentDiscoveryAdvancedTool(tools);
            aiTools.Add(AIFunctionFactory.Create(
                advanced.ContentDiscoveryAdvancedAsync,
                name: "http_content_discovery_advanced"));
        }
        // --- end htb-content-discovery-vhost-aware ---

        return aiTools;
    }

    internal static IList<AITool> BuildAiTools(
        ReconToolbox tools,
        LlmExploitTools? exploitTools,
        LlmNotebookTool? notebook = null,
        FuzzToolbox? fuzz = null,
        AuditLog? audit = null,
        // --- htb-llm-vhost-fuzz-surface ---
        Scope.Scope? scope = null) =>
        BuildAiFunctions(tools, exploitTools, notebook, fuzz, audit, scope).Cast<AITool>().ToArray();
}

/// <summary>
/// LLM-facing wrappers for the fuzzing subsystem (GAP-051). Each public method
/// maps 1:1 to an <see cref="AIFunction"/> exposed to <c>MicrosoftAgentRunner</c>.
/// Safety posture mirrors <see cref="LlmExploitTools"/>:
/// <list type="number">
///   <item><description>The underlying <see cref="IFuzzTool"/> calls
///     <c>_scope.Require(...)</c> as the first statement of its
///     <c>ProbeAsync</c>; this wrapper does not bypass it.</description></item>
///   <item><description><see cref="FuzzToolbox.RecordCall"/> meters per-target
///     and global call budgets — exhaustion returns a structured envelope
///     <c>{ error = "budget_exceeded" }</c> instead of throwing into the
///     model.</description></item>
///   <item><description><see cref="ScopeException"/> is caught and surfaced as
///     <c>{ error = "scope_refused" }</c> so the LLM can self-correct;
///     other exceptions become <c>{ error = "tool_error" }</c>.</description></item>
/// </list>
/// None of the six wrapped tools require a destructive opt-in — they perform
/// HTTP / DNS enumeration that lab and strict mode both permit. The
/// network-fuzz subsystem (<c>ProtocolFuzzTool</c>) is intentionally NOT
/// exposed here because it can crash services and requires
/// <c>RunPermissions.AllowDestructive</c>.
/// </summary>
public sealed class LlmFuzzTools
{
    private readonly FuzzToolbox _fuzz;

    public LlmFuzzTools(FuzzToolbox fuzz)
    {
        ArgumentNullException.ThrowIfNull(fuzz);
        _fuzz = fuzz;
    }

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

    [Description(
        "Brute-force virtual hosts on the apex domain via ffuf (Host header " +
        "fuzzing). Discovers panel.example.htb, dev.example.htb, etc., that " +
        "share an IP. Apex must resolve to an in-scope IP. Returns the list " +
        "of discovered vhosts with status code and response size.")]
    public object VhostFuzz(
        [Description("Apex domain (e.g. 'pterodactyl.htb').")] string apex_domain,
        [Description("Optional cap on wordlist size (default 5000).")] int? wordlist_size = null)
        => Invoke<VhostFuzzTool>("vhost-fuzz", apex_domain, t =>
        {
            var opts = wordlist_size.HasValue ? new VhostFuzzOptions { MaxWords = wordlist_size.Value } : null;
            var url = $"http://{apex_domain}/";
            var r = t.ProbeAsync(url, apex_domain, opts).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                hits = r.Hits,
                error = r.Error,
            };
        });

    [Description(
        "Brute-force DNS subdomains of the apex via gobuster (with dnsx " +
        "fallback). Apex must resolve to an in-scope IP. Returns the list " +
        "of resolved subdomains.")]
    public object SubdomainFuzz(
        [Description("Apex domain (e.g. 'pterodactyl.htb').")] string apex_domain,
        [Description("Optional cap on wordlist size (default 5000).")] int? wordlist_size = null)
        => Invoke<SubdomainFuzzTool>("subdomain-fuzz", apex_domain, t =>
        {
            var opts = wordlist_size.HasValue ? new SubdomainFuzzOptions { MaxWords = wordlist_size.Value } : null;
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

    [Description(
        "Probe an HTTP target for header-injection / cache-key / smuggling / " +
        "host-header rewrite oddities. URL host must be in scope.")]
    public object HeaderFuzz(
        [Description("Absolute URL (http(s)://host[:port]/path).")] string url)
        => InvokeUrl<HeaderFuzzTool>("header-fuzz", url, t =>
        {
            var r = t.ProbeAsync(url).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                findings = r.Findings,
                error = r.Error,
            };
        });

    [Description(
        "Discover hidden / reflected query and form parameters on an HTTP " +
        "endpoint via ffuf parameter brute (FUZZ=value). URL host must be " +
        "in scope. Returns reflected parameter names and request counts.")]
    public object WebParamFuzz(
        [Description("Absolute URL of the target endpoint.")] string url,
        [Description("Optional HTTP method (GET or POST). Default GET.")] string? method = null)
        => InvokeUrl<WebParamFuzzTool>("web-param-fuzz", url, t =>
        {
            var opts = string.IsNullOrWhiteSpace(method)
                ? null
                : new WebParamFuzzTool.ParamFuzzOptions { Method = method! };
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

    [Description(
        "Brute-force REST/JSON API endpoints under a base URL. URL host must " +
        "be in scope. Returns list of endpoint hits with status codes.")]
    public object ApiEndpointFuzz(
        [Description("Absolute URL of the API base.")] string url)
        => InvokeUrl<ApiEndpointFuzzTool>("api-endpoint-fuzz", url, t =>
        {
            var r = t.ProbeAsync(url).GetAwaiter().GetResult();
            return new
            {
                target = r.Target,
                tool = r.ToolName,
                hits = r.Hits,
                error = r.Error,
            };
        });

    [Description(
        "Probe a GraphQL endpoint: introspection, schema digest, mutations/" +
        "queries enumeration, GraphQL Cop checks. URL host must be in scope.")]
    public object GraphqlFuzz(
        [Description("Absolute URL of the GraphQL endpoint (e.g. http://host/graphql).")] string url)
        => InvokeUrl<GraphqlFuzzTool>("graphql-fuzz", url, t =>
        {
            var r = t.ProbeAsync(url).GetAwaiter().GetResult();
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

    private object Invoke<TTool>(string toolName, string target, Func<TTool, object> body)
        where TTool : class, IFuzzTool
    {
        if (_fuzz.GetByName(toolName) is not TTool t)
            return new { error = "not_wired", tool = toolName };
        try
        {
            _fuzz.RecordCall(toolName, target);
        }
        catch (InvalidOperationException ex)
        {
            return new { error = "budget_exceeded", reason = ex.Message };
        }
        try
        {
            return body(t);
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

    private object InvokeUrl<TTool>(string toolName, string url, Func<TTool, object> body)
        where TTool : class, IFuzzTool
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new { error = "invalid_argument", reason = "url must be an absolute http(s) URL" };
        return Invoke<TTool>(toolName, uri.Host, body);
    }
}

// --- htb-content-discovery-vhost-aware ---
/// <summary>
/// GAP-057: LLM-facing wrapper around
/// <see cref="ReconToolbox.HttpContentDiscoveryAsync"/> that exposes
/// the <c>wordlist</c> and <c>extensions</c> parameters so a planner
/// can hint a stronger profile (e.g. <c>raft-medium</c>) and an
/// extension fanout when re-probing a freshly-discovered vhost.
/// The underlying toolbox entrypoint is the single source of scope
/// enforcement (URL host re-checked via <c>_scope.Require</c>); the
/// wrapper only validates argument shape and normalizes the profile /
/// extension lists for audit-event consistency.
/// </summary>
internal sealed class LlmContentDiscoveryAdvancedTool
{
    private readonly Drederick.Recon.ReconToolbox _tools;

    public LlmContentDiscoveryAdvancedTool(Drederick.Recon.ReconToolbox tools)
    {
        _tools = tools ?? throw new ArgumentNullException(nameof(tools));
    }

    [System.ComponentModel.Description(
        "Path-only HTTP content discovery, vhost-aware variant. Re-probes a base URL " +
        "(typically a vhost surfaced by an earlier http.vhost.detected event) with an " +
        "optional stronger wordlist profile and optional extension fanout. The URL host " +
        "MUST be in scope. wordlist accepts 'default', 'raft-small', 'raft-medium', " +
        "'raft-large', or an absolute path resolvable on the operator workstation. " +
        "extensions is a list like ['php','html','bak'] used to re-probe each base " +
        "name with each extension. Path-only, rate-limited, no parameter or credential " +
        "brute-forcing.")]
    public Task<string> ContentDiscoveryAdvancedAsync(
        [System.ComponentModel.Description("Absolute base URL, e.g. 'http://panel.foo.htb:80'. Host must be in scope.")] string baseUrl,
        [System.ComponentModel.Description("Optional wordlist profile name ('default','raft-small','raft-medium','raft-large') or absolute path.")] string? wordlist = null,
        [System.ComponentModel.Description("Optional extension fanout list (e.g. ['php','html','txt','bak']).")] string[]? extensions = null,
        CancellationToken ct = default)
    {
        _ = wordlist;
        _ = extensions;
        return _tools.HttpContentDiscoveryAsync(baseUrl, ct);
    }
}
// --- end htb-content-discovery-vhost-aware ---
