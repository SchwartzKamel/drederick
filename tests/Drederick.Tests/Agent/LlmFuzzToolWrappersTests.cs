using System.Reflection;
using Drederick.Agent;
using Drederick.Audit;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// htb-llm-vhost-fuzz-surface (GAP-051): unit tests for the six LLM-facing
/// fuzz tool wrappers in <see cref="LlmFuzzToolWrappers"/>.
/// </summary>
public class LlmFuzzToolWrappersTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-lfw-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope() => ScopeLoader.Parse("10.10.10.0/24");

    private static FuzzToolbox NewFuzzToolboxAllSix(Scope.Scope scope, AuditLog audit)
    {
        var tools = new IFuzzTool[]
        {
            new VhostFuzzTool(scope, audit),
            new SubdomainFuzzTool(scope, audit),
            new HeaderFuzzTool(scope, audit),
            new WebParamFuzzTool(scope, audit),
            new ApiEndpointFuzzTool(scope, audit),
            new GraphqlFuzzTool(scope, audit),
        };
        return new FuzzToolbox(tools, audit);
    }

    private static LlmFuzzToolWrappers NewWrappers(out AuditLog audit, out string auditPath)
    {
        audit = new AuditLog(auditPath = NewAuditPath());
        var scope = NewScope();
        return new LlmFuzzToolWrappers(scope, audit, NewFuzzToolboxAllSix(scope, audit));
    }

    // -------------------------------------------------------------------
    // 1. Catalog registration: BuildAiFunctions exposes 6 names.
    // -------------------------------------------------------------------
    [Fact]
    public void BuildAiFunctions_Exposes_All_Six_Wrappers()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var fns = w.BuildAiFunctions();
            var names = fns.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            Assert.Contains("vhost_fuzz", names);
            Assert.Contains("subdomain_fuzz", names);
            Assert.Contains("header_fuzz", names);
            Assert.Contains("web_param_fuzz", names);
            Assert.Contains("api_endpoint_fuzz", names);
            Assert.Contains("graphql_fuzz", names);
            Assert.Equal(6, fns.Count);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void Catalog_BuildAiFunctions_With_Scope_And_Fuzz_Has_Six_Names()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var nmap = new Drederick.Recon.NmapTool(scope, audit);
            var http = new Drederick.Recon.HttpProbeTool(scope, audit);
            var tls = new Drederick.Recon.TlsProbeTool(scope, audit);
            var dns = new Drederick.Recon.DnsProbeTool(scope, audit);
            var recon = new Drederick.Recon.ReconToolbox(nmap, http, tls, dns, audit);
            var fuzz = NewFuzzToolboxAllSix(scope, audit);

            var fns = LlmToolCatalog.BuildAiFunctions(
                recon, exploitTools: null, notebook: null, fuzz: fuzz, audit: audit, scope: scope);

            var names = fns.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            // The six new tool names must all be present exactly once.
            Assert.Contains("vhost_fuzz", names);
            Assert.Contains("subdomain_fuzz", names);
            Assert.Contains("header_fuzz", names);
            Assert.Contains("web_param_fuzz", names);
            Assert.Contains("api_endpoint_fuzz", names);
            Assert.Contains("graphql_fuzz", names);
            // No duplicates from concurrent legacy + enriched wiring.
            foreach (var n in new[] { "vhost_fuzz", "subdomain_fuzz", "header_fuzz",
                                       "web_param_fuzz", "api_endpoint_fuzz", "graphql_fuzz" })
            {
                Assert.Single(fns, f => f.Name == n);
            }
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 2. Each wrapper refuses out-of-scope target with scope_refused envelope.
    //    Inputs use 1.1.1.1 / non-resolvable hosts that aren't in 10.10.10.0/24.
    // -------------------------------------------------------------------
    [Fact]
    public void VhostFuzz_Refuses_Out_Of_Scope_Target()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.VhostFuzz("1.1.1.1", "evil.example.com", null);
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void SubdomainFuzz_Refuses_Out_Of_Scope_Apex()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            // Hostname that won't resolve to anything in 10.10.10.0/24.
            var r = w.SubdomainFuzz("1.1.1.1", null);
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void HeaderFuzz_Refuses_Out_Of_Scope_Url()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.HeaderFuzz("http://1.1.1.1/", null);
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void WebParamFuzz_Refuses_Out_Of_Scope_Url()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.WebParamFuzz("http://1.1.1.1/", null);
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void ApiEndpointFuzz_Refuses_Out_Of_Scope_Url()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.ApiEndpointFuzz("http://1.1.1.1/api/", null);
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Fact]
    public void GraphqlFuzz_Refuses_Out_Of_Scope_Url()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.GraphqlFuzz("http://1.1.1.1/graphql");
            AssertEnvelopeError(r, "scope_refused");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 3. Each wrapper records audit event with name + arg hash (no plaintext).
    // -------------------------------------------------------------------
    [Fact]
    public void Wrappers_Record_LlmFuzz_Invoked_Audit_Event_With_Arg_Digest()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var w = new LlmFuzzToolWrappers(scope, audit, NewFuzzToolboxAllSix(scope, audit));

            // Out-of-scope → scope-refused; the audit event should still be
            // written exactly once, with the digest but NOT the wordlist
            // name in plaintext.
            const string sensitiveWordlist = "operator-secret-wordlist.txt";
            _ = w.VhostFuzz("1.1.1.1", "evil.example.com", sensitiveWordlist);

            var lines = File.ReadAllLines(auditPath);
            var invokeLine = lines.FirstOrDefault(l => l.Contains("\"llm.fuzz.vhost-fuzz.invoked\""));
            Assert.NotNull(invokeLine);
            Assert.Contains("\"arg_digest\"", invokeLine!);
            Assert.DoesNotContain(sensitiveWordlist, invokeLine!);
            Assert.DoesNotContain("evil.example.com", invokeLine!);
            // Also assert the digest looks like SHA-256 hex.
            var digestIdx = invokeLine!.IndexOf("\"arg_digest\":\"", StringComparison.Ordinal);
            Assert.True(digestIdx > 0);
            var hexStart = digestIdx + "\"arg_digest\":\"".Length;
            var hex = invokeLine.Substring(hexStart, 64);
            Assert.Matches("^[a-f0-9]{64}$", hex);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    [Theory]
    [InlineData("vhost_fuzz")]
    [InlineData("subdomain_fuzz")]
    [InlineData("header_fuzz")]
    [InlineData("web_param_fuzz")]
    [InlineData("api_endpoint_fuzz")]
    [InlineData("graphql_fuzz")]
    public void Each_Wrapper_Emits_Its_Llm_Fuzz_Invoked_Event(string toolName)
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var w = new LlmFuzzToolWrappers(scope, audit, NewFuzzToolboxAllSix(scope, audit));

            // Drive each wrapper with out-of-scope inputs so the inner tool
            // never spawns a process. The wrapper's audit event must still
            // appear exactly once.
            object _result = toolName switch
            {
                "vhost_fuzz" => w.VhostFuzz("1.1.1.1", "x.com", null),
                "subdomain_fuzz" => w.SubdomainFuzz("1.1.1.1", null),
                "header_fuzz" => w.HeaderFuzz("http://1.1.1.1/", null),
                "web_param_fuzz" => w.WebParamFuzz("http://1.1.1.1/", null),
                "api_endpoint_fuzz" => w.ApiEndpointFuzz("http://1.1.1.1/", null),
                "graphql_fuzz" => w.GraphqlFuzz("http://1.1.1.1/graphql"),
                _ => throw new InvalidOperationException(toolName),
            };

            var innerName = toolName.Replace("_", "-");
            var lines = File.ReadAllLines(auditPath);
            var matches = lines.Where(l =>
                l.Contains($"\"llm.fuzz.{innerName}.invoked\"")).ToList();
            Assert.NotEmpty(matches);
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 4. Invalid URL → invalid_argument envelope (not exception).
    // -------------------------------------------------------------------
    [Fact]
    public void HeaderFuzz_Rejects_NonAbsolute_Url()
    {
        var w = NewWrappers(out var _, out var auditPath);
        try
        {
            var r = w.HeaderFuzz("not-a-url", null);
            AssertEnvelopeError(r, "invalid_argument");
        }
        finally { try { File.Delete(auditPath); } catch { } }
    }

    // -------------------------------------------------------------------
    // 5. ComputeArgDigest is stable and hex-shaped.
    // -------------------------------------------------------------------
    [Fact]
    public void ComputeArgDigest_Is_Stable_Sha256_Hex()
    {
        var blob = new { url = "http://example.com/", wordlist = "x.txt" };
        var d1 = InvokeStatic<string>(typeof(LlmFuzzToolWrappers), "ComputeArgDigest", blob);
        var d2 = InvokeStatic<string>(typeof(LlmFuzzToolWrappers), "ComputeArgDigest", blob);
        Assert.Equal(d1, d2);
        Assert.Matches("^[a-f0-9]{64}$", d1);
    }

    [Fact]
    public void ResolveWordlist_Rejects_Path_Traversal_And_Metachars()
    {
        var r1 = InvokeStatic<string?>(typeof(LlmFuzzToolWrappers), "ResolveWordlist", "../etc/passwd");
        Assert.Null(r1);
        var r2 = InvokeStatic<string?>(typeof(LlmFuzzToolWrappers), "ResolveWordlist", "foo;rm -rf /");
        Assert.Null(r2);
        var r3 = InvokeStatic<string?>(typeof(LlmFuzzToolWrappers), "ResolveWordlist", new object?[] { null });
        Assert.Null(r3);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------
    private static void AssertEnvelopeError(object envelope, string expectedError)
    {
        var t = envelope.GetType();
        var prop = t.GetProperty("error");
        Assert.NotNull(prop);
        Assert.Equal(expectedError, prop!.GetValue(envelope) as string);
    }

    private static T InvokeStatic<T>(Type type, string method, params object?[] args)
    {
        var m = type.GetMethod(
            method,
            BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
        Assert.NotNull(m);
        var result = m!.Invoke(null, args);
        return (T)result!;
    }
}
