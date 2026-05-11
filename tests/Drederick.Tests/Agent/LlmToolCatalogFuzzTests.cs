using Drederick.Agent;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

/// <summary>
/// GAP-051: validates that <see cref="LlmToolCatalog.BuildAiFunctions"/> exposes
/// the six fuzz wrappers as <c>AIFunction</c>s when a <see cref="FuzzToolbox"/>
/// is supplied, and that the wrappers preserve the load-bearing scope check.
/// </summary>
public class LlmToolCatalogFuzzTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-llmcat-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope() => ScopeLoader.Parse("10.10.10.0/24", "192.168.1.0/24");

    private static ReconToolbox NewReconToolbox(Scope.Scope scope, AuditLog audit)
    {
        var nmap = new NmapTool(scope, audit);
        var http = new HttpProbeTool(scope, audit);
        var tls = new TlsProbeTool(scope, audit);
        var dns = new DnsProbeTool(scope, audit);
        return new ReconToolbox(nmap, http, tls, dns, audit);
    }

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

    [Fact]
    public void BuildAiFunctions_Exposes_All_Six_Fuzz_Tools_When_Toolbox_Provided()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);
            var fuzz = NewFuzzToolboxAllSix(scope, audit);

            var fns = LlmToolCatalog.BuildAiFunctions(recon, exploitTools: null, notebook: null, fuzz: fuzz);

            var names = fns.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            Assert.Contains("vhost_fuzz", names);
            Assert.Contains("subdomain_fuzz", names);
            Assert.Contains("header_fuzz", names);
            Assert.Contains("web_param_fuzz", names);
            Assert.Contains("api_endpoint_fuzz", names);
            Assert.Contains("graphql_fuzz", names);
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public void BuildAiFunctions_Omits_Fuzz_Surface_When_Toolbox_Null()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var recon = NewReconToolbox(scope, audit);

            var fns = LlmToolCatalog.BuildAiFunctions(recon, exploitTools: null, notebook: null, fuzz: null);

            var names = fns.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
            Assert.DoesNotContain("vhost_fuzz", names);
            Assert.DoesNotContain("subdomain_fuzz", names);
            Assert.DoesNotContain("header_fuzz", names);
            Assert.DoesNotContain("web_param_fuzz", names);
            Assert.DoesNotContain("api_endpoint_fuzz", names);
            Assert.DoesNotContain("graphql_fuzz", names);
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public void HeaderFuzz_Wrapper_Returns_ScopeRefused_For_OutOfScope_Url()
    {
        // 8.8.8.8 is not in NewScope() (10.10.10.0/24, 192.168.1.0/24).
        // The underlying HeaderFuzzTool calls _scope.Require(uri.Host) which
        // throws ScopeException. The wrapper must catch it and return a
        // structured envelope instead of letting it bubble into the LLM loop.
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var fuzz = NewFuzzToolboxAllSix(scope, audit);
            var llmFuzz = new LlmFuzzTools(fuzz);

            var result = llmFuzz.HeaderFuzz("http://8.8.8.8/");

            // Anonymous-typed envelope { error = "scope_refused", reason = ... }
            var errorProp = result.GetType().GetProperty("error");
            Assert.NotNull(errorProp);
            Assert.Equal("scope_refused", errorProp!.GetValue(result));
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }

    [Fact]
    public void HeaderFuzz_Wrapper_Returns_InvalidArgument_For_Malformed_Url()
    {
        var scope = NewScope();
        var auditPath = NewAuditPath();
        try
        {
            var audit = new AuditLog(auditPath);
            var fuzz = NewFuzzToolboxAllSix(scope, audit);
            var llmFuzz = new LlmFuzzTools(fuzz);

            var result = llmFuzz.HeaderFuzz("not a url");
            var errorProp = result.GetType().GetProperty("error");
            Assert.Equal("invalid_argument", errorProp!.GetValue(result));
        }
        finally
        {
            try { File.Delete(auditPath); } catch { }
        }
    }
}
