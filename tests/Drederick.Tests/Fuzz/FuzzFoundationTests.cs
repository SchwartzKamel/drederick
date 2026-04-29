using Drederick.Audit;
using Drederick.Recon;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

/// <summary>
/// Tests for the fuzzing subsystem foundation types:
/// <see cref="FuzzCategory"/>, <see cref="IFuzzTool"/>,
/// <see cref="FuzzToolbox"/>. Validates budget enforcement, category filtering,
/// and duplicate-name rejection using stub tool implementations.
/// </summary>
public class FuzzFoundationTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-fuzz-{Guid.NewGuid():N}.jsonl");

    private static Scope.Scope NewScope()
    {
        return ScopeLoader.Parse("10.10.10.0/24", "192.168.1.0/24");
    }

    /// <summary>
    /// Stub <see cref="IFuzzTool"/> for testing <see cref="FuzzToolbox"/>
    /// wiring and budget enforcement. Does not implement any actual fuzzing
    /// logic; just satisfies the interface contract.
    /// </summary>
    private sealed class StubFuzzTool : IFuzzTool
    {
        public StubFuzzTool(string name, FuzzCategory category, string description = "stub tool")
        {
            Name = name;
            Category = category;
            Description = description;
        }

        public string Name { get; }
        public FuzzCategory Category { get; }
        public string Description { get; }
    }

    [Fact]
    public void FuzzCategory_Has_All_Expected_Values()
    {
        // Ensure every category from the spec is present in the enum.
        var values = Enum.GetValues<FuzzCategory>().ToHashSet();

        Assert.Contains(FuzzCategory.Web, values);
        Assert.Contains(FuzzCategory.WebApi, values);
        Assert.Contains(FuzzCategory.Dns, values);
        Assert.Contains(FuzzCategory.Auth, values);
        Assert.Contains(FuzzCategory.Network, values);
        Assert.Contains(FuzzCategory.Mutation, values);

        // And that we haven't added extra undocumented categories by accident.
        Assert.Equal(6, values.Count);
    }

    [Fact]
    public void FuzzToolbox_Throws_When_Duplicate_Tool_Name()
    {
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var tool1 = new StubFuzzTool("param-fuzz", FuzzCategory.Web);
        var tool2 = new StubFuzzTool("param-fuzz", FuzzCategory.Web); // duplicate name

        var ex = Assert.Throws<ArgumentException>(() =>
        {
            _ = new FuzzToolbox(new[] { tool1, tool2 }, audit);
        });

        Assert.Contains("Duplicate fuzz tool name", ex.Message);
        Assert.Contains("param-fuzz", ex.Message);

        File.Delete(auditPath);
    }

    [Fact]
    public void FuzzToolbox_GetByName_Returns_Registered_Tool()
    {
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var tool1 = new StubFuzzTool("param-fuzz", FuzzCategory.Web);
        var tool2 = new StubFuzzTool("subdomain-fuzz", FuzzCategory.Dns);
        var toolbox = new FuzzToolbox(new[] { tool1, tool2 }, audit);

        var found1 = toolbox.GetByName("param-fuzz");
        Assert.NotNull(found1);
        Assert.Equal("param-fuzz", found1.Name);
        Assert.Equal(FuzzCategory.Web, found1.Category);

        var found2 = toolbox.GetByName("subdomain-fuzz");
        Assert.NotNull(found2);
        Assert.Equal("subdomain-fuzz", found2.Name);
        Assert.Equal(FuzzCategory.Dns, found2.Category);

        var notFound = toolbox.GetByName("nonexistent");
        Assert.Null(notFound);

        File.Delete(auditPath);
    }

    [Fact]
    public void FuzzToolbox_ByCategory_Filters_Correctly()
    {
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var webTool1 = new StubFuzzTool("param-fuzz", FuzzCategory.Web);
        var webTool2 = new StubFuzzTool("vhost-fuzz", FuzzCategory.Web);
        var apiTool = new StubFuzzTool("graphql-fuzz", FuzzCategory.WebApi);
        var dnsTool = new StubFuzzTool("subdomain-fuzz", FuzzCategory.Dns);

        var toolbox = new FuzzToolbox(new[] { webTool1, webTool2, apiTool, dnsTool }, audit);

        var webTools = toolbox.ByCategory(FuzzCategory.Web).ToList();
        Assert.Equal(2, webTools.Count);
        Assert.Contains(webTools, t => t.Name == "param-fuzz");
        Assert.Contains(webTools, t => t.Name == "vhost-fuzz");

        var apiTools = toolbox.ByCategory(FuzzCategory.WebApi).ToList();
        Assert.Single(apiTools);
        Assert.Equal("graphql-fuzz", apiTools[0].Name);

        var dnsTools = toolbox.ByCategory(FuzzCategory.Dns).ToList();
        Assert.Single(dnsTools);
        Assert.Equal("subdomain-fuzz", dnsTools[0].Name);

        var networkTools = toolbox.ByCategory(FuzzCategory.Network).ToList();
        Assert.Empty(networkTools);

        File.Delete(auditPath);
    }

    [Fact]
    public void FuzzToolbox_RecordCall_Throws_When_Budget_Exceeded()
    {
        var auditPath = NewAuditPath();
        var audit = new AuditLog(auditPath);

        var tool = new StubFuzzTool("param-fuzz", FuzzCategory.Web);

        // Set a very tight budget: 2 per-target per-tool, 10 total.
        var budget = new ToolBudget(PerTargetPerTool: 2, MaxTotalCalls: 10);
        var toolbox = new FuzzToolbox(new[] { tool }, audit, budget);

        // First call on target1: OK
        toolbox.RecordCall("param-fuzz", "10.10.10.5");
        Assert.Equal(1, toolbox.ToolCallsTotal);

        // Second call on target1: OK (cap is 2)
        toolbox.RecordCall("param-fuzz", "10.10.10.5");
        Assert.Equal(2, toolbox.ToolCallsTotal);

        // Third call on target1: exceeds per-target per-tool cap
        var ex1 = Assert.Throws<InvalidOperationException>(() =>
        {
            toolbox.RecordCall("param-fuzz", "10.10.10.5");
        });
        Assert.Contains("Fuzz budget exceeded", ex1.Message);
        Assert.Contains("param-fuzz", ex1.Message);
        Assert.Contains("10.10.10.5", ex1.Message);
        // Note: global counter was incremented before the per-target check threw
        Assert.Equal(3, toolbox.ToolCallsTotal);

        // But a call on target2 is still OK (different target)
        toolbox.RecordCall("param-fuzz", "10.10.10.6");
        Assert.Equal(4, toolbox.ToolCallsTotal);

        // Continue until global cap (10 total calls).
        // target2: second call
        toolbox.RecordCall("param-fuzz", "10.10.10.6");
        Assert.Equal(5, toolbox.ToolCallsTotal);

        // target3: 2 calls
        toolbox.RecordCall("param-fuzz", "10.10.10.7");
        toolbox.RecordCall("param-fuzz", "10.10.10.7");
        Assert.Equal(7, toolbox.ToolCallsTotal);

        // target4: 2 calls
        toolbox.RecordCall("param-fuzz", "10.10.10.8");
        toolbox.RecordCall("param-fuzz", "10.10.10.8");
        Assert.Equal(9, toolbox.ToolCallsTotal);

        // target5: 1 call (gets us to 10 total)
        toolbox.RecordCall("param-fuzz", "10.10.10.9");
        Assert.Equal(10, toolbox.ToolCallsTotal);

        // Next call exceeds global cap (10 total)
        var ex2 = Assert.Throws<InvalidOperationException>(() =>
        {
            toolbox.RecordCall("param-fuzz", "10.10.10.10");
        });
        Assert.Contains("Total fuzz tool-call budget exceeded", ex2.Message);
        Assert.Contains("10", ex2.Message); // the cap value

        File.Delete(auditPath);
    }
}
