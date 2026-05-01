using System.Net;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Recon;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class SnmpToolTests
{
    private static string NewAuditPath() =>
        Path.Combine(AppContext.BaseDirectory, $"drederick-snmp-{Guid.NewGuid():N}.jsonl");

    // -------------------------------------------------------------------------
    // Stub walker
    // -------------------------------------------------------------------------

    private sealed class StubWalker : ISnmpWalker
    {
        // Per-community, per-subtree responses. Key: (community, subtreeOid).
        private readonly Dictionary<(string Community, string Subtree), (List<(string, string)>? Data, bool Timeout)>
            _responses = new();

        public List<(string Community, string Subtree, IPEndPoint Endpoint)> Calls { get; } = new();

        /// <summary>Configure a successful walk response for the given community + subtree root.</summary>
        public StubWalker OnWalk(
            string community,
            string subtreeOid,
            params (string Oid, string Value)[] rows)
        {
            _responses[(community, subtreeOid)] = (rows.Select(r => (r.Oid, r.Value)).ToList(), false);
            return this;
        }

        /// <summary>Configure a timeout for the given community (applies to any subtree).</summary>
        public StubWalker OnTimeout(string community)
        {
            foreach (var subtree in new[] { "1.3.6.1.2.1.1", "1.3.6.1.2.1.25.4.2", "1.3.6.1.2.1.25.6.3" })
                _responses[(community, subtree)] = (null, true);
            return this;
        }

        public void Walk(
            string community,
            IPEndPoint endpoint,
            string subtreeOid,
            int timeoutMs,
            List<(string Oid, string Value)> output)
        {
            Calls.Add((community, subtreeOid, endpoint));
            if (_responses.TryGetValue((community, subtreeOid), out var r))
            {
                if (r.Timeout) throw new SnmpTimeoutException("stub timeout");
                if (r.Data is not null) output.AddRange(r.Data);
            }
            // No configuration → return empty list (no OIDs, triggers "no OIDs returned" branch)
        }
    }

    // Representative system MIB OIDs in SharpSNMP format (no leading dot).
    private static List<(string, string)> SampleSystemOids() =>
    [
        ("1.3.6.1.2.1.1.1.0", "Linux gateway 6.1.0-13-amd64"),
        ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.8072.3.2.10"),
        ("1.3.6.1.2.1.1.3.0", "123456"),
        ("1.3.6.1.2.1.1.4.0", "admin@example.com"),
        ("1.3.6.1.2.1.1.5.0", "gateway"),
        ("1.3.6.1.2.1.1.6.0", "rack 4"),
        ("1.3.6.1.2.1.1.7.0", "76"),
    ];

    // -------------------------------------------------------------------------
    // Scope tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProbeAsync_Throws_When_Target_Out_Of_Scope()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());
        var walker = new StubWalker();
        var tool = new SnmpTool(scope, audit, walker);

        await Assert.ThrowsAsync<ScopeException>(() => tool.ProbeAsync("192.0.2.9"));
        Assert.Empty(walker.Calls);
    }

    // -------------------------------------------------------------------------
    // Happy-path tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProbeAsync_Public_Works_Populates_System_Oids()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());

        var systemOids = SampleSystemOids();
        var walker = new StubWalker()
            .OnWalk("public", "1.3.6.1.2.1.1", [.. systemOids]);

        var tool = new SnmpTool(scope, audit, walker);
        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(result.Reachable);
        Assert.Equal("public", result.Community);
        Assert.Null(result.Error);
        Assert.Equal(161, result.Port);
        Assert.Equal(7, result.SystemOids.Count);
        Assert.Equal("Linux gateway 6.1.0-13-amd64", result.SystemOids["1.3.6.1.2.1.1.1.0"]);
        Assert.Equal("1.3.6.1.4.1.8072.3.2.10", result.SystemOids["1.3.6.1.2.1.1.2.0"]);
        Assert.Equal("gateway", result.SystemOids["1.3.6.1.2.1.1.5.0"]);

        // Only system-subtree walk should have been called (process/software walked best-effort).
        Assert.Contains(walker.Calls, c => c.Community == "public" && c.Subtree == "1.3.6.1.2.1.1");
    }

    [Fact]
    public async Task ProbeAsync_Public_Fails_Private_Works()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());

        var systemOids = SampleSystemOids();
        var walker = new StubWalker()
            .OnTimeout("public")
            .OnWalk("private", "1.3.6.1.2.1.1", [.. systemOids]);

        var tool = new SnmpTool(scope, audit, walker);
        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.True(result.Reachable);
        Assert.Equal("private", result.Community);
        Assert.Null(result.Error);
        Assert.NotEmpty(result.SystemOids);

        // Attempted "public" first, then "private".
        Assert.Contains(walker.Calls, c => c.Community == "public");
        Assert.Contains(walker.Calls, c => c.Community == "private");
    }

    [Fact]
    public async Task ProbeAsync_All_Communities_Fail_Sets_Error()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());

        var walker = new StubWalker();
        foreach (var c in SnmpTool.DefaultCommunities)
            walker.OnTimeout(c);

        var tool = new SnmpTool(scope, audit, walker);
        var result = await tool.ProbeAsync("10.10.10.5");

        Assert.False(result.Reachable);
        Assert.Equal(string.Empty, result.Community);
        Assert.Empty(result.SystemOids);
        Assert.False(string.IsNullOrWhiteSpace(result.Error));
    }

    [Fact]
    public async Task ProbeAsync_Connection_Refused_Returns_Error_No_Exception()
    {
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(NewAuditPath());

        // All communities time out (simulates closed UDP port or unreachable host).
        var walker = new StubWalker();
        foreach (var c in SnmpTool.DefaultCommunities)
            walker.OnTimeout(c);

        var tool = new SnmpTool(scope, audit, walker);

        // Must not propagate an exception — return a graceful SnmpResult instead.
        var result = await tool.ProbeAsync("10.10.10.5", port: 161);

        Assert.False(result.Reachable);
        Assert.NotNull(result.Error);
        Assert.Equal(161, result.Port);
    }

    // -------------------------------------------------------------------------
    // Audit invariant: community strings must not appear in plaintext
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProbeAsync_Audit_Does_Not_Log_Plaintext_Community()
    {
        var auditPath = NewAuditPath();
        var scope = ScopeLoader.Parse("10.10.10.5");
        using var audit = new AuditLog(auditPath);

        // Use "public" as the canary community that must not appear verbatim.
        const string canary = "public";
        var systemOids = SampleSystemOids();
        var walker = new StubWalker()
            .OnWalk(canary, "1.3.6.1.2.1.1", [.. systemOids]);

        var tool = new SnmpTool(scope, audit, walker);
        await tool.ProbeAsync("10.10.10.5");
        audit.Dispose();

        var lines = await File.ReadAllLinesAsync(auditPath);
        Assert.NotEmpty(lines);

        foreach (var line in lines)
        {
            // Parse as JSON to inspect values, not raw text (avoids false positives
            // if the community appears in a field name like "community_digest").
            var doc = JsonDocument.Parse(line);
            AssertNoPlaintextCommunity(doc.RootElement, canary, line);
        }
    }

    private static void AssertNoPlaintextCommunity(JsonElement element, string community, string line)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                    AssertNoPlaintextCommunity(prop.Value, community, line);
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    AssertNoPlaintextCommunity(item, community, line);
                break;
            case JsonValueKind.String:
                // The community string value must never appear as a standalone JSON string value.
                Assert.NotEqual(community, element.GetString());
                break;
        }
    }
}
