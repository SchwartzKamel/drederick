using System.Net;
using System.Net.NetworkInformation;
using Drederick.Audit;
using Drederick.Ops;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

/// <summary>
/// In-process integration coverage of <see cref="VpnPreflight.Run"/> — the
/// orchestrator wired in under the <c>// ANCHOR: vpn-preflight</c> block in
/// Program.cs. These exercise the same code-path without spawning a
/// subprocess.
/// </summary>
public class VpnPreflightIntegrationTests : IDisposable
{
    private readonly string _dir;

    public VpnPreflightIntegrationTests()
    {
        _dir = Path.Combine(AppContext.BaseDirectory, "vpn-preflight-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private sealed class FakeProvider : INetworkInterfaceProvider
    {
        private readonly VpnInterfaceInfo[] _ifaces;
        public FakeProvider(params VpnInterfaceInfo[] ifaces) => _ifaces = ifaces;
        public IEnumerable<VpnInterfaceInfo> GetInterfaces() => _ifaces;
    }

    private static VpnDetector NoVpn() => new VpnDetector(new FakeProvider(
        new VpnInterfaceInfo("eth0", OperationalStatus.Up, new[] { IPAddress.Parse("192.168.1.10") })));

    private static VpnDetector VpnUp() => new VpnDetector(new FakeProvider(
        new VpnInterfaceInfo("tun0", OperationalStatus.Up, new[] { IPAddress.Parse("10.10.14.5") })));

    private string AuditPath() => Path.Combine(_dir, "audit-" + Guid.NewGuid().ToString("N") + ".jsonl");

    [Fact]
    public void HtbTarget_NoVpn_RequireVpn_ReturnsAbort()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "10.10.11.42" }, RequireVpn: true, SkipVpnCheck: false),
            audit, report, stderr, NoVpn());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.AbortNoVpn, outcome);
        Assert.Contains("no tun*/tap* VPN interface is up", stderr.ToString());
        Assert.Contains("\"vpn.preflight.warn\"", File.ReadAllText(audit.Path));
    }

    [Fact]
    public void HtbTarget_VpnUp_ReturnsActive_AndAuditsOk()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "10.129.1.1" }, RequireVpn: true, SkipVpnCheck: false),
            audit, report, stderr, VpnUp());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.VpnActive, outcome);
        Assert.Empty(stderr.ToString());
        var auditText = File.ReadAllText(audit.Path);
        Assert.Contains("\"vpn.preflight.ok\"", auditText);
        Assert.DoesNotContain("\"vpn.preflight.warn\"", auditText);
    }

    [Fact]
    public void NonHtbTarget_NoVpn_ProceedsSilently()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "192.168.1.50" }, RequireVpn: true, SkipVpnCheck: false),
            audit, report, stderr, NoVpn());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.NotHtbTarget, outcome);
        Assert.Empty(stderr.ToString());
        var auditText = File.ReadAllText(audit.Path);
        Assert.DoesNotContain("vpn.preflight.warn", auditText);
        Assert.DoesNotContain("vpn.preflight.ok", auditText);
    }

    [Fact]
    public void SkipVpnCheck_ShortCircuits_EvenForHtbTargets()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "10.10.10.5" }, RequireVpn: true, SkipVpnCheck: true),
            audit, report, stderr, NoVpn());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.Skipped, outcome);
        Assert.Empty(stderr.ToString());
        Assert.Contains("\"vpn.preflight.skipped\"", File.ReadAllText(audit.Path));
    }

    [Fact]
    public void HtbTarget_NoVpn_WithoutRequireVpn_ReturnsWarn()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "10.10.10.5" }, RequireVpn: false, SkipVpnCheck: false),
            audit, report, stderr, NoVpn());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.WarnNoVpn, outcome);
        Assert.Contains("WARNING", stderr.ToString());

        // tooling table should have an 'absent' row for vpn.
        var dbPath = Path.Combine(_dir, "findings.db");
        Assert.True(File.Exists(dbPath));
        using var conn = new SqliteConnection("Data Source=" + dbPath);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT source, path FROM tooling WHERE name = 'vpn'";
        using var r = cmd.ExecuteReader();
        Assert.True(r.Read());
        Assert.Equal("absent", r.GetString(0));
        Assert.Contains("no tun", r.GetString(1));
    }

    [Fact]
    public void HtbHostname_TreatedAsHtbTarget()
    {
        var audit = new AuditLog(AuditPath());
        var report = new SqliteReport(_dir);
        var stderr = new StringWriter();

        var outcome = VpnPreflight.Run(
            new VpnPreflight.Options(new[] { "driver.htb" }, RequireVpn: false, SkipVpnCheck: false),
            audit, report, stderr, NoVpn());

        audit.Dispose();
        Assert.Equal(VpnPreflightOutcome.WarnNoVpn, outcome);
    }
}
