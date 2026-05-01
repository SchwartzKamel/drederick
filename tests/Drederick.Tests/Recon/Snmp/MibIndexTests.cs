using Drederick.Recon.Snmp;
using Xunit;

namespace Drederick.Tests.Recon.Snmp;

public class MibIndexTests
{
    [Fact]
    public void Embedded_HasMinimumCoverage()
    {
        // The hand-curated table must hit ≥200 mappings (exact + prefix). This
        // guards against accidental regressions in the embedded data block.
        var idx = MibIndex.Embedded;
        Assert.True(
            idx.ExactCount + idx.PrefixCount >= 200,
            $"expected >=200 mappings; got exact={idx.ExactCount} prefix={idx.PrefixCount}");
    }

    [Fact]
    public void Resolve_SysName_Scalar()
    {
        // sysName.0 is the canonical "what's this box called" OID. RFC 3418.
        Assert.Equal("sysName.0", MibIndex.Embedded.Resolve("1.3.6.1.2.1.1.5.0"));
    }

    [Fact]
    public void Resolve_SysDescr_AndCommonScalars()
    {
        var idx = MibIndex.Embedded;
        Assert.Equal("sysDescr.0", idx.Resolve("1.3.6.1.2.1.1.1.0"));
        Assert.Equal("sysObjectID.0", idx.Resolve("1.3.6.1.2.1.1.2.0"));
        Assert.Equal("sysContact.0", idx.Resolve("1.3.6.1.2.1.1.4.0"));
        Assert.Equal("sysLocation.0", idx.Resolve("1.3.6.1.2.1.1.6.0"));
    }

    [Fact]
    public void Resolve_HrSystemUptime()
    {
        // hrSystemUptime.0 — RFC 2790 HOST-RESOURCES-MIB.
        Assert.Equal("hrSystemUptime.0", MibIndex.Embedded.Resolve("1.3.6.1.2.1.25.1.1.0"));
    }

    [Fact]
    public void Resolve_IfTableRow_KeepsIndices()
    {
        // ifDescr for ifIndex 2 → ifDescr.2 (not ifTable.1.2.2 etc.)
        Assert.Equal("ifDescr.2", MibIndex.Embedded.Resolve("1.3.6.1.2.1.2.2.1.2.2"));
    }

    [Fact]
    public void Resolve_TcpConnTableRow()
    {
        // tcpConnState.<addr>.<port>.<addr>.<port>
        var resolved = MibIndex.Embedded.Resolve("1.3.6.1.2.1.6.13.1.1.10.0.0.5.22.10.0.0.1.51234");
        Assert.StartsWith("tcpConnState.", resolved);
    }

    [Fact]
    public void Resolve_CiscoEnterprisePrefix()
    {
        // Anything under 1.3.6.1.4.1.9 must surface "cisco" (or a more
        // specific cisco-rooted symbol like ciscoMgmt) — never bare numeric.
        var idx = MibIndex.Embedded;
        Assert.StartsWith("cisco", idx.Resolve("1.3.6.1.4.1.9.2.1.58.0"));
        Assert.StartsWith("cisco", idx.Resolve("1.3.6.1.4.1.9.9.13.1.3.1.3.1"));
        Assert.Equal("ciscoMgmt", idx.Resolve("1.3.6.1.4.1.9.9"));
    }

    [Fact]
    public void Resolve_NetSnmpAndJuniperPrefix()
    {
        var idx = MibIndex.Embedded;
        Assert.StartsWith("netSnmp", idx.Resolve("1.3.6.1.4.1.8072.1.2.3"));
        // Pick an OID directly under the juniper enterprise root that does
        // NOT fall under a more specific child (jnxMibs/jnxBoxAnatomy).
        Assert.StartsWith("juniper", idx.Resolve("1.3.6.1.4.1.2636.4.99.1"));
    }

    [Fact]
    public void Resolve_UnknownOid_ReturnsNumeric()
    {
        // No prefix matches under iso branch 7. Resolver must round-trip
        // the input rather than throw or invent a name.
        const string unknown = "7.99.99.99.1.2.3";
        Assert.Equal(unknown, MibIndex.Embedded.Resolve(unknown));
    }

    [Fact]
    public void Resolve_EmptyOrNull_HandledGracefully()
    {
        Assert.Equal(string.Empty, MibIndex.Embedded.Resolve(""));
        // Whitespace input is not a valid OID — resolver must round-trip it
        // rather than throw.
        Assert.Equal("   ", MibIndex.Embedded.Resolve("   "));
    }

    [Fact]
    public void LoadWithAugmentation_MissingDir_ReturnsEmbeddedOnly()
    {
        var bogus = Path.Combine(AppContext.BaseDirectory, $"no-such-mibs-{Guid.NewGuid():N}");
        var idx = MibIndex.LoadWithAugmentation(bogus);
        Assert.Equal("sysName.0", idx.Resolve("1.3.6.1.2.1.1.5.0"));
    }

    [Fact]
    public void LoadWithAugmentation_FromSidecarJson()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, $"mibs-aug-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, "oid-map.json"),
                "{\"1.3.6.1.4.1.99999.1\":\"acmeFoo\",\"1.3.6.1.4.1.99999.1.2\":\"acmeBar\"}");

            var idx = MibIndex.LoadWithAugmentation(dir);

            Assert.Equal("acmeFoo", idx.Resolve("1.3.6.1.4.1.99999.1"));
            Assert.Equal("acmeBar", idx.Resolve("1.3.6.1.4.1.99999.1.2"));
            Assert.Equal("sysName.0", idx.Resolve("1.3.6.1.2.1.1.5.0"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void LoadWithAugmentation_FromMibFile_SimpleAssignment()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, $"mibs-mib-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // Minimal SMIv2-shaped MIB referencing the embedded "enterprises"
            // anchor (1.3.6.1.4.1) and chaining one level of children.
            var mib = """
ACME-MIB DEFINITIONS ::= BEGIN

acmeRoot OBJECT IDENTIFIER ::= { enterprises 424242 }

acmeWidget OBJECT IDENTIFIER ::= { acmeRoot 7 }

END
""";
            File.WriteAllText(Path.Combine(dir, "ACME-MIB.txt"), mib);

            var idx = MibIndex.LoadWithAugmentation(dir);

            Assert.Equal("acmeRoot", idx.Resolve("1.3.6.1.4.1.424242"));
            Assert.Equal("acmeWidget", idx.Resolve("1.3.6.1.4.1.424242.7"));
            Assert.Equal("acmeWidget.1.0", idx.Resolve("1.3.6.1.4.1.424242.7.1.0"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void LoadWithAugmentation_DoesNotOverrideEmbedded()
    {
        // Even a malicious sidecar cannot overwrite "sysName" — augmentation
        // is strictly additive for unknown OIDs.
        var dir = Path.Combine(AppContext.BaseDirectory, $"mibs-evil-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, "oid-map.json"),
                "{\"1.3.6.1.2.1.1.5\":\"ATTACKER_OVERRIDE\"}");

            var idx = MibIndex.LoadWithAugmentation(dir);
            Assert.Equal("sysName.0", idx.Resolve("1.3.6.1.2.1.1.5.0"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void LoadWithAugmentation_MalformedSidecarIsIgnored()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, $"mibs-bad-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "oid-map.json"), "{ this is not json");
            var idx = MibIndex.LoadWithAugmentation(dir);
            Assert.Equal("sysName.0", idx.Resolve("1.3.6.1.2.1.1.5.0"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
