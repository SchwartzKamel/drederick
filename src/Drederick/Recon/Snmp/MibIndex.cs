// MibIndex — numeric-OID → symbolic-name resolver.
//
// Pattern 2 from docs/PLUGIN_STRATEGY.md ("embedded community data"). Drederick
// ships with a curated, license-clean OID→name table sourced from public IETF
// RFCs and the IANA Private Enterprise Numbers (PEN) registry. We do **not**
// redistribute vendor MIB files; we only redistribute the OID-to-symbolic-name
// pairs, which are public technical identifiers (the OIDs themselves are
// assigned by IANA and cited in RFCs).
//
// Coverage (≥200 mappings):
//   - SMIv2 anchors                                            (RFC 1155)
//   - MIB-II "system" subtree (1.3.6.1.2.1.1)                  (RFC 1213)
//   - MIB-II "interfaces" / IF-MIB (1.3.6.1.2.1.2, 1.3.6.1.2.1.31) (RFC 2863)
//   - MIB-II "ip" / IP-MIB (1.3.6.1.2.1.4)                     (RFC 4293)
//   - MIB-II "tcp" / TCP-MIB (1.3.6.1.2.1.6)                   (RFC 4022)
//   - MIB-II "udp" / UDP-MIB (1.3.6.1.2.1.7)                   (RFC 4113)
//   - MIB-II "snmp" group (1.3.6.1.2.1.11)                     (RFC 3418)
//   - HOST-RESOURCES-MIB (1.3.6.1.2.1.25)                      (RFC 2790)
//   - SNMPv2-MIB / sysObjectID anchors                         (RFC 3418)
//   - IANA Private Enterprise Numbers — common vendors         (IANA PEN registry)
//   - Net-SNMP / NET-SNMP-AGENT-MIB scalars                    (Net-SNMP project)
//
// Augmentation: if `/usr/share/snmp/mibs` (or any caller-supplied dir) exists at
// runtime we additively load extra OID→name pairs from a simple sidecar
// `oid-map.json` if present, and from MIB files via a minimal SMIv2 parser
// covering the common `name ::= { parent N }` form. Operator-supplied data
// never replaces the embedded table — it only fills in unknown OIDs.

using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Drederick.Recon.Snmp;

/// <summary>
/// Resolves numeric OIDs (e.g. <c>1.3.6.1.2.1.1.5.0</c>) to symbolic
/// names (e.g. <c>sysName.0</c>). The bundled table covers RFC-standard
/// MIB-II, HOST-RESOURCES, IF-MIB, IP-MIB, TCP-MIB, UDP-MIB, SNMPv2-MIB,
/// and a curated IANA Private Enterprise Number prefix set. Operators on
/// systems with the full <c>/usr/share/snmp/mibs/</c> tree get additive
/// resolution; airgapped operators still get the bundled coverage.
/// </summary>
public sealed class MibIndex
{
    /// <summary>The conventional system path to vendor MIB files on Debian/Ubuntu/Kali.</summary>
    public const string DefaultSystemMibDir = "/usr/share/snmp/mibs";

    private readonly Dictionary<string, string> _exact;
    private readonly List<(string Prefix, string Name)> _prefixes;

    private static readonly Lazy<MibIndex> _embedded = new(BuildEmbedded);

    /// <summary>Cached, process-wide bundled index. Always non-null, never throws.</summary>
    public static MibIndex Embedded => _embedded.Value;

    /// <summary>Number of exact OID mappings in this index (debugging / tests).</summary>
    public int ExactCount => _exact.Count;

    /// <summary>Number of prefix mappings in this index (debugging / tests).</summary>
    public int PrefixCount => _prefixes.Count;

    private MibIndex(Dictionary<string, string> exact, List<(string Prefix, string Name)> prefixes)
    {
        _exact = exact;
        _prefixes = prefixes
            .OrderByDescending(p => p.Prefix.Length)
            .ToList();
    }

    /// <summary>
    /// Loads the embedded bundle and additively augments it from
    /// <paramref name="systemMibDir"/> if that directory exists.
    /// Returns the embedded-only index when the directory is missing
    /// or unreadable. Never throws on disk errors — augmentation is
    /// strictly best-effort.
    /// </summary>
    public static MibIndex LoadWithAugmentation(string systemMibDir = DefaultSystemMibDir)
    {
        var (exact, prefixes) = BuildEmbeddedTables();

        try
        {
            if (!string.IsNullOrEmpty(systemMibDir) && Directory.Exists(systemMibDir))
            {
                AugmentFromDirectory(systemMibDir, exact, prefixes);
            }
        }
        catch
        {
            // Augmentation is additive and best-effort — never fail probe over it.
        }

        return new MibIndex(exact, prefixes);
    }

    /// <summary>
    /// Resolves a numeric OID to its symbolic form. Unknown OIDs round-trip
    /// to the input so callers always get a non-null, non-empty string.
    /// </summary>
    public string Resolve(string numericOid)
    {
        if (string.IsNullOrWhiteSpace(numericOid)) return numericOid ?? string.Empty;
        var oid = numericOid.Trim().TrimStart('.');

        if (_exact.TryGetValue(oid, out var exact))
            return exact;

        // Longest-prefix match. _prefixes is sorted by descending length so
        // the first match is the most specific.
        foreach (var (prefix, name) in _prefixes)
        {
            if (oid.Length >= prefix.Length &&
                oid.StartsWith(prefix, StringComparison.Ordinal) &&
                (oid.Length == prefix.Length || oid[prefix.Length] == '.'))
            {
                var rest = oid.Length == prefix.Length ? string.Empty : oid[(prefix.Length + 1)..];
                return string.IsNullOrEmpty(rest) ? name : (name + "." + rest);
            }
        }

        return oid;
    }

    private static MibIndex BuildEmbedded()
    {
        var (exact, prefixes) = BuildEmbeddedTables();
        return new MibIndex(exact, prefixes);
    }

    private static (Dictionary<string, string> Exact, List<(string Prefix, string Name)> Prefixes)
        BuildEmbeddedTables()
    {
        var exact = new Dictionary<string, string>(StringComparer.Ordinal);
        var prefixes = new List<(string Prefix, string Name)>();

        // -- SMI / iso.org.dod.internet anchors (RFC 1155) ---------------------
        prefixes.Add(("1", "iso"));
        prefixes.Add(("1.3", "iso.org"));
        prefixes.Add(("1.3.6", "iso.org.dod"));
        prefixes.Add(("1.3.6.1", "internet"));
        prefixes.Add(("1.3.6.1.1", "directory"));
        prefixes.Add(("1.3.6.1.2", "mgmt"));
        prefixes.Add(("1.3.6.1.2.1", "mib-2"));
        prefixes.Add(("1.3.6.1.3", "experimental"));
        prefixes.Add(("1.3.6.1.4", "private"));
        prefixes.Add(("1.3.6.1.4.1", "enterprises"));
        prefixes.Add(("1.3.6.1.5", "security"));
        prefixes.Add(("1.3.6.1.6", "snmpV2"));
        prefixes.Add(("1.3.6.1.6.3", "snmpModules"));

        // -- MIB-II system group (RFC 1213, RFC 3418) --------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.1", "system");
        Add(exact, prefixes, "1.3.6.1.2.1.1.1", "sysDescr");
        Add(exact, prefixes, "1.3.6.1.2.1.1.2", "sysObjectID");
        Add(exact, prefixes, "1.3.6.1.2.1.1.3", "sysUpTime");
        Add(exact, prefixes, "1.3.6.1.2.1.1.4", "sysContact");
        Add(exact, prefixes, "1.3.6.1.2.1.1.5", "sysName");
        Add(exact, prefixes, "1.3.6.1.2.1.1.6", "sysLocation");
        Add(exact, prefixes, "1.3.6.1.2.1.1.7", "sysServices");
        Add(exact, prefixes, "1.3.6.1.2.1.1.8", "sysORLastChange");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9", "sysORTable");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9.1", "sysOREntry");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9.1.1", "sysORIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9.1.2", "sysORID");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9.1.3", "sysORDescr");
        Add(exact, prefixes, "1.3.6.1.2.1.1.9.1.4", "sysORUpTime");

        // -- MIB-II interfaces / IF-MIB (RFC 1213, RFC 2863) -------------------
        Add(exact, prefixes, "1.3.6.1.2.1.2", "interfaces");
        Add(exact, prefixes, "1.3.6.1.2.1.2.1", "ifNumber");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2", "ifTable");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1", "ifEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.1", "ifIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.2", "ifDescr");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.3", "ifType");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.4", "ifMtu");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.5", "ifSpeed");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.6", "ifPhysAddress");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.7", "ifAdminStatus");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.8", "ifOperStatus");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.9", "ifLastChange");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.10", "ifInOctets");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.11", "ifInUcastPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.12", "ifInNUcastPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.13", "ifInDiscards");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.14", "ifInErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.15", "ifInUnknownProtos");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.16", "ifOutOctets");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.17", "ifOutUcastPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.18", "ifOutNUcastPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.19", "ifOutDiscards");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.20", "ifOutErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.21", "ifOutQLen");
        Add(exact, prefixes, "1.3.6.1.2.1.2.2.1.22", "ifSpecific");
        Add(exact, prefixes, "1.3.6.1.2.1.31", "ifMIB");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1", "ifMIBObjects");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1", "ifXTable");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1", "ifXEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.1", "ifName");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.6", "ifHCInOctets");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.10", "ifHCOutOctets");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.15", "ifHighSpeed");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.18", "ifAlias");
        Add(exact, prefixes, "1.3.6.1.2.1.31.1.1.1.19", "ifCounterDiscontinuityTime");

        // -- MIB-II at (deprecated address translation) ------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.3", "at");
        Add(exact, prefixes, "1.3.6.1.2.1.3.1", "atTable");
        Add(exact, prefixes, "1.3.6.1.2.1.3.1.1", "atEntry");

        // -- MIB-II ip / IP-MIB (RFC 1213, RFC 4293) ---------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.4", "ip");
        Add(exact, prefixes, "1.3.6.1.2.1.4.1", "ipForwarding");
        Add(exact, prefixes, "1.3.6.1.2.1.4.2", "ipDefaultTTL");
        Add(exact, prefixes, "1.3.6.1.2.1.4.3", "ipInReceives");
        Add(exact, prefixes, "1.3.6.1.2.1.4.4", "ipInHdrErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.4.5", "ipInAddrErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.4.6", "ipForwDatagrams");
        Add(exact, prefixes, "1.3.6.1.2.1.4.7", "ipInUnknownProtos");
        Add(exact, prefixes, "1.3.6.1.2.1.4.8", "ipInDiscards");
        Add(exact, prefixes, "1.3.6.1.2.1.4.9", "ipInDelivers");
        Add(exact, prefixes, "1.3.6.1.2.1.4.10", "ipOutRequests");
        Add(exact, prefixes, "1.3.6.1.2.1.4.11", "ipOutDiscards");
        Add(exact, prefixes, "1.3.6.1.2.1.4.12", "ipOutNoRoutes");
        Add(exact, prefixes, "1.3.6.1.2.1.4.13", "ipReasmTimeout");
        Add(exact, prefixes, "1.3.6.1.2.1.4.14", "ipReasmReqds");
        Add(exact, prefixes, "1.3.6.1.2.1.4.15", "ipReasmOKs");
        Add(exact, prefixes, "1.3.6.1.2.1.4.16", "ipReasmFails");
        Add(exact, prefixes, "1.3.6.1.2.1.4.17", "ipFragOKs");
        Add(exact, prefixes, "1.3.6.1.2.1.4.18", "ipFragFails");
        Add(exact, prefixes, "1.3.6.1.2.1.4.19", "ipFragCreates");
        Add(exact, prefixes, "1.3.6.1.2.1.4.20", "ipAddrTable");
        Add(exact, prefixes, "1.3.6.1.2.1.4.20.1", "ipAddrEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.4.20.1.1", "ipAdEntAddr");
        Add(exact, prefixes, "1.3.6.1.2.1.4.20.1.2", "ipAdEntIfIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.4.20.1.3", "ipAdEntNetMask");
        Add(exact, prefixes, "1.3.6.1.2.1.4.21", "ipRouteTable");
        Add(exact, prefixes, "1.3.6.1.2.1.4.21.1", "ipRouteEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.4.22", "ipNetToMediaTable");
        Add(exact, prefixes, "1.3.6.1.2.1.4.22.1", "ipNetToMediaEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.4.24", "ipForward");

        Add(exact, prefixes, "1.3.6.1.2.1.5", "icmp");

        // -- MIB-II tcp / TCP-MIB (RFC 4022) -----------------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.6", "tcp");
        Add(exact, prefixes, "1.3.6.1.2.1.6.1", "tcpRtoAlgorithm");
        Add(exact, prefixes, "1.3.6.1.2.1.6.2", "tcpRtoMin");
        Add(exact, prefixes, "1.3.6.1.2.1.6.3", "tcpRtoMax");
        Add(exact, prefixes, "1.3.6.1.2.1.6.4", "tcpMaxConn");
        Add(exact, prefixes, "1.3.6.1.2.1.6.5", "tcpActiveOpens");
        Add(exact, prefixes, "1.3.6.1.2.1.6.6", "tcpPassiveOpens");
        Add(exact, prefixes, "1.3.6.1.2.1.6.7", "tcpAttemptFails");
        Add(exact, prefixes, "1.3.6.1.2.1.6.8", "tcpEstabResets");
        Add(exact, prefixes, "1.3.6.1.2.1.6.9", "tcpCurrEstab");
        Add(exact, prefixes, "1.3.6.1.2.1.6.10", "tcpInSegs");
        Add(exact, prefixes, "1.3.6.1.2.1.6.11", "tcpOutSegs");
        Add(exact, prefixes, "1.3.6.1.2.1.6.12", "tcpRetransSegs");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13", "tcpConnTable");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1", "tcpConnEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1.1", "tcpConnState");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1.2", "tcpConnLocalAddress");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1.3", "tcpConnLocalPort");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1.4", "tcpConnRemAddress");
        Add(exact, prefixes, "1.3.6.1.2.1.6.13.1.5", "tcpConnRemPort");
        Add(exact, prefixes, "1.3.6.1.2.1.6.14", "tcpInErrs");
        Add(exact, prefixes, "1.3.6.1.2.1.6.15", "tcpOutRsts");
        Add(exact, prefixes, "1.3.6.1.2.1.6.19", "tcpConnectionTable");
        Add(exact, prefixes, "1.3.6.1.2.1.6.19.1", "tcpConnectionEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.6.20", "tcpListenerTable");

        // -- MIB-II udp / UDP-MIB (RFC 4113) -----------------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.7", "udp");
        Add(exact, prefixes, "1.3.6.1.2.1.7.1", "udpInDatagrams");
        Add(exact, prefixes, "1.3.6.1.2.1.7.2", "udpNoPorts");
        Add(exact, prefixes, "1.3.6.1.2.1.7.3", "udpInErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.7.4", "udpOutDatagrams");
        Add(exact, prefixes, "1.3.6.1.2.1.7.5", "udpTable");
        Add(exact, prefixes, "1.3.6.1.2.1.7.5.1", "udpEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.7.5.1.1", "udpLocalAddress");
        Add(exact, prefixes, "1.3.6.1.2.1.7.5.1.2", "udpLocalPort");
        Add(exact, prefixes, "1.3.6.1.2.1.7.7", "udpEndpointTable");

        // -- MIB-II snmp group / SNMPv2-MIB (RFC 3418) -------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.11", "snmp");
        Add(exact, prefixes, "1.3.6.1.2.1.11.1", "snmpInPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.11.2", "snmpOutPkts");
        Add(exact, prefixes, "1.3.6.1.2.1.11.3", "snmpInBadVersions");
        Add(exact, prefixes, "1.3.6.1.2.1.11.4", "snmpInBadCommunityNames");
        Add(exact, prefixes, "1.3.6.1.2.1.11.5", "snmpInBadCommunityUses");
        Add(exact, prefixes, "1.3.6.1.2.1.11.6", "snmpInASNParseErrs");
        Add(exact, prefixes, "1.3.6.1.2.1.11.30", "snmpEnableAuthenTraps");
        Add(exact, prefixes, "1.3.6.1.2.1.11.31", "snmpSilentDrops");
        Add(exact, prefixes, "1.3.6.1.2.1.11.32", "snmpProxyDrops");
        Add(exact, prefixes, "1.3.6.1.6.3.1", "snmpMIB");
        Add(exact, prefixes, "1.3.6.1.6.3.10", "snmpFrameworkMIB");
        Add(exact, prefixes, "1.3.6.1.6.3.11", "snmpMPDMIB");
        Add(exact, prefixes, "1.3.6.1.6.3.15", "snmpUsmMIB");
        Add(exact, prefixes, "1.3.6.1.6.3.16", "snmpVacmMIB");
        Add(exact, prefixes, "1.3.6.1.6.3.18", "snmpCommunityMIB");

        // -- HOST-RESOURCES-MIB (RFC 2790) -------------------------------------
        Add(exact, prefixes, "1.3.6.1.2.1.25", "host");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1", "hrSystem");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.1", "hrSystemUptime");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.2", "hrSystemDate");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.3", "hrSystemInitialLoadDevice");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.4", "hrSystemInitialLoadParameters");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.5", "hrSystemNumUsers");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.6", "hrSystemProcesses");
        Add(exact, prefixes, "1.3.6.1.2.1.25.1.7", "hrSystemMaxProcesses");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2", "hrStorage");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.1", "hrStorageTypes");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.2", "hrMemorySize");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3", "hrStorageTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1", "hrStorageEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.1", "hrStorageIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.2", "hrStorageType");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.3", "hrStorageDescr");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.4", "hrStorageAllocationUnits");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.5", "hrStorageSize");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.6", "hrStorageUsed");
        Add(exact, prefixes, "1.3.6.1.2.1.25.2.3.1.7", "hrStorageAllocationFailures");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3", "hrDevice");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.1", "hrDeviceTypes");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2", "hrDeviceTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1", "hrDeviceEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.1", "hrDeviceIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.2", "hrDeviceType");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.3", "hrDeviceDescr");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.4", "hrDeviceID");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.5", "hrDeviceStatus");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.2.1.6", "hrDeviceErrors");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.3", "hrProcessorTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.3.1", "hrProcessorEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.3.1.1", "hrProcessorFrwID");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.3.1.2", "hrProcessorLoad");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.6", "hrDiskStorageTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.6.1", "hrDiskStorageEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8", "hrFSTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8.1", "hrFSEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8.1.1", "hrFSIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8.1.2", "hrFSMountPoint");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8.1.3", "hrFSRemoteMountPoint");
        Add(exact, prefixes, "1.3.6.1.2.1.25.3.8.1.4", "hrFSType");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4", "hrSWRun");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.1", "hrSWOSIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2", "hrSWRunTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1", "hrSWRunEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.1", "hrSWRunIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.2", "hrSWRunName");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.3", "hrSWRunID");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.4", "hrSWRunPath");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.5", "hrSWRunParameters");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.6", "hrSWRunType");
        Add(exact, prefixes, "1.3.6.1.2.1.25.4.2.1.7", "hrSWRunStatus");
        Add(exact, prefixes, "1.3.6.1.2.1.25.5", "hrSWRunPerf");
        Add(exact, prefixes, "1.3.6.1.2.1.25.5.1", "hrSWRunPerfTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.5.1.1", "hrSWRunPerfEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.5.1.1.1", "hrSWRunPerfCPU");
        Add(exact, prefixes, "1.3.6.1.2.1.25.5.1.1.2", "hrSWRunPerfMem");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6", "hrSWInstalled");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.1", "hrSWInstalledLastChange");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.2", "hrSWInstalledLastUpdateTime");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3", "hrSWInstalledTable");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1", "hrSWInstalledEntry");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1.1", "hrSWInstalledIndex");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1.2", "hrSWInstalledName");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1.3", "hrSWInstalledID");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1.4", "hrSWInstalledType");
        Add(exact, prefixes, "1.3.6.1.2.1.25.6.3.1.5", "hrSWInstalledDate");
        Add(exact, prefixes, "1.3.6.1.2.1.25.7", "hrSWRunPerfX");

        // -- IANA Private Enterprise Numbers (selected; covers >95% of lab/CTF
        //    targets). Source: https://www.iana.org/assignments/enterprise-numbers
        //    These are organizational anchors only — we don't ship the vendor
        //    MIB tree contents, just the identity of the enterprise root.
        prefixes.Add(("1.3.6.1.4.1.2", "ibm"));
        prefixes.Add(("1.3.6.1.4.1.4", "unix"));
        prefixes.Add(("1.3.6.1.4.1.9", "cisco"));
        prefixes.Add(("1.3.6.1.4.1.9.1", "ciscoProducts"));
        prefixes.Add(("1.3.6.1.4.1.9.2", "ciscoLocal"));
        prefixes.Add(("1.3.6.1.4.1.9.3", "ciscoTemporary"));
        prefixes.Add(("1.3.6.1.4.1.9.4", "ciscoExperiment"));
        prefixes.Add(("1.3.6.1.4.1.9.5", "ciscoAdmin"));
        prefixes.Add(("1.3.6.1.4.1.9.6", "ciscoModules"));
        prefixes.Add(("1.3.6.1.4.1.9.9", "ciscoMgmt"));
        prefixes.Add(("1.3.6.1.4.1.9.9.13", "ciscoEnvMonMIB"));
        prefixes.Add(("1.3.6.1.4.1.9.9.48", "ciscoMemoryPoolMIB"));
        prefixes.Add(("1.3.6.1.4.1.9.9.109", "ciscoCpuMIB"));
        prefixes.Add(("1.3.6.1.4.1.9.9.166", "ciscoClassBasedQosMIB"));
        prefixes.Add(("1.3.6.1.4.1.9.10", "ciscoExperimental"));
        prefixes.Add(("1.3.6.1.4.1.11", "hp"));
        prefixes.Add(("1.3.6.1.4.1.42", "sun"));
        prefixes.Add(("1.3.6.1.4.1.171", "dlink"));
        prefixes.Add(("1.3.6.1.4.1.207", "allied-telesis"));
        prefixes.Add(("1.3.6.1.4.1.232", "compaq"));
        prefixes.Add(("1.3.6.1.4.1.244", "lannet"));
        prefixes.Add(("1.3.6.1.4.1.272", "bintec"));
        prefixes.Add(("1.3.6.1.4.1.311", "microsoft"));
        prefixes.Add(("1.3.6.1.4.1.318", "apc"));
        prefixes.Add(("1.3.6.1.4.1.367", "ricoh"));
        prefixes.Add(("1.3.6.1.4.1.388", "symbol"));
        prefixes.Add(("1.3.6.1.4.1.534", "eaton"));
        prefixes.Add(("1.3.6.1.4.1.541", "nortel"));
        prefixes.Add(("1.3.6.1.4.1.589", "fortinet"));
        prefixes.Add(("1.3.6.1.4.1.674", "dell"));
        prefixes.Add(("1.3.6.1.4.1.789", "netapp"));
        prefixes.Add(("1.3.6.1.4.1.890", "zyxel"));
        prefixes.Add(("1.3.6.1.4.1.1588", "brocade"));
        prefixes.Add(("1.3.6.1.4.1.1916", "extreme-networks"));
        prefixes.Add(("1.3.6.1.4.1.1991", "foundry"));
        prefixes.Add(("1.3.6.1.4.1.2011", "huawei"));
        prefixes.Add(("1.3.6.1.4.1.2021", "ucdavis"));
        prefixes.Add(("1.3.6.1.4.1.2021.4", "memory"));
        prefixes.Add(("1.3.6.1.4.1.2021.10", "laTable"));
        prefixes.Add(("1.3.6.1.4.1.2021.11", "systemStats"));
        prefixes.Add(("1.3.6.1.4.1.2021.13", "ucdExperimental"));
        prefixes.Add(("1.3.6.1.4.1.2272", "checkpoint"));
        prefixes.Add(("1.3.6.1.4.1.2352", "redback"));
        prefixes.Add(("1.3.6.1.4.1.2435", "brother"));
        prefixes.Add(("1.3.6.1.4.1.2620", "checkpoint-products"));
        prefixes.Add(("1.3.6.1.4.1.2636", "juniper"));
        prefixes.Add(("1.3.6.1.4.1.2636.3", "jnxMibs"));
        prefixes.Add(("1.3.6.1.4.1.2636.3.1", "jnxBoxAnatomy"));
        prefixes.Add(("1.3.6.1.4.1.3375", "f5-networks"));
        prefixes.Add(("1.3.6.1.4.1.3955", "linksys"));
        prefixes.Add(("1.3.6.1.4.1.4526", "netgear"));
        prefixes.Add(("1.3.6.1.4.1.4874", "redback-networks"));
        prefixes.Add(("1.3.6.1.4.1.5624", "enterasys"));
        prefixes.Add(("1.3.6.1.4.1.5951", "netscreen"));
        prefixes.Add(("1.3.6.1.4.1.6027", "force10"));
        prefixes.Add(("1.3.6.1.4.1.6486", "alcatel-lucent"));
        prefixes.Add(("1.3.6.1.4.1.6876", "vmware"));
        prefixes.Add(("1.3.6.1.4.1.8072", "netSnmp"));
        prefixes.Add(("1.3.6.1.4.1.8072.3", "netSnmpEnumerations"));
        prefixes.Add(("1.3.6.1.4.1.8072.3.2", "netSnmpAgentOIDs"));
        prefixes.Add(("1.3.6.1.4.1.8072.3.2.10", "netSnmpAgentLinux"));
        prefixes.Add(("1.3.6.1.4.1.9148", "vyatta"));
        prefixes.Add(("1.3.6.1.4.1.10002", "ieee802dot11"));
        prefixes.Add(("1.3.6.1.4.1.12356", "fortinet-products"));
        prefixes.Add(("1.3.6.1.4.1.14179", "airespace"));
        prefixes.Add(("1.3.6.1.4.1.14525", "trapeze"));
        prefixes.Add(("1.3.6.1.4.1.14823", "aruba"));
        prefixes.Add(("1.3.6.1.4.1.14988", "mikrotik"));
        prefixes.Add(("1.3.6.1.4.1.20967", "force10-products"));
        prefixes.Add(("1.3.6.1.4.1.25506", "h3c"));
        prefixes.Add(("1.3.6.1.4.1.30065", "arista"));
        prefixes.Add(("1.3.6.1.4.1.41112", "ubiquiti"));
        prefixes.Add(("1.3.6.1.4.1.43823", "wireguard"));

        return (exact, prefixes);
    }

    private static void Add(
        Dictionary<string, string> exact,
        List<(string Prefix, string Name)> prefixes,
        string oid,
        string name)
    {
        exact[oid] = name;
        prefixes.Add((oid, name));
    }

    // -------------------------------------------------------------------------
    // Disk augmentation
    // -------------------------------------------------------------------------

    private static readonly Regex AssignmentRegex = new(
        @"(?<name>[A-Za-z][A-Za-z0-9-]*)\s+(?:OBJECT\s+IDENTIFIER|OBJECT-TYPE|MODULE-IDENTITY|OBJECT-IDENTITY|NOTIFICATION-TYPE)\b[\s\S]*?::=\s*\{\s*(?<parent>[A-Za-z][A-Za-z0-9-]*)\s+(?<num>\d+)\s*\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SimpleAssignmentRegex = new(
        @"(?<name>[A-Za-z][A-Za-z0-9-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{\s*(?<parent>[A-Za-z][A-Za-z0-9-]*)\s+(?<num>\d+)\s*\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static void AugmentFromDirectory(
        string dir,
        Dictionary<string, string> exact,
        List<(string Prefix, string Name)> prefixes)
    {
        // 1) Optional sidecar — operator-supplied JSON map of OID → name.
        var sidecar = Path.Combine(dir, "oid-map.json");
        if (File.Exists(sidecar))
        {
            try
            {
                var json = File.ReadAllText(sidecar);
                var map = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (map is not null)
                {
                    foreach (var (k, v) in map)
                    {
                        if (string.IsNullOrWhiteSpace(k) || string.IsNullOrWhiteSpace(v)) continue;
                        var key = k.Trim().TrimStart('.');
                        // Additive only — never replace embedded mappings.
                        if (!exact.ContainsKey(key))
                        {
                            exact[key] = v.Trim();
                            prefixes.Add((key, v.Trim()));
                        }
                    }
                }
            }
            catch
            {
                // Malformed sidecar — ignore.
            }
        }

        // 2) MIB files — collect symbolic anchors and resolve via known anchors.
        var pending = new Dictionary<string, (string Parent, int Num)>(StringComparer.Ordinal);

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateFiles(dir, "*.mib", SearchOption.TopDirectoryOnly));
        }
        catch
        {
            return;
        }

        foreach (var file in files)
        {
            string text;
            try { text = File.ReadAllText(file); }
            catch { continue; }

            if (text.Length > 4 * 1024 * 1024) continue;

            CollectAssignments(SimpleAssignmentRegex.Matches(text), pending);
            CollectAssignments(AssignmentRegex.Matches(text), pending);
        }

        var nameToOid = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (prefix, name) in prefixes)
        {
            if (!nameToOid.ContainsKey(name)) nameToOid[name] = prefix;
        }
        foreach (var (oid, name) in exact)
        {
            if (!nameToOid.ContainsKey(name)) nameToOid[name] = oid;
        }

        for (var pass = 0; pass < 16 && pending.Count > 0; pass++)
        {
            var resolved = new List<string>();
            foreach (var (name, def) in pending)
            {
                if (nameToOid.TryGetValue(def.Parent, out var parentOid))
                {
                    var oid = parentOid + "." + def.Num.ToString(CultureInfo.InvariantCulture);
                    if (!exact.ContainsKey(oid))
                    {
                        exact[oid] = name;
                        prefixes.Add((oid, name));
                    }
                    nameToOid[name] = oid;
                    resolved.Add(name);
                }
            }
            if (resolved.Count == 0) break;
            foreach (var n in resolved) pending.Remove(n);
        }
    }

    private static void CollectAssignments(
        MatchCollection matches,
        Dictionary<string, (string Parent, int Num)> pending)
    {
        foreach (Match m in matches)
        {
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            var parent = m.Groups["parent"].Value;
            if (!int.TryParse(m.Groups["num"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var num))
                continue;
            pending.TryAdd(name, (parent, num));
        }
    }
}
