using System.Net;
using BenchmarkDotNet.Attributes;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;

namespace Drederick.Bench;

/// <summary>
/// Compares an in-process SharpSNMP <c>sysName.0</c> GET against shelling out
/// to <c>snmpwalk</c>. There is no embedded SNMP responder in this harness,
/// so both arms target loopback and rely on the operator running a local
/// agent. They are marked <see cref="SkippableBenchmarkAttribute"/>: when no
/// agent answers, the call fails fast and the timing reflects the connect
/// latency only.
/// </summary>
[MemoryDiagnoser]
public class SnmpSysNameBench
{
    private static readonly IPEndPoint Endpoint = new(IPAddress.Loopback, 161);
    private static readonly OctetString Community = new("public");
    private static readonly ObjectIdentifier SysName = new("1.3.6.1.2.1.1.5.0");

    [GlobalSetup]
    public void Setup()
    {
        BenchHelpers.LoopbackScope().Require(IPAddress.Loopback.ToString());
    }

    [SkippableBenchmark(Reason = "Requires SNMP responder on 127.0.0.1:161", Description = "SharpSNMP GET sysName.0 (native)")]
    public int Native()
    {
        try
        {
            var result = Messenger.Get(
                VersionCode.V2,
                Endpoint,
                Community,
                new List<Variable> { new(SysName) },
                500);
            return result.Count;
        }
        catch
        {
            return 0;
        }
    }

    [SkippableBenchmark(Reason = "Requires snmpwalk on PATH and an SNMP responder", Description = "snmpwalk (subprocess)")]
    public string Subprocess()
    {
        if (!BenchHelpers.BinaryAvailable("snmpwalk")) return string.Empty;
        return BenchHelpers.RunAndCapture("snmpwalk", "-v2c -c public -t 1 -r 0 127.0.0.1 sysName.0");
    }
}
