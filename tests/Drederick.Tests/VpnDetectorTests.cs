using System.Net;
using System.Net.NetworkInformation;
using Drederick.Ops;
using Xunit;

namespace Drederick.Tests;

public class VpnDetectorTests
{
    private sealed class FakeProvider : INetworkInterfaceProvider
    {
        private readonly IEnumerable<VpnInterfaceInfo> _ifaces;
        public FakeProvider(params VpnInterfaceInfo[] ifaces) => _ifaces = ifaces;
        public IEnumerable<VpnInterfaceInfo> GetInterfaces() => _ifaces;
    }

    private static VpnInterfaceInfo Iface(string name, OperationalStatus status, params string[] ips)
    {
        return new VpnInterfaceInfo(
            name,
            status,
            ips.Select(IPAddress.Parse).ToList());
    }

    [Fact]
    public void DetectVpn_Tun0Up_ReturnsActive()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("eth0", OperationalStatus.Up, "192.168.1.10"),
            Iface("tun0", OperationalStatus.Up, "10.10.14.5")));
        var s = det.DetectVpn();
        Assert.True(s.IsActive);
        Assert.Equal("tun0", s.InterfaceName);
        Assert.Equal("10.10.14.5", s.LocalIp!.ToString());
    }

    [Fact]
    public void DetectVpn_NoTun_ReturnsInactive()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("eth0", OperationalStatus.Up, "192.168.1.10"),
            Iface("wlan0", OperationalStatus.Up, "192.168.2.10")));
        Assert.False(det.DetectVpn().IsActive);
    }

    [Fact]
    public void DetectVpn_TunDown_ReturnsInactive()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("tun0", OperationalStatus.Down, "10.10.14.5")));
        Assert.False(det.DetectVpn().IsActive);
    }

    [Fact]
    public void DetectVpn_TunWithLinkLocalOnly_ReturnsInactive()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("tun0", OperationalStatus.Up, "169.254.1.2")));
        Assert.False(det.DetectVpn().IsActive);
    }

    [Fact]
    public void DetectVpn_MultipleTuns_ReturnsFirstActive()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("tun0", OperationalStatus.Down, "10.10.14.1"),
            Iface("tun1", OperationalStatus.Up, "10.10.14.2"),
            Iface("tun2", OperationalStatus.Up, "10.10.14.3")));
        var s = det.DetectVpn();
        Assert.True(s.IsActive);
        Assert.Equal("tun1", s.InterfaceName);
    }

    [Fact]
    public void DetectVpn_TapInterface_AlsoDetected()
    {
        var det = new VpnDetector(new FakeProvider(
            Iface("tap0", OperationalStatus.Up, "10.10.14.9")));
        Assert.True(det.DetectVpn().IsActive);
    }
}
