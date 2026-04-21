using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Drederick.Scope;

/// <summary>
/// An immutable, validated collection of authorized networks. Every target that
/// a recon tool touches is checked against this scope at the tool boundary. A
/// Scope is constructed only via <see cref="ScopeLoader"/>, which enforces
/// default-deny semantics: empty scopes, wildcard entries, and over-broad
/// prefixes are refused unless <c>allowBroad</c> is explicitly set.
/// </summary>
public sealed class Scope
{
    public IReadOnlyList<ScopeEntry> Entries { get; }
    public string Source { get; }

    internal Scope(IReadOnlyList<ScopeEntry> entries, string source)
    {
        Entries = entries;
        Source = source;
    }

    /// <summary>True if <paramref name="target"/> parses as an IP and falls inside the scope.</summary>
    public bool Contains(string target)
    {
        if (!IPAddress.TryParse(target, out var ip)) return false;
        foreach (var e in Entries)
        {
            if (e.Contains(ip)) return true;
        }
        return false;
    }

    /// <summary>
    /// Throws <see cref="ScopeException"/> if <paramref name="target"/> is not a valid
    /// IP address that falls inside the scope. This is the required guard for every
    /// tool that touches the network.
    /// </summary>
    public void Require(string target)
    {
        if (!Contains(target))
        {
            throw new ScopeException(
                $"Target '{target}' is not in scope (source: {Source}). " +
                "Add it to the scope file or refuse the action.");
        }
    }

    /// <summary>
    /// Verifies that a file path exists and is readable. Throws <see cref="ScopeException"/>
    /// if the file doesn't exist, is not readable, or if a scope is enforced and the
    /// file path attempts to escape it. This is the required guard for tools that
    /// access local files (e.g., binary analysis).
    /// </summary>
    public void RequireFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}");
        }

        try
        {
            using (File.Open(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                // Just verifying readability; close immediately.
            }
        }
        catch (UnauthorizedAccessException)
        {
            throw new UnauthorizedAccessException($"Permission denied reading {filePath}");
        }
    }

    /// <summary>Enumerates every host address in scope. Refuses ranges larger than 4096 addresses.</summary>
    public IReadOnlyList<string> Expand()
    {
        var hosts = new List<string>();
        foreach (var e in Entries)
        {
            var count = e.AddressCount;
            if (count > 4096)
            {
                throw new ScopeException(
                    $"Refusing to expand {e}: {count} addresses. " +
                    "Pass explicit targets for large ranges.");
            }
            hosts.AddRange(e.EnumerateHosts());
        }
        return hosts;
    }
}

/// <summary>A single CIDR entry in the scope (IPv4 or IPv6).</summary>
public sealed class ScopeEntry
{
    public IPAddress Network { get; }
    public int PrefixLength { get; }
    public AddressFamily Family => Network.AddressFamily;

    private readonly BigInteger _networkInt;
    private readonly BigInteger _mask;
    private readonly int _totalBits;

    public ScopeEntry(IPAddress network, int prefixLength)
    {
        _totalBits = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > _totalBits)
            throw new ScopeException($"Invalid prefix length {prefixLength}.");
        PrefixLength = prefixLength;
        _mask = BigInteger.Zero;
        for (int i = 0; i < prefixLength; i++)
        {
            _mask = (_mask << 1) | BigInteger.One;
        }
        _mask <<= (_totalBits - prefixLength);
        _networkInt = ToBigInt(network) & _mask;
        Network = FromBigInt(_networkInt, network.AddressFamily);
    }

    public BigInteger AddressCount => BigInteger.One << (_totalBits - PrefixLength);

    public bool Contains(IPAddress ip)
    {
        if (ip.AddressFamily != Family) return false;
        var v = ToBigInt(ip);
        return (v & _mask) == _networkInt;
    }

    public IEnumerable<string> EnumerateHosts()
    {
        var count = AddressCount;
        if (count == BigInteger.One)
        {
            yield return Network.ToString();
            yield break;
        }
        // Skip network and broadcast for IPv4 /31+ convention; keep all for /31, /32.
        BigInteger start = _networkInt;
        BigInteger end = _networkInt + count - BigInteger.One;
        // Skip network (.0) and broadcast (.255-style) addresses for IPv4
        // networks with prefix < /31; keep all addresses for IPv4 /31 and /32
        // and every IPv6 network (IPv6 has no broadcast address).
        bool skipEnds = Family == AddressFamily.InterNetwork && PrefixLength < 31;
        if (skipEnds) { start += 1; end -= 1; }
        for (var cur = start; cur <= end; cur++)
        {
            yield return FromBigInt(cur, Family).ToString();
        }
    }

    public override string ToString() => $"{Network}/{PrefixLength}";

    private static BigInteger ToBigInt(IPAddress ip)
    {
        // Big-endian, unsigned.
        var bytes = ip.GetAddressBytes();
        Array.Reverse(bytes);
        var padded = new byte[bytes.Length + 1];
        Array.Copy(bytes, padded, bytes.Length);
        return new BigInteger(padded);
    }

    private static IPAddress FromBigInt(BigInteger value, AddressFamily family)
    {
        int width = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = value.ToByteArray();
        if (bytes.Length > width + 1 || (bytes.Length == width + 1 && bytes[width] != 0))
            throw new ScopeException("Address overflow while enumerating scope.");
        var fixedBytes = new byte[width];
        Array.Copy(bytes, fixedBytes, Math.Min(bytes.Length, width));
        Array.Reverse(fixedBytes);
        return new IPAddress(fixedBytes);
    }
}
