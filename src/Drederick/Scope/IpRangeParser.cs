using System.Net;

namespace Drederick.Scope;

/// <summary>
/// Pure-function parser for nmap-style target entries that the existing
/// scope parser does not natively understand:
///
/// - Bare IPv4/IPv6 (`10.0.0.1`) — returned as a single-element list.
/// - IPv4 last-octet dash range (`10.0.0.1-50`) — expanded to all IPs in
///   the range, inclusive on both ends. The first three octets are taken
///   from the literal IP; the fourth octet runs from the literal value
///   to the dash-suffix value.
///
/// Out of scope (caller handles separately):
///
/// - CIDR (`10.0.0.0/24`) — `<see cref="ParseStatus.NotARange"/>`. The
///   caller already validates CIDR via <see cref="System.Net.IPNetwork"/>.
/// - Full-IP dash form (`10.0.0.1-10.0.0.50`) — deferred to a follow-up.
///   Returned as <see cref="ParseStatus.Invalid"/> for now.
/// - Hostnames — caller resolves DNS first.
///
/// Bounded at <see cref="MaxExpansionCount"/> entries; ranges that would
/// expand to more IPs are refused with <see cref="ParseStatus.TooLarge"/>
/// to prevent accidental enumeration of an entire address space (e.g.
/// `10.0.0.0-10.255.255.255`).
/// </summary>
public static class IpRangeParser
{
    /// <summary>Maximum number of IPs a single entry may expand to.</summary>
    public const int MaxExpansionCount = 1024;

    public enum ParseStatus
    {
        Ok,
        NotARange,
        Invalid,
        TooLarge,
        Backwards,
    }

    public sealed record ParseResult(
        ParseStatus Status,
        IReadOnlyList<IPAddress> Addresses,
        string? Reason);

    /// <summary>
    /// Parse a single nmap-style target entry. Returns
    /// <see cref="ParseStatus.NotARange"/> for inputs the existing scope
    /// parser already handles (CIDR), otherwise either an expanded address
    /// list or a typed failure.
    /// </summary>
    public static ParseResult Parse(string entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
            return new ParseResult(ParseStatus.Invalid, Array.Empty<IPAddress>(), "empty");

        var trimmed = entry.Trim();

        // CIDR is handled elsewhere by the existing scope parser.
        if (trimmed.Contains('/', StringComparison.Ordinal))
            return new ParseResult(ParseStatus.NotARange, Array.Empty<IPAddress>(), "cidr");

        // Bare IP literal — single-element expansion.
        if (IPAddress.TryParse(trimmed, out var single))
            return new ParseResult(ParseStatus.Ok, new[] { single }, null);

        // Look for a dash. Only IPv4 last-octet form is supported.
        var dash = trimmed.IndexOf('-');
        if (dash <= 0 || dash == trimmed.Length - 1)
            return new ParseResult(ParseStatus.Invalid, Array.Empty<IPAddress>(),
                "not a parseable IP or last-octet range");

        var head = trimmed[..dash];
        var tail = trimmed[(dash + 1)..];

        if (!IPAddress.TryParse(head, out var headIp) ||
            headIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return new ParseResult(ParseStatus.Invalid, Array.Empty<IPAddress>(),
                "head is not IPv4 (full-IP dash form and IPv6 ranges deferred)");
        }

        // Reject full-IP form (10.0.0.1-10.0.0.50) — defer to a follow-up.
        if (tail.Contains('.', StringComparison.Ordinal))
        {
            return new ParseResult(ParseStatus.Invalid, Array.Empty<IPAddress>(),
                "full-IP dash form (10.0.0.1-10.0.0.50) is deferred");
        }

        if (!byte.TryParse(tail, out var tailOctet))
        {
            return new ParseResult(ParseStatus.Invalid, Array.Empty<IPAddress>(),
                $"dash suffix '{tail}' is not 0-255");
        }

        var headBytes = headIp.GetAddressBytes();
        var headOctet = headBytes[3];

        if (tailOctet < headOctet)
        {
            return new ParseResult(ParseStatus.Backwards, Array.Empty<IPAddress>(),
                $"range '{trimmed}' is backwards ({headOctet} > {tailOctet})");
        }

        var count = tailOctet - headOctet + 1;
        if (count > MaxExpansionCount)
        {
            return new ParseResult(ParseStatus.TooLarge, Array.Empty<IPAddress>(),
                $"range '{trimmed}' would expand to {count} IPs (cap {MaxExpansionCount})");
        }

        var list = new List<IPAddress>(count);
        for (int o = headOctet; o <= tailOctet; o++)
        {
            var b = (byte[])headBytes.Clone();
            b[3] = (byte)o;
            list.Add(new IPAddress(b));
        }
        return new ParseResult(ParseStatus.Ok, list, null);
    }
}
