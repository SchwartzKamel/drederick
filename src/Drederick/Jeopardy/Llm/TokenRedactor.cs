using System.Text.RegularExpressions;

namespace Drederick.Jeopardy.Llm;

/// <summary>
/// Redacts GitHub / Copilot-style tokens from free-form strings. Used before
/// anything lands in the audit log or an exception message.
/// </summary>
internal static class TokenRedactor
{
    private static readonly Regex[] Patterns =
    {
        new(@"gh[uoprs]_[A-Za-z0-9]{16,}", RegexOptions.Compiled),
        new(@"github_pat_[A-Za-z0-9_]{20,}", RegexOptions.Compiled),
        new(@"Bearer\s+[A-Za-z0-9._\-]{16,}", RegexOptions.Compiled | RegexOptions.IgnoreCase),
    };

    public static string Redact(string? s)
    {
        if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
        var redacted = s;
        foreach (var p in Patterns) redacted = p.Replace(redacted, "***REDACTED***");
        return redacted;
    }
}
