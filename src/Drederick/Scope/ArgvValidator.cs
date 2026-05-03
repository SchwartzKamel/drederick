using System.Text.RegularExpressions;

namespace Drederick.Scope;

public static class ArgvValidator
{
    private static readonly Regex ShellMetacharRegex = new(
        @"[;&|`$<>(){}\\""\n\r\t]|\$\(|\$\{|>>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DnsBypassRegex = new(
        @"(?:%[0-9a-fA-F]{2}|xn--|0x[0-9a-fA-F]+|@)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex UrlRegex = new(
        @"^(?<scheme>https?|ftp|gopher|ldap|file)://(?<host>[^/?#:]+)(?::\d+)?(?:[/?#].*)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public static bool ContainsShellMetachars(string? value)
        => !string.IsNullOrEmpty(value) && ShellMetacharRegex.IsMatch(value);

    public static bool ContainsDnsBypassPattern(string? value)
        => !string.IsNullOrEmpty(value) && DnsBypassRegex.IsMatch(value);

    public static bool LooksLikeUrl(string? value)
        => !string.IsNullOrEmpty(value) && UrlRegex.IsMatch(value);

    public static string? ExtractUrlHost(string value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        var m = UrlRegex.Match(value);
        return m.Success ? m.Groups["host"].Value : null;
    }

    public static void RevalidateUrlHostInScope(Scope scope, string value)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var host = ExtractUrlHost(value);
        if (host is null) return;
        scope.Require(host);
    }
}
