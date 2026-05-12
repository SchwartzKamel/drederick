namespace Drederick.Recon.Http;

/// <summary>
/// GAP-057 / htb-content-discovery-vhost-aware: content-discovery
/// wordlist profile enumeration + the default extension-fanout set
/// (<c>php,html,txt,bak,zip,log,old,inc,asp,aspx,jsp</c>).
/// <para>
/// The repository deliberately does <b>not</b> bundle the
/// <c>raft-medium-directories.txt</c> file (would push the binary
/// distribution well past 200 KB for one wordlist) — instead this
/// helper resolves a profile to a SecLists-rooted on-disk path the
/// operator already has, mirroring the search-dir strategy used in
/// <see cref="Drederick.Recon.HttpContentDiscoveryTool.ResolveWordlistProfile"/>.
/// When no path resolves, callers fall back to the in-tree
/// <see cref="Drederick.Recon.HttpContentDiscoveryTool.DefaultWordlist"/>.
/// </para>
/// </summary>
public enum ContentDiscoveryProfile
{
    /// <summary>The in-tree default wordlist baked into the harness.</summary>
    Default,
    /// <summary>SecLists raft-small-directories.txt (lower coverage, faster).</summary>
    RaftSmall,
    /// <summary>SecLists raft-medium-directories.txt (recommended for vhost re-probe).</summary>
    RaftMedium,
    /// <summary>SecLists raft-large-directories.txt (highest coverage, slowest).</summary>
    RaftLarge,
}

/// <summary>
/// Static helpers for <see cref="ContentDiscoveryProfile"/>: name
/// parsing, canonical wire-name emission, default extension fanout
/// list, and best-effort SecLists path resolution.
/// </summary>
public static class ContentDiscoveryProfiles
{
    /// <summary>
    /// Default extension fanout for re-probing 200-OK directories.
    /// Lower-case, no leading dot, stable order. Matches the
    /// "common web tech + backup" set used by gobuster/ffuf cheat
    /// sheets for HTB-style targets.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultExtensionFanout = new[]
    {
        "php", "html", "txt", "bak", "zip",
        "log", "old", "inc", "asp", "aspx", "jsp",
    };

    /// <summary>
    /// SecLists Web-Content directories searched (in order) for a
    /// profile's wordlist file. Mirrors the search list used by the
    /// existing <see cref="Drederick.Recon.HttpContentDiscoveryTool"/>.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultSeclistsSearchDirs = new[]
    {
        "/usr/share/seclists/Discovery/Web-Content/",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/",
        "/opt/seclists/Discovery/Web-Content/",
    };

    /// <summary>
    /// Returns the canonical lower-kebab name for a profile
    /// (<c>default</c>, <c>raft-small</c>, <c>raft-medium</c>,
    /// <c>raft-large</c>).
    /// </summary>
    public static string ToWireName(ContentDiscoveryProfile profile) => profile switch
    {
        ContentDiscoveryProfile.Default => "default",
        ContentDiscoveryProfile.RaftSmall => "raft-small",
        ContentDiscoveryProfile.RaftMedium => "raft-medium",
        ContentDiscoveryProfile.RaftLarge => "raft-large",
        _ => "default",
    };

    /// <summary>
    /// Parse a wire-name (case- and dash-insensitive) into a profile.
    /// Returns <c>true</c> on success. Unknown names return
    /// <c>false</c> and leave <paramref name="profile"/> set to
    /// <see cref="ContentDiscoveryProfile.Default"/>.
    /// </summary>
    public static bool TryParse(string? name, out ContentDiscoveryProfile profile)
    {
        profile = ContentDiscoveryProfile.Default;
        if (string.IsNullOrWhiteSpace(name)) return false;
        var normalized = name.Trim().ToLowerInvariant().Replace('_', '-');
        switch (normalized)
        {
            case "default": profile = ContentDiscoveryProfile.Default; return true;
            case "raft-small": profile = ContentDiscoveryProfile.RaftSmall; return true;
            case "raft-medium": profile = ContentDiscoveryProfile.RaftMedium; return true;
            case "raft-large": profile = ContentDiscoveryProfile.RaftLarge; return true;
            default: return false;
        }
    }

    /// <summary>
    /// Conventional filename for a profile under the SecLists
    /// Web-Content directory (matches the directories-suffixed list
    /// that is most useful for vhost re-probe). Returns
    /// <c>null</c> for <see cref="ContentDiscoveryProfile.Default"/>.
    /// </summary>
    public static string? WordlistFileName(ContentDiscoveryProfile profile) => profile switch
    {
        ContentDiscoveryProfile.RaftSmall => "raft-small-directories.txt",
        ContentDiscoveryProfile.RaftMedium => "raft-medium-directories.txt",
        ContentDiscoveryProfile.RaftLarge => "raft-large-directories.txt",
        _ => null,
    };

    /// <summary>
    /// Resolve a profile to an on-disk wordlist path by searching the
    /// supplied SecLists roots (or
    /// <see cref="DefaultSeclistsSearchDirs"/> when
    /// <paramref name="searchDirs"/> is <c>null</c>). Returns the
    /// first existing match, or <c>null</c> if the profile is
    /// <see cref="ContentDiscoveryProfile.Default"/> or no match
    /// exists on the operator workstation.
    /// </summary>
    public static string? ResolveWordlistPath(
        ContentDiscoveryProfile profile,
        IEnumerable<string>? searchDirs = null)
    {
        var fileName = WordlistFileName(profile);
        if (fileName is null) return null;
        var roots = searchDirs ?? DefaultSeclistsSearchDirs;
        foreach (var dir in roots)
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            string path;
            try { path = Path.Combine(dir, fileName); }
            catch { continue; }
            try
            {
                if (File.Exists(path)) return path;
            }
            catch
            {
                // Permission / IO — fall through.
            }
        }
        return null;
    }
}
