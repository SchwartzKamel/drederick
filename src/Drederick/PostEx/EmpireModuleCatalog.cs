using System;
using System.Collections.Generic;
using System.Linq;
using Drederick.Exploit;
using Drederick.Exploit.Empire;

namespace Drederick.PostEx;

/// <summary>
/// Curated map between <see cref="EmpirePostExAction"/> categories and the
/// concrete Empire module names that implement them on each platform.
///
/// The catalog is the single source of truth for action → module routing.
/// Adding a new action is one entry per supported platform; the dispatcher,
/// the post-ex tools, and the LLM tool descriptions all read from here so
/// there is no place to drift.
///
/// Module-name strings track upstream Empire's <c>powershell/…</c> and
/// <c>python/…</c> conventions (BC-Security/Empire). The catalog does NOT
/// invent module names — every entry must exist in a default Empire 5.x
/// install.
/// </summary>
public static class EmpireModuleCatalog
{
    private static readonly IReadOnlyDictionary<EmpirePostExAction, string> Windows =
        new Dictionary<EmpirePostExAction, string>
        {
            [EmpirePostExAction.Portscan] = "powershell/situational_awareness/network/portscan",
            [EmpirePostExAction.LogonPasswords] = "powershell/credentials/mimikatz/logonpasswords",
            [EmpirePostExAction.KerberosTickets] = "powershell/credentials/mimikatz/extract_tickets",
            [EmpirePostExAction.LsaDump] = "powershell/credentials/mimikatz/lsadump",
            [EmpirePostExAction.DcSync] = "powershell/credentials/mimikatz/dcsync",
            [EmpirePostExAction.WatsonPrivesc] = "powershell/privesc/watson",
            [EmpirePostExAction.Sherlock] = "powershell/privesc/sherlock",
            [EmpirePostExAction.GetSystem] = "powershell/privesc/getsystem",
            [EmpirePostExAction.PersistenceSchtasks] = "powershell/persistence/elevated/schtasks",
        };

    private static readonly IReadOnlyDictionary<EmpirePostExAction, string> Linux =
        new Dictionary<EmpirePostExAction, string>
        {
            [EmpirePostExAction.Portscan] = "python/situational_awareness/network/portscan",
            [EmpirePostExAction.SshKeys] = "python/collection/linux/ssh_keys",
            [EmpirePostExAction.SudoConfig] = "python/situational_awareness/host/sudo_spawn",
            [EmpirePostExAction.KernelVersion] = "python/privesc/linux/linux_priv_checker",
            [EmpirePostExAction.Capabilities] = "python/situational_awareness/host/linux_capabilities",
            [EmpirePostExAction.SuidFiles] = "python/situational_awareness/host/find_suid",
            [EmpirePostExAction.PersistenceCron] = "python/persistence/multi/crontab",
        };

    /// <summary>
    /// Resolve a module name for <paramref name="action"/> on
    /// <paramref name="platform"/>. Throws
    /// <see cref="EmpireModuleNotSupportedException"/> when the action has
    /// no module on the requested platform (e.g. <c>LogonPasswords</c> on
    /// Linux, <c>SshKeys</c> on Windows).
    /// </summary>
    public static string Lookup(EmpirePlatform platform, EmpirePostExAction action)
    {
        var map = platform == EmpirePlatform.Windows ? Windows : Linux;
        if (!map.TryGetValue(action, out var module))
        {
            throw new EmpireModuleNotSupportedException(
                $"Empire action {action} has no module on platform {platform}.");
        }
        return module;
    }

    public static bool TryLookup(EmpirePlatform platform, EmpirePostExAction action, out string module)
    {
        var map = platform == EmpirePlatform.Windows ? Windows : Linux;
        return map.TryGetValue(action, out module!);
    }

    /// <summary>All actions registered for <paramref name="platform"/>.</summary>
    public static IReadOnlyCollection<EmpirePostExAction> ActionsFor(EmpirePlatform platform)
        => (platform == EmpirePlatform.Windows ? Windows.Keys : Linux.Keys).ToArray();

    /// <summary>
    /// Heuristic platform detection from an <see cref="EmpireSession"/>.
    /// Empire stages either a PowerShell agent (Windows) or a Python agent
    /// (Linux/macOS); we read the listener / agent fields to decide.
    /// </summary>
    public static EmpirePlatform PlatformFor(EmpireSession session)
    {
        if (session is null) throw new ArgumentNullException(nameof(session));
        var blob = string.Join(" ",
            session.Listener ?? string.Empty,
            session.User ?? string.Empty,
            session.Host ?? string.Empty);
        var lower = blob.ToLowerInvariant();

        if (lower.Contains("python") || lower.Contains("linux") || lower.Contains("ubuntu"))
            return EmpirePlatform.Linux;
        if (lower.Contains("powershell") || lower.Contains("windows") || lower.Contains("\\"))
            return EmpirePlatform.Windows;

        // Default: Windows. PowerShell agents are by far the most common
        // Empire deployment; defaulting to Windows minimizes spurious
        // platform-mismatch errors on ambiguous metadata.
        return EmpirePlatform.Windows;
    }

    /// <summary>
    /// The exploit category each action falls under — used by the
    /// dispatcher to gate via <see cref="RunPermissions.Require"/>.
    /// </summary>
    public static ExploitCategory CategoryFor(EmpirePostExAction action) => action switch
    {
        EmpirePostExAction.LogonPasswords => ExploitCategory.CredAttacks,
        EmpirePostExAction.KerberosTickets => ExploitCategory.CredAttacks,
        EmpirePostExAction.LsaDump => ExploitCategory.CredAttacks,
        EmpirePostExAction.DcSync => ExploitCategory.CredAttacks,
        EmpirePostExAction.SshKeys => ExploitCategory.CredAttacks,

        EmpirePostExAction.GetSystem => ExploitCategory.Destructive,
        EmpirePostExAction.PersistenceSchtasks => ExploitCategory.Destructive,
        EmpirePostExAction.PersistenceCron => ExploitCategory.Destructive,
        EmpirePostExAction.KernelVersion => ExploitCategory.Destructive,

        _ => ExploitCategory.ExecPocs,
    };
}

/// <summary>
/// Raised when <see cref="EmpireModuleCatalog.Lookup"/> cannot find a
/// module for a given (platform, action) pair.
/// </summary>
public sealed class EmpireModuleNotSupportedException : Exception
{
    public EmpireModuleNotSupportedException(string message) : base(message) { }
}
