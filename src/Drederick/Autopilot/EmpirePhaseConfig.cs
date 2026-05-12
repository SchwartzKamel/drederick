using System;
using System.Collections.Generic;
using Drederick.PostEx;

namespace Drederick.Autopilot;

/// <summary>
/// Static configuration for <see cref="EmpireAutopilotPhase"/>. The phase
/// only runs when <see cref="Enabled"/> is true *and* the surrounding
/// <see cref="Drederick.Exploit.RunPermissions"/> grant
/// <c>AllowPayloads</c> (and <c>AllowCredAttacks</c> for any mimikatz-class
/// module). The flag plumbed at the CLI (<c>--empire-autopilot</c>) is the
/// operator's positive opt-in; defaults are deliberately conservative.
///
/// Default module sets are the curated "first wave" enumeration the phase
/// dispatches automatically against every compromised host. They are
/// platform-keyed because PowerShell vs Python agents have disjoint module
/// surfaces (see <see cref="EmpireModuleCatalog"/>). Operators can override
/// either set without rebuilding.
/// </summary>
public sealed class EmpirePhaseConfig
{
    /// <summary>Default deadline for the entire phase (server start →
    /// stager → checkin → modules → loot). Mirrors HTB-scale runs;
    /// individual operations carry their own tighter timeouts.</summary>
    public static readonly TimeSpan DefaultMaxWait = TimeSpan.FromMinutes(15);

    /// <summary>Default deadline for an Empire agent to call back after
    /// stager delivery before the phase gives up on the host.</summary>
    public static readonly TimeSpan DefaultCheckinWait = TimeSpan.FromMinutes(3);

    /// <summary>Master gate. False = phase short-circuits with a
    /// <c>autopilot.empire.phase.skipped</c> audit and no network egress.
    /// Wired from <c>--empire-autopilot</c>.</summary>
    public bool Enabled { get; }

    /// <summary>Hard cap on the whole phase. Cancellation also respects
    /// the caller's <see cref="System.Threading.CancellationToken"/>.</summary>
    public TimeSpan MaxWait { get; }

    /// <summary>How long to wait for an Empire agent to call back after
    /// stager delivery on a given host before skipping it.</summary>
    public TimeSpan CheckinWait { get; }

    /// <summary>Default Empire module action set per platform — the phase
    /// dispatches each entry in order. <see cref="EmpireModuleCatalog"/>
    /// resolves the platform-specific module name.</summary>
    public IReadOnlyDictionary<EmpirePlatform, IReadOnlyList<EmpirePostExAction>> DefaultModules { get; }

    /// <summary>Default stager kind selected per platform. Windows → Ps1,
    /// Linux → Py.</summary>
    public IReadOnlyDictionary<EmpirePlatform, Drederick.Exploit.Empire.EmpireStagerKind> StagerKinds { get; }

    public EmpirePhaseConfig(
        bool enabled = false,
        TimeSpan? maxWait = null,
        TimeSpan? checkinWait = null,
        IReadOnlyDictionary<EmpirePlatform, IReadOnlyList<EmpirePostExAction>>? defaultModules = null,
        IReadOnlyDictionary<EmpirePlatform, Drederick.Exploit.Empire.EmpireStagerKind>? stagerKinds = null)
    {
        Enabled = enabled;
        MaxWait = maxWait ?? DefaultMaxWait;
        CheckinWait = checkinWait ?? DefaultCheckinWait;
        DefaultModules = defaultModules ?? BuildDefaultModules();
        StagerKinds = stagerKinds ?? BuildDefaultStagerKinds();

        if (MaxWait <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(maxWait), "MaxWait must be positive.");
        if (CheckinWait <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(checkinWait), "CheckinWait must be positive.");
    }

    /// <summary>Disabled, all-defaults instance — the safe value for an
    /// autopilot run that has not opted in to Empire.</summary>
    public static EmpirePhaseConfig Disabled { get; } = new(enabled: false);

    private static IReadOnlyDictionary<EmpirePlatform, IReadOnlyList<EmpirePostExAction>> BuildDefaultModules() =>
        new Dictionary<EmpirePlatform, IReadOnlyList<EmpirePostExAction>>
        {
            [EmpirePlatform.Windows] = new[]
            {
                EmpirePostExAction.Portscan,
                EmpirePostExAction.LogonPasswords,
                EmpirePostExAction.WatsonPrivesc,
            },
            [EmpirePlatform.Linux] = new[]
            {
                EmpirePostExAction.Portscan,
                EmpirePostExAction.SshKeys,
                EmpirePostExAction.SuidFiles,
            },
        };

    private static IReadOnlyDictionary<EmpirePlatform, Drederick.Exploit.Empire.EmpireStagerKind> BuildDefaultStagerKinds() =>
        new Dictionary<EmpirePlatform, Drederick.Exploit.Empire.EmpireStagerKind>
        {
            [EmpirePlatform.Windows] = Drederick.Exploit.Empire.EmpireStagerKind.Ps1,
            [EmpirePlatform.Linux] = Drederick.Exploit.Empire.EmpireStagerKind.Py,
        };
}
