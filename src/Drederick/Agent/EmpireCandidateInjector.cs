using System;
using System.Collections.Generic;
using System.Linq;
using Drederick.Exploit.Empire;
using Drederick.PostEx;
using Drederick.Recon;

namespace Drederick.Agent;

/// <summary>
/// Empire Wave C — pure logic that, given a host's current findings plus
/// any active Empire sessions plus a capability snapshot, returns the
/// set of <see cref="EmpireCandidate"/> actions the deterministic
/// <see cref="AdaptiveRunner"/> should consider injecting into its plan.
///
/// <para>
/// The injector itself performs no I/O and never spawns a process. It is
/// safe to call from any thread. Scope enforcement remains the
/// responsibility of the executor that ultimately dispatches a
/// candidate (e.g. <c>EmpireAgentStager</c>, <c>EmpireModuleExecutor</c>,
/// <c>EmpirePostExDispatcher</c>) — see the
/// <c>@invariant-id:scope-in-every-tool</c> rule.
/// </para>
///
/// <para>Rules (all gated by <see cref="EmpireInjectionCapabilities.EmpireAutopilotEnabled"/>):</para>
/// <list type="number">
///   <item>If an Empire session is already active on the host, emit one
///   <c>empire-module</c> candidate per
///   <see cref="EmpireModuleCatalog.ActionsFor"/> entry for the
///   detected <see cref="EmpirePlatform"/>. Skip if the existing plan
///   already contains an Empire module step for this host (no double-
///   injection).</item>
///   <item>Else if the host has confirmed Windows code execution
///   (<see cref="EmpireInjectionCapabilities.HasConfirmedWindowsRce"/>),
///   emit a single PowerShell-launcher <c>empire-stager</c> candidate.</item>
///   <item>Else if the host has working Linux SSH credentials
///   (<see cref="EmpireInjectionCapabilities.HasLinuxSshCredentials"/>),
///   emit a single Python-launcher <c>empire-stager</c> candidate.</item>
///   <item>Otherwise return an empty list.</item>
/// </list>
/// </summary>
public static class EmpireCandidateInjector
{
    /// <summary>
    /// Compute the set of Empire candidates to inject for <paramref name="host"/>.
    /// </summary>
    /// <param name="host">Target host (IP or hostname). Required.</param>
    /// <param name="findings">Recon findings for the host. May be <c>null</c>.</param>
    /// <param name="sessions">Active Empire sessions, across all hosts. May be empty.</param>
    /// <param name="capabilities">Runtime capability + opt-in flags.</param>
    /// <param name="existingChain">Optional: the planner's current candidate
    /// chain for this host. Used to suppress duplicate Empire steps.</param>
    public static IReadOnlyList<EmpireCandidate> Inject(
        string host,
        HostFinding? findings,
        IReadOnlyList<EmpireSession>? sessions,
        EmpireInjectionCapabilities capabilities,
        IReadOnlyList<EmpireCandidate>? existingChain = null)
    {
        if (string.IsNullOrWhiteSpace(host)) throw new ArgumentException("host required", nameof(host));
        if (!capabilities.EmpireAutopilotEnabled)
            return Array.Empty<EmpireCandidate>();

        var hostSessions = sessions?
            .Where(s => s is not null && string.Equals(s.Host, host, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (hostSessions is { Count: > 0 })
        {
            if (existingChain is not null && existingChain.Any(c =>
                    string.Equals(c.Target, host, StringComparison.OrdinalIgnoreCase) &&
                    c.Kind == EmpireCandidateKind.Module))
            {
                return Array.Empty<EmpireCandidate>();
            }

            var platform = EmpireModuleCatalog.PlatformFor(hostSessions[0]);
            var actions = EmpireModuleCatalog.ActionsFor(platform);
            var modules = new List<EmpireCandidate>(actions.Count);
            foreach (var action in actions)
            {
                var moduleName = EmpireModuleCatalog.TryLookup(platform, action, out var m) ? m : null;
                modules.Add(new EmpireCandidate(
                    Target: host,
                    Kind: EmpireCandidateKind.Module,
                    Platform: platform,
                    Launcher: null,
                    ModuleAction: action,
                    ModuleName: moduleName));
            }
            return modules;
        }

        // No active session — decide whether to stage.
        if (existingChain is not null && existingChain.Any(c =>
                string.Equals(c.Target, host, StringComparison.OrdinalIgnoreCase) &&
                c.Kind == EmpireCandidateKind.Stager))
        {
            return Array.Empty<EmpireCandidate>();
        }

        if (capabilities.HasConfirmedWindowsRce)
        {
            return new[]
            {
                new EmpireCandidate(
                    Target: host,
                    Kind: EmpireCandidateKind.Stager,
                    Platform: EmpirePlatform.Windows,
                    Launcher: EmpireStagerLauncher.PowerShell),
            };
        }

        if (capabilities.HasLinuxSshCredentials)
        {
            return new[]
            {
                new EmpireCandidate(
                    Target: host,
                    Kind: EmpireCandidateKind.Stager,
                    Platform: EmpirePlatform.Linux,
                    Launcher: EmpireStagerLauncher.Python),
            };
        }

        return Array.Empty<EmpireCandidate>();
    }
}

/// <summary>
/// Capability snapshot consumed by <see cref="EmpireCandidateInjector.Inject"/>.
///
/// <para>
/// <see cref="EmpireAutopilotEnabled"/> mirrors the <c>--empire-autopilot</c>
/// CLI flag (default off). The injector returns an empty list whenever this
/// flag is false — Empire never auto-stages without explicit opt-in.
/// </para>
/// </summary>
public sealed record EmpireInjectionCapabilities(
    bool EmpireAutopilotEnabled,
    bool HasConfirmedWindowsRce = false,
    bool HasLinuxSshCredentials = false);

/// <summary>
/// One injection-eligible Empire action. The injector returns these as a
/// pure descriptor; an executor (wired by the call site) is responsible for
/// dispatch and scope re-validation.
/// </summary>
public sealed record EmpireCandidate(
    string Target,
    EmpireCandidateKind Kind,
    EmpirePlatform Platform,
    EmpireStagerLauncher? Launcher = null,
    EmpirePostExAction? ModuleAction = null,
    string? ModuleName = null);

public enum EmpireCandidateKind
{
    Stager,
    Module,
}

public enum EmpireStagerLauncher
{
    PowerShell,
    Python,
}
