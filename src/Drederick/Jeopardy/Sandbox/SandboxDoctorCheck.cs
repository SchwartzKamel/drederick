namespace Drederick.Jeopardy.Sandbox;

/// <summary>
/// Lightweight result shape for <see cref="SandboxManager.CheckDockerHealthyAsync"/>.
/// Mirrors the Doctor-subsystem result shape without dragging that namespace
/// into the sandbox. The forthcoming <c>jeopardy-doctor</c> todo will adapt
/// this into a full DoctorCheck entry.
/// </summary>
public sealed record SandboxDoctorCheck(
    bool Ok,
    string Name,
    string Detail);
