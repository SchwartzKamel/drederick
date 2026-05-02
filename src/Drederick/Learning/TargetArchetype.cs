namespace Drederick.Learning;

/// <summary>
/// Coarse host archetype labels used by planners and the LLM system
/// prompt to reason at archetype scale rather than per-port. Stable
/// enum values; downstream corpus replay keys on these names.
/// </summary>
public enum TargetArchetype
{
    Unknown = 0,
    LinuxClassic,
    LinuxModern,
    WindowsWorkstation,
    WindowsAdEdge,
    WindowsDcCandidate,
    NetworkAppliance,
    WebStack,
    MailServer,
    DbServer,
    IotEmbedded,
    Honeypot,
}
