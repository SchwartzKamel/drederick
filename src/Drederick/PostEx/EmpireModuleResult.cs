using System.Collections.Generic;

namespace Drederick.PostEx;

/// <summary>
/// Categorical actions exposed by the Empire post-ex dispatcher. Each entry
/// maps (in <see cref="EmpireModuleCatalog"/>) to a concrete Empire module
/// name on each supported platform. Action enums are the LLM- and operator-
/// facing surface — module name strings are an implementation detail of the
/// Empire backend.
/// </summary>
public enum EmpirePostExAction
{
    // Windows + Linux: portscan from the agent's vantage point.
    Portscan,

    // Windows-only credential / AD modules.
    LogonPasswords,
    KerberosTickets,
    LsaDump,
    DcSync,

    // Windows-only privesc enumerators.
    WatsonPrivesc,
    Sherlock,
    GetSystem,

    // Windows-only persistence.
    PersistenceSchtasks,

    // Linux-only enum.
    SshKeys,
    SudoConfig,
    KernelVersion,
    Capabilities,
    SuidFiles,

    // Linux-only persistence.
    PersistenceCron,
}

/// <summary>
/// Empire agent OS family. Determined from <c>EmpireSession.Listener</c> /
/// agent language metadata by <see cref="EmpireModuleCatalog.PlatformFor"/>.
/// </summary>
public enum EmpirePlatform
{
    Windows,
    Linux,
}

/// <summary>
/// One structured datum extracted from an Empire module's free-form output
/// (mimikatz creds, portscan results, etc.). The <see cref="Fields"/> map
/// is module-specific.
///
/// IMPORTANT: plaintext passwords are NEVER stored in <see cref="Fields"/>.
/// A mimikatz credential finding carries <c>password_sha256</c> only; the
/// plaintext flows through <see cref="EmpirePostExDispatcher"/> directly
/// into <see cref="Drederick.Autopilot.CredentialStore"/> in-memory.
/// </summary>
public sealed record EmpireParsedFinding(
    string Kind,
    IReadOnlyDictionary<string, string> Fields);

/// <summary>
/// Typed result of dispatching an Empire post-ex module via
/// <see cref="EmpirePostExDispatcher.RunAsync"/>.
///
/// Output is captured truncated at 64 KB (see
/// <see cref="EmpirePostExDispatcher.OutputTruncateBytes"/>) with a SHA-256
/// of the full pre-truncation bytes recorded in <see cref="OutputDigest"/>
/// for forensic correlation. Plaintext credentials never reach this record.
/// </summary>
public sealed record EmpireModuleResult(
    string AgentId,
    string Module,
    string ExitStatus,
    string OutputDigest,
    int OutputBytes,
    string OutputTruncated,
    IReadOnlyList<EmpireParsedFinding> ParsedFindings,
    string? Error = null);
