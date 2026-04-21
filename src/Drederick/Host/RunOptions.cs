namespace Drederick.Host;

/// <summary>
/// Operator-facing options for a single <see cref="DrederickHost.RunAsync"/>
/// call. Mirrors the shape of <see cref="Drederick.Cli.CommandLineOptions"/>
/// but exposes only the fields the first UI iteration needs. Immutable by
/// design: any config drift across threads must go through a new instance.
///
/// Invariant boundary: <see cref="AllowBroad"/> and <see cref="LabMode"/> are
/// passed through to <see cref="Drederick.Scope.ScopeLoader"/> as-is; they
/// never unlock wildcard scopes (<c>0.0.0.0/0</c> refusal is hard-coded in
/// <c>ScopeLoader</c>).
/// </summary>
public sealed record RunOptions(
    string? ScopePath,
    IReadOnlyList<string> Targets,
    string OutputDir = "out",
    string MemoryPath = "memory/findings.json",
    bool LabMode = true,
    bool AllowBroad = false,
    bool UseAgent = false,
    int HostConcurrency = 4,
    int ServiceConcurrency = 8,
    bool ContentDiscovery = false);
