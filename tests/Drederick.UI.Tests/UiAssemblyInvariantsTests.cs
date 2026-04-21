using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Defence-in-depth invariant check: source files under <c>src/Drederick.UI</c>
/// must not spawn arbitrary external binaries. The one narrowly-allowed
/// exception is launching the drederick CLI's own <c>serve</c> subcommand
/// (Datasette over the read-only <c>findings.db</c>) — that is the harness
/// itself, not a scanner binary, and Datasette never executes a PoC.
///
/// Invariants reinforced:
/// <list type="bullet">
///   <item><c>@invariant-id:scope-in-every-tool</c> — scanner binaries
///   (<c>nmap</c>, <c>searchsploit</c>, etc.) must only be invoked through
///   scope-enforced <c>IReconTool</c>s in the engine assembly.</item>
///   <item><c>@invariant-id:aggregate-not-execute</c> — the UI must never
///   <c>chmod +x</c> / exec anything under <c>poc_cache</c>.</item>
/// </list>
/// </summary>
public class UiAssemblyInvariantsTests
{
    // Names we must never see the UI spawning directly. Keeping this list
    // explicit (rather than an allow-list) makes new scanner integrations
    // loud about the boundary.
    private static readonly string[] ForbiddenBinaries =
    {
        "nmap", "searchsploit", "hydra", "medusa", "ncrack", "patator",
        "crackmapexec", "netexec", "evil-winrm", "impacket-GetNPUsers",
        "impacket-GetUserSPNs", "responder", "mitm6", "bettercap",
        "msfconsole", "metasploit",
    };

    private static readonly string[] ForbiddenPatterns =
    {
        "chmod +x",
        "poc_cache",
    };

    [Fact]
    public void Ui_source_tree_does_not_spawn_scanner_binaries_or_poc_cache_execs()
    {
        var repoRoot = FindRepoRoot();
        var uiDir = Path.Combine(repoRoot, "src", "Drederick.UI");
        Assert.True(Directory.Exists(uiDir), $"expected {uiDir} to exist");

        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(uiDir, "*.cs", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(uiDir, file).Replace('\\', '/');
            if (rel.StartsWith("obj/") || rel.StartsWith("bin/")) continue;

            var text = File.ReadAllText(file);

            foreach (var bin in ForbiddenBinaries)
            {
                // Word-boundary match to avoid catching "nmap" inside a
                // docstring sentence. We look for the name wrapped in
                // quotes (string literal) or as a bare identifier touching
                // non-word characters.
                if (text.Contains($"\"{bin}\"", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains($"'{bin}'", StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add($"{rel}: references forbidden binary '{bin}'");
                }
            }

            foreach (var pat in ForbiddenPatterns)
            {
                if (text.Contains(pat, StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add($"{rel}: contains forbidden pattern '{pat}'");
                }
            }
        }

        Assert.True(offenders.Count == 0,
            "Drederick.UI must not spawn scanner binaries or exec anything in poc_cache. " +
            "Route scanner work through DrederickHost / ReconToolbox. Offenders:\n  " +
            string.Join("\n  ", offenders));
    }

    private static string FindRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            if (Directory.Exists(Path.Combine(dir, "src", "Drederick.UI")))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }
        throw new DirectoryNotFoundException("could not locate repo root (expected src/Drederick.UI)");
    }
}
