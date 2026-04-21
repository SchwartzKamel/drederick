using Xunit;

namespace Drederick.UI.Tests;

/// <summary>
/// Defence-in-depth invariant check: source files under <c>src/Drederick.UI</c>
/// must not invoke <c>Process.Start</c> directly. All subprocess work goes
/// through <c>DrederickHost</c> and the scope-enforced recon tools in the
/// engine assembly (@invariant-id:scope-in-every-tool,
/// @invariant-id:aggregate-not-execute). If the UI ever grows a "Run this
/// PoC" / "Launch terminal in poc_cache" button, this test fails before the
/// PR lands.
/// </summary>
public class UiAssemblyInvariantsTests
{
    [Fact]
    public void Ui_source_tree_does_not_call_Process_Start()
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
            if (text.Contains("Process.Start", StringComparison.Ordinal) ||
                text.Contains("System.Diagnostics.Process.Start", StringComparison.Ordinal))
            {
                offenders.Add(rel);
            }
        }

        Assert.True(offenders.Count == 0,
            "Drederick.UI must not call Process.Start directly; route subprocess work " +
            "through DrederickHost / ReconToolbox. Offending files:\n  " +
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
