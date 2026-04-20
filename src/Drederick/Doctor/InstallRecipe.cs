namespace Drederick.Doctor;

/// <summary>
/// Describes how to install a specific tool under a specific system package manager.
/// A recipe with <see cref="NeedsSudo"/>=true and a non-null <see cref="Command"/>
/// will be shown verbatim and gated behind confirmation before execution.
/// </summary>
public sealed record InstallRecipe(
    string ToolName,
    string Command,
    bool NeedsSudo,
    string Rationale);

public static class InstallRecipes
{
    /// <summary>
    /// Resolve an install recipe for <paramref name="tool"/> under <paramref name="pm"/>.
    /// Returns null if we have no recipe for this combination (e.g. exotic pkg
    /// manager + tool that ships out-of-band).
    /// </summary>
    /// <param name="hasPipx">Whether <c>pipx</c> is available on the operator's PATH.</param>
    /// <param name="hasUv">Whether <c>uv</c> is available; when present prefer
    /// <c>uv tool install</c> for Python CLI tools.</param>
    public static InstallRecipe? Resolve(string tool, PackageManager pm, bool hasPipx, bool hasUv)
    {
        // Language-native preferred paths first (independent of system pm).
        switch (tool)
        {
            case "datasette":
                if (hasUv)
                    return new InstallRecipe(tool, "uv tool install datasette", NeedsSudo: false,
                        "datasette is a Python tool; uv tool install is the cleanest path.");
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install datasette", NeedsSudo: false,
                        "datasette is a Python tool; pipx keeps it isolated.");
                // No Python tool installer available: ask operator to bootstrap pipx first.
                return new InstallRecipe(tool,
                    pm switch
                    {
                        PackageManager.Apt => "apt-get install -y pipx && pipx ensurepath && pipx install datasette",
                        PackageManager.Dnf => "dnf install -y pipx && pipx ensurepath && pipx install datasette",
                        PackageManager.Pacman => "pacman -S --noconfirm python-pipx && pipx ensurepath && pipx install datasette",
                        PackageManager.Zypper => "zypper install -y python3-pipx && pipx ensurepath && pipx install datasette",
                        PackageManager.Brew => "brew install pipx && pipx ensurepath && pipx install datasette",
                        _ => "pipx install datasette",
                    },
                    NeedsSudo: pm is PackageManager.Apt or PackageManager.Dnf or PackageManager.Pacman or PackageManager.Zypper,
                    Rationale: "datasette requires a Python CLI installer; bootstrap pipx via the system package manager first.");

            case "searchsploit":
                // Debian/Ubuntu/Kali ship Exploit-DB as the exploitdb package.
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y exploitdb",
                        NeedsSudo: true,
                        "searchsploit is provided by the exploitdb package on Debian/Ubuntu/Kali.");
                // Fallback: git clone to ~/.local/share/exploitdb and symlink the binary.
                var home = Environment.GetEnvironmentVariable("HOME") ?? "~";
                var dest = System.IO.Path.Combine(home, ".local", "share", "exploitdb");
                var bin = System.IO.Path.Combine(home, ".local", "bin");
                return new InstallRecipe(tool,
                    $"mkdir -p {bin} && git clone https://github.com/offensive-security/exploitdb.git {dest} " +
                    $"&& ln -sf {dest}/searchsploit {bin}/searchsploit",
                    NeedsSudo: false,
                    "No system package for searchsploit; clone Exploit-DB and symlink the launcher into ~/.local/bin.");
        }

        // Generic system-pm recipes for the rest.
        string? pkg = tool switch
        {
            "nmap" => "nmap",
            "python3" => pm == PackageManager.Pacman ? "python" : "python3",
            "python2" => pm switch
            {
                PackageManager.Apt => "python2",
                PackageManager.Dnf => "python2",
                PackageManager.Pacman => "python2",
                PackageManager.Zypper => "python2",
                PackageManager.Brew => "python@2",
                _ => null,
            },
            "go" => pm switch
            {
                PackageManager.Apt => "golang-go",
                PackageManager.Dnf => "golang",
                PackageManager.Pacman => "go",
                PackageManager.Zypper => "go",
                PackageManager.Brew => "go",
                _ => null,
            },
            "ruby" => "ruby",
            "git" => "git",
            "curl" => "curl",
            "jq" => "jq",
            _ => null,
        };
        if (pkg is null) return null;

        return pm switch
        {
            PackageManager.Apt => new InstallRecipe(tool, $"apt-get install -y {pkg}", true, "apt-get"),
            PackageManager.Dnf => new InstallRecipe(tool, $"dnf install -y {pkg}", true, "dnf"),
            PackageManager.Pacman => new InstallRecipe(tool, $"pacman -S --noconfirm {pkg}", true, "pacman"),
            PackageManager.Zypper => new InstallRecipe(tool, $"zypper install -y {pkg}", true, "zypper"),
            PackageManager.Brew => new InstallRecipe(tool, $"brew install {pkg}", false, "brew"),
            _ => null,
        };
    }
}
