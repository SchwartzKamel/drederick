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

            // --- HTB / CTF tooling -----------------------------------------

            case "netexec":
                // pipx primary; apt ships `crackmapexec` (legacy) or `netexec`.
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install netexec", false,
                        "netexec (CrackMapExec successor) via pipx.");
                return PipxBootstrapRecipe(tool, "netexec", pm,
                    "netexec via pipx; bootstrap pipx from the system package manager.");

            case "impacket":
                // pipx primary; Kali/Debian alternative is python3-impacket.
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install impacket", false,
                        "impacket scripts (GetNPUsers, secretsdump, ...) via pipx.");
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y python3-impacket", true,
                        "Kali/Debian ship impacket scripts as python3-impacket.");
                return PipxBootstrapRecipe(tool, "impacket", pm,
                    "impacket via pipx; bootstrap pipx from the system package manager.");

            case "hashcat":
                return SystemPmRecipe(tool, "hashcat", pm, "hashcat GPU password cracker.");

            case "john":
                // Most distros: `john`. Brew package is also `john`.
                return SystemPmRecipe(tool, "john", pm, "John the Ripper password cracker.");

            case "responder":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y responder", true,
                        "Kali/Debian package responder.");
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install responder", false,
                        "responder via pipx (no system package on this distro).");
                return PipxBootstrapRecipe(tool, "responder", pm,
                    "responder via pipx; bootstrap pipx from the system package manager.");

            case "gobuster":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y gobuster", true,
                        "gobuster DNS/dir/vhost brute-forcer.");
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install gobuster", false,
                        "gobuster DNS/dir/vhost brute-forcer.");
                return new InstallRecipe(tool,
                    "go install github.com/OJ/gobuster/v3@latest",
                    NeedsSudo: false,
                    "gobuster via `go install` (no system package on this distro; requires Go).");

            case "ffuf":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y ffuf", true,
                        "ffuf web fuzzer.");
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install ffuf", false, "ffuf web fuzzer.");
                return new InstallRecipe(tool,
                    "go install github.com/ffuf/ffuf/v2@latest",
                    NeedsSudo: false,
                    "ffuf via `go install` (no system package on this distro; requires Go).");

            case "sqlmap":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y sqlmap", true, "sqlmap SQLi tool.");
                if (pm == PackageManager.Dnf)
                    return new InstallRecipe(tool, "dnf install -y sqlmap", true, "sqlmap SQLi tool.");
                if (pm == PackageManager.Pacman)
                    return new InstallRecipe(tool, "pacman -S --noconfirm sqlmap", true, "sqlmap SQLi tool.");
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install sqlmap", false, "sqlmap SQLi tool.");
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install sqlmap", false, "sqlmap via pipx.");
                return PipxBootstrapRecipe(tool, "sqlmap", pm,
                    "sqlmap via pipx; bootstrap pipx from the system package manager.");

            case "nuclei":
                // Go install is the upstream-blessed path; Kali apt also works.
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y nuclei", true,
                        "nuclei template scanner (Kali apt).");
                return new InstallRecipe(tool,
                    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    NeedsSudo: false,
                    "nuclei via `go install` (upstream-recommended).");

            case "kerbrute":
                // No system packages across distros — go install is the canonical path.
                return new InstallRecipe(tool,
                    "go install github.com/ropnop/kerbrute@latest",
                    NeedsSudo: false,
                    "kerbrute via `go install` (no system package on any supported distro).");

            case "seclists":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y seclists", true,
                        "SecLists wordlists via apt.");
                {
                    var sHome = Environment.GetEnvironmentVariable("HOME") ?? "~";
                    var sDest = System.IO.Path.Combine(sHome, "seclists");
                    return new InstallRecipe(tool,
                        $"git clone https://github.com/danielmiessler/SecLists {sDest}",
                        NeedsSudo: false,
                        "SecLists wordlists via git clone (no system package on this distro).");
                }

            case "evil-winrm":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y evil-winrm", true,
                        "evil-winrm via apt (Kali/Debian).");
                return new InstallRecipe(tool, "gem install evil-winrm", NeedsSudo: false,
                    "evil-winrm via RubyGems (no system package on this distro; requires Ruby).");

            case "enum4linux-ng":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install enum4linux-ng", false,
                        "enum4linux-ng via pipx.");
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y enum4linux-ng", true,
                        "enum4linux-ng via apt (Kali).");
                return PipxBootstrapRecipe(tool, "enum4linux-ng", pm,
                    "enum4linux-ng via pipx; bootstrap pipx from the system package manager.");

            case "wfuzz":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install wfuzz", false, "wfuzz via pipx.");
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y wfuzz", true,
                        "wfuzz via apt (Kali).");
                return PipxBootstrapRecipe(tool, "wfuzz", pm,
                    "wfuzz via pipx; bootstrap pipx from the system package manager.");
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

    // Emit a "native system package" recipe using the canonical package name
    // (same string across every supported pm). Used for widely-available
    // tools like hashcat / john.
    private static InstallRecipe? SystemPmRecipe(string tool, string pkg, PackageManager pm, string rationale)
    {
        return pm switch
        {
            PackageManager.Apt => new InstallRecipe(tool, $"apt-get install -y {pkg}", true, rationale),
            PackageManager.Dnf => new InstallRecipe(tool, $"dnf install -y {pkg}", true, rationale),
            PackageManager.Pacman => new InstallRecipe(tool, $"pacman -S --noconfirm {pkg}", true, rationale),
            PackageManager.Zypper => new InstallRecipe(tool, $"zypper install -y {pkg}", true, rationale),
            PackageManager.Brew => new InstallRecipe(tool, $"brew install {pkg}", false, rationale),
            _ => null,
        };
    }

    // Same shape as the datasette pipx-bootstrap fallback: install pipx from
    // the system package manager, then pipx install the Python CLI. Used for
    // Python tools where no direct apt/dnf/pacman/zypper/brew package exists
    // or where pipx is preferred upstream.
    private static InstallRecipe PipxBootstrapRecipe(string tool, string pyPkg, PackageManager pm, string rationale)
    {
        return new InstallRecipe(tool,
            pm switch
            {
                PackageManager.Apt => $"apt-get install -y pipx && pipx ensurepath && pipx install {pyPkg}",
                PackageManager.Dnf => $"dnf install -y pipx && pipx ensurepath && pipx install {pyPkg}",
                PackageManager.Pacman => $"pacman -S --noconfirm python-pipx && pipx ensurepath && pipx install {pyPkg}",
                PackageManager.Zypper => $"zypper install -y python3-pipx && pipx ensurepath && pipx install {pyPkg}",
                PackageManager.Brew => $"brew install pipx && pipx ensurepath && pipx install {pyPkg}",
                _ => $"pipx install {pyPkg}",
            },
            NeedsSudo: pm is PackageManager.Apt or PackageManager.Dnf or PackageManager.Pacman or PackageManager.Zypper,
            Rationale: rationale);
    }
}
