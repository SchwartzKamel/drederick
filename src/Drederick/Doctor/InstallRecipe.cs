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
    string Rationale,
    string? FallbackCommand = null,
    bool FallbackNeedsSudo = false,
    string? FallbackRationale = null);

public static class InstallRecipes
{
    // Pinned upstream Go used to bootstrap `go install` fallbacks when the
    // distro-provided Go is too old to parse modern go.mod directives
    // (e.g. Parrot ships Go too old to resolve nuclei v3.8+'s `go 1.25.7`).
    // Updated together with the minimum acceptable Go minor below.
    private const string UpstreamGoVersion = "1.23.4";
    private const int MinGoMinor = 21;

    /// <summary>
    /// Shell prelude that guarantees a modern Go toolchain is on PATH before
    /// invoking the caller's <c>go install</c>. If the system already has
    /// <c>go</c> >= 1.<see cref="MinGoMinor"/> it is used as-is; otherwise
    /// the upstream tarball is downloaded to <c>/usr/local/go</c> and
    /// prepended to PATH. Safe to use as a standalone one-liner inside a
    /// <see cref="InstallRecipe.FallbackCommand"/> string.
    /// </summary>
    internal static string GoBootstrapPrelude()
    {
        // Single-line POSIX sh fragment: detect → (maybe) fetch → prepend PATH.
        // Kept on one line (joined with ; / &&) so it composes cleanly with
        // the caller's `&& go install …` suffix.
        return string.Join(" ",
            "need=1;",
            "if command -v go >/dev/null 2>&1; then",
            "  v=$(go version | awk '{print $3}' | sed 's/^go//');",
            "  maj=${v%%.*}; rest=${v#*.}; min=${rest%%.*};",
            $"  if [ \"$maj\" -gt 1 ] || {{ [ \"$maj\" = 1 ] && [ \"$min\" -ge {MinGoMinor} ]; }}; then need=0; fi;",
            "fi;",
            "if [ \"$need\" = 1 ]; then",
            "  arch=$(uname -m);",
            "  case \"$arch\" in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) echo \"doctor: unsupported arch for upstream go: $arch\" >&2; exit 1;; esac;",
            $"  tarball=go{UpstreamGoVersion}.linux-${{a}}.tar.gz;",
            "  tmp=$(mktemp -d);",
            "  echo \"doctor: bootstrapping upstream go ($tarball)\";",
            "  curl -fsSL \"https://go.dev/dl/${tarball}\" -o \"${tmp}/${tarball}\" || { echo \"doctor: go download failed\" >&2; exit 1; };",
            "  rm -rf /usr/local/go && tar -C /usr/local -xzf \"${tmp}/${tarball}\" || { echo \"doctor: go extract failed\" >&2; exit 1; };",
            "  export PATH=\"/usr/local/go/bin:$PATH\";",
            "fi");
    }

    // Helper to compose a `go install …@latest` invocation behind the Go
    // bootstrap prelude. Caller passes the Go module path (e.g.
    // "github.com/ropnop/kerbrute"). The generated command starts with
    // the prelude, followed by `&& go install <path>@latest`, which keeps
    // the literal substring `go install <path>` intact so existing tests
    // that assert on it continue to pass.
    private static string BootstrappedGoInstall(string modulePath)
        => $"{GoBootstrapPrelude()} && go install {modulePath}@latest";

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
            {
                // Git-clone recipe works everywhere (Kali, Ubuntu, Fedora, …).
                var ssHome = Environment.GetEnvironmentVariable("HOME") ?? "~";
                var ssDest = System.IO.Path.Combine(ssHome, ".local", "share", "exploitdb");
                var ssBin = System.IO.Path.Combine(ssHome, ".local", "bin");
                var gitCloneCmd =
                    $"mkdir -p {ssBin} && git clone https://github.com/offensive-security/exploitdb.git {ssDest} " +
                    $"&& ln -sf {ssDest}/searchsploit {ssBin}/searchsploit";
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y exploitdb",
                        NeedsSudo: true,
                        "searchsploit is provided by the exploitdb package on Kali/Debian.",
                        FallbackCommand: gitCloneCmd,
                        FallbackNeedsSudo: false,
                        FallbackRationale: "exploitdb apt package is Kali-only; fallback: git clone Exploit-DB and symlink.");
                return new InstallRecipe(tool, gitCloneCmd,
                    NeedsSudo: false,
                    "No system package for searchsploit; clone Exploit-DB and symlink the launcher into ~/.local/bin.");
            }

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
                // pipx is the cleanest cross-distro path.
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install responder", false,
                        "responder via pipx (works on all distros).");
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y responder", true,
                        "Kali/Debian package responder.",
                        FallbackCommand: "apt-get install -y pipx && pipx ensurepath && pipx install responder",
                        FallbackNeedsSudo: true,
                        FallbackRationale: "responder apt package is Kali-only; fallback: bootstrap pipx then install.");
                return PipxBootstrapRecipe(tool, "responder", pm,
                    "responder via pipx; bootstrap pipx from the system package manager.");

            case "gobuster":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y gobuster", true,
                        "gobuster DNS/dir/vhost brute-forcer.",
                        FallbackCommand: BootstrappedGoInstall("github.com/OJ/gobuster/v3"),
                        FallbackNeedsSudo: true,
                        FallbackRationale: "fallback: go install (bootstraps upstream Go if too old).");
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install gobuster", false,
                        "gobuster DNS/dir/vhost brute-forcer.");
                return new InstallRecipe(tool,
                    BootstrappedGoInstall("github.com/OJ/gobuster/v3"),
                    NeedsSudo: false,
                    "gobuster via `go install` (no system package on this distro; bootstraps upstream Go if too old).");

            case "ffuf":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y ffuf", true,
                        "ffuf web fuzzer.",
                        FallbackCommand: BootstrappedGoInstall("github.com/ffuf/ffuf/v2"),
                        FallbackNeedsSudo: true,
                        FallbackRationale: "fallback: go install (bootstraps upstream Go if too old).");
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install ffuf", false, "ffuf web fuzzer.");
                return new InstallRecipe(tool,
                    BootstrappedGoInstall("github.com/ffuf/ffuf/v2"),
                    NeedsSudo: false,
                    "ffuf via `go install` (no system package on this distro; bootstraps upstream Go if too old).");

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
                        "nuclei template scanner (Kali apt).",
                        FallbackCommand: BootstrappedGoInstall("github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
                        FallbackNeedsSudo: true,
                        FallbackRationale: "fallback: go install (bootstraps upstream Go if too old; needed on Parrot).");
                return new InstallRecipe(tool,
                    BootstrappedGoInstall("github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
                    NeedsSudo: false,
                    "nuclei via `go install` (upstream-recommended; bootstraps upstream Go if too old).");

            case "kerbrute":
                // No system packages across distros — go install is the canonical path.
                return new InstallRecipe(tool,
                    BootstrappedGoInstall("github.com/ropnop/kerbrute"),
                    NeedsSudo: false,
                    "kerbrute via `go install` (no system package on any supported distro; bootstraps upstream Go if too old).");

            case "seclists":
                {
                    var slHome = Environment.GetEnvironmentVariable("HOME") ?? "~";
                    var slDest = System.IO.Path.Combine(slHome, "seclists");
                    var gitClone = $"git clone --depth=1 https://github.com/danielmiessler/SecLists {slDest}";
                    if (pm == PackageManager.Apt)
                        return new InstallRecipe(tool, "apt-get install -y seclists", true,
                            "SecLists wordlists via apt (Kali).",
                            FallbackCommand: gitClone,
                            FallbackNeedsSudo: false,
                            FallbackRationale: "seclists apt package is Kali-only; fallback: shallow git clone.");
                    return new InstallRecipe(tool, gitClone,
                        NeedsSudo: false,
                        "SecLists wordlists via git clone (no system package on this distro).");
                }

            case "evil-winrm":
                if (pm == PackageManager.Apt)
                    return new InstallRecipe(tool, "apt-get install -y evil-winrm", true,
                        "evil-winrm via apt (Kali/Debian).",
                        FallbackCommand: "gem install evil-winrm",
                        FallbackNeedsSudo: false,
                        FallbackRationale: "evil-winrm apt package is Kali-only; fallback: RubyGems.");
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

            case "magika":
                // Primary: pipx (Google ships magika as a Python package, and
                // pipx keeps it isolated). Fallback: cargo install (Rust CLI
                // binary, fastest startup). No system packages ship magika on
                // any distro as of 2026-04 — apt/dnf/pacman/zypper are unused.
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install magika", NeedsSudo: false,
                        "magika via pipx (primary path; Google's ML file-type detector).",
                        FallbackCommand: "cargo install magika",
                        FallbackNeedsSudo: false,
                        FallbackRationale: "fallback: cargo install magika (Rust CLI; requires a Rust toolchain).");
                return PipxBootstrapRecipe(tool, "magika", pm,
                    "magika via pipx; bootstrap pipx from the system package manager. Alternate path: `cargo install magika`.");

            // --- Fuzzing tools (Recon/Fuzz/* subsystem) -----------------------

            case "arjun":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install arjun", false,
                        "arjun HTTP parameter discovery via pipx.");
                return PipxBootstrapRecipe(tool, "arjun", pm,
                    "arjun via pipx; bootstrap pipx from the system package manager.");

            case "x8":
                // x8 is a Rust binary; cargo install is the canonical path.
                return new InstallRecipe(tool,
                    "cargo install x8",
                    NeedsSudo: false,
                    "x8 hidden-parameter discovery via cargo install (requires Rust toolchain).",
                    FallbackCommand: "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && . \"$HOME/.cargo/env\" && cargo install x8",
                    FallbackNeedsSudo: false,
                    FallbackRationale: "fallback: bootstrap Rust toolchain via rustup, then cargo install x8.");

            case "kr":
            {
                // kiterunner ships release binaries; go install does not work
                // (the root module is not a main package). Download from GitHub
                // releases as the primary path.
                var krHome = Environment.GetEnvironmentVariable("HOME") ?? "~";
                var krBin = System.IO.Path.Combine(krHome, ".local", "bin");
                return new InstallRecipe(tool,
                    $"arch=$(uname -m); case \"$arch\" in x86_64) a=amd64;; aarch64|arm64) a=arm64;; *) echo \"doctor: unsupported arch for kr: $arch\" >&2; exit 1;; esac; " +
                    $"tmp=$(mktemp -d); " +
                    $"curl -fsSL \"https://github.com/assetnote/kiterunner/releases/latest/download/kiterunner_1.0.2_linux_${{a}}.tar.gz\" -o \"${{tmp}}/kr.tar.gz\" && " +
                    $"tar -xzf \"${{tmp}}/kr.tar.gz\" -C \"${{tmp}}\" && mkdir -p {krBin} && cp \"${{tmp}}/kr\" {krBin}/kr && chmod +x {krBin}/kr && rm -rf \"${{tmp}}\"",
                    NeedsSudo: false,
                    "kiterunner API content-discovery via GitHub release binary.");
            }

            case "graphql-cop":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install graphql-cop", false,
                        "graphql-cop GraphQL security auditor via pipx.");
                return PipxBootstrapRecipe(tool, "graphql-cop", pm,
                    "graphql-cop via pipx; bootstrap pipx from the system package manager.");

            case "jwt_tool":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install jwt-tool", false,
                        "jwt_tool JWT testing toolkit via pipx (PyPI package: jwt-tool).");
                return PipxBootstrapRecipe(tool, "jwt-tool", pm,
                    "jwt_tool via pipx; bootstrap pipx from the system package manager.");

            case "radamsa":
            {
                var radHome = Environment.GetEnvironmentVariable("HOME") ?? "~";
                var radDest = System.IO.Path.Combine(radHome, ".local", "src", "radamsa");
                var radBin = System.IO.Path.Combine(radHome, ".local", "bin");
                return new InstallRecipe(tool,
                    $"apt-get install -y gcc make git && git clone https://gitlab.com/akihe/radamsa.git {radDest} && cd {radDest} && make && mkdir -p {radBin} && cp bin/radamsa {radBin}/radamsa",
                    NeedsSudo: true,
                    "radamsa general-purpose fuzzer built from source (needs gcc, make, git).");
            }

            case "boofuzz":
                if (hasPipx)
                    return new InstallRecipe(tool, "pipx install boofuzz", false,
                        "boofuzz protocol fuzzing framework via pipx.");
                return PipxBootstrapRecipe(tool, "boofuzz", pm,
                    "boofuzz via pipx; bootstrap pipx from the system package manager.");

            case "python2":
                // Brew still has a real py2 package; use it.
                if (pm == PackageManager.Brew)
                    return new InstallRecipe(tool, "brew install python@2", false,
                        "python2 via Homebrew's python@2 formula.");
                // Everywhere else (apt/dnf/pacman/zypper/unknown): no distro
                // packages python2 anymore. Instead of a 5-minute pyenv build
                // (which needs a dozen -dev packages), grab PyPy2.7 portable:
                // a ~40MB statically-linked Python 2.7 drop-in that extracts
                // straight to /opt and symlinks into /usr/local/bin. Enough for
                // legacy CTF exploit scripts (ctypes + stdlib).
                const string pypyVersion = "7.3.17";
                string pypyRecipe =
                    $"arch=$(uname -m); case \"$arch\" in x86_64) a=linux64;; aarch64|arm64) a=aarch64;; *) echo \"doctor: unsupported arch for pypy2: $arch\" >&2; exit 1;; esac; " +
                    $"ver=pypy2.7-v{pypyVersion}-${{a}}; " +
                    "tmp=$(mktemp -d); " +
                    $"echo \"doctor: fetching PyPy2.7 portable (${{ver}}.tar.bz2)\"; " +
                    $"curl -fsSL \"https://downloads.python.org/pypy/${{ver}}.tar.bz2\" -o \"${{tmp}}/pypy.tar.bz2\" && " +
                    "mkdir -p /opt && tar -xjf \"${tmp}/pypy.tar.bz2\" -C /opt && " +
                    "ln -sf \"/opt/${ver}/bin/pypy\" /usr/local/bin/python2";
                return new InstallRecipe(tool, pypyRecipe, NeedsSudo: true,
                    "python2 via PyPy2.7 portable tarball (fast ~40MB download; drop-in Python 2.7; no build-deps).");
        }

        // Generic system-pm recipes for the rest.
        string? pkg = tool switch
        {
            "nmap" => "nmap",
            "python3" => pm == PackageManager.Pacman ? "python" : "python3",
            "python2" => null, // handled explicitly above for every pm.
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
