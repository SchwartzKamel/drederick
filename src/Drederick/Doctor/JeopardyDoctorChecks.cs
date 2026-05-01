using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Jeopardy.Llm;
using Drederick.Scope;

namespace Drederick.Doctor;

/// <summary>
/// Thin HTTP probe abstraction so doctor network checks can be unit-tested
/// without actually hitting api.githubcopilot.com or a live CTFd. Returns
/// the raw HTTP status code (or -1 on transport failure). Implementations
/// must not throw on non-2xx status.
/// </summary>
public interface IHttpStatusProbe
{
    Task<int> GetStatusAsync(string url, IReadOnlyDictionary<string, string>? headers, CancellationToken ct);
}

internal sealed class DefaultHttpStatusProbe : IHttpStatusProbe
{
    private readonly HttpClient _http;
    public DefaultHttpStatusProbe(HttpClient? http = null)
    {
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    public async Task<int> GetStatusAsync(string url, IReadOnlyDictionary<string, string>? headers, CancellationToken ct)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (headers is not null)
            {
                foreach (var (k, v) in headers)
                {
                    req.Headers.TryAddWithoutValidation(k, v);
                }
            }
            using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            return (int)resp.StatusCode;
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return -1;
        }
    }
}

/// <summary>
/// Environment-variable reader abstraction for tests. Default impl reads
/// process environment; tests inject a dictionary-backed implementation.
/// </summary>
public interface IEnvReader
{
    string? Get(string name);
}

internal sealed class ProcessEnvReader : IEnvReader
{
    public string? Get(string name) => Environment.GetEnvironmentVariable(name);
}

internal sealed class DictEnvReader : IEnvReader
{
    private readonly IReadOnlyDictionary<string, string?> _map;
    public DictEnvReader(IReadOnlyDictionary<string, string?> map) => _map = map;
    public string? Get(string name) => _map.TryGetValue(name, out var v) ? v : null;
}

/// <summary>
/// Disk-free abstraction. Default impl uses <see cref="DriveInfo"/>; tests
/// inject a fixed-value reader so CI runs are deterministic.
/// </summary>
public interface IDiskFreeReader
{
    /// <summary>Bytes available to non-privileged processes at <paramref name="path"/>, or -1 if unknown.</summary>
    long AvailableBytes(string path);
}

internal sealed class DefaultDiskFreeReader : IDiskFreeReader
{
    public long AvailableBytes(string path)
    {
        try
        {
            // Walk up to the nearest existing ancestor so /var/lib/docker on
            // a box that never started docker still resolves to its parent.
            var probe = path;
            while (!string.IsNullOrEmpty(probe) && !Directory.Exists(probe))
            {
                probe = Path.GetDirectoryName(probe);
            }
            if (string.IsNullOrEmpty(probe)) probe = "/";
            var di = new DriveInfo(new DirectoryInfo(probe).Root.FullName);
            return di.AvailableFreeSpace;
        }
        catch
        {
            return -1;
        }
    }
}

// =============================================================================
// Jeopardy doctor checks
// =============================================================================

/// <summary>
/// Shared dependencies for every Jeopardy doctor check. Exposed as a record so
/// tests can spin up a stub graph in one line. None of these fields are mutated
/// after construction.
/// </summary>
public sealed record JeopardyDoctorDeps(
    AuditLog Audit,
    IProcessRunner Runner,
    IEnvReader Env,
    IHttpStatusProbe Http,
    IDiskFreeReader DiskFree,
    Scope.Scope? Scope,
    bool AllowCopilotHost,
    string DockerBinary = "docker",
    string SandboxImage = "drederick-jeopardy-sandbox:latest",
    string DockerfilePath = "sandbox/Dockerfile.jeopardy-sandbox",
    string SandboxBuildContext = "sandbox/",
    string CopilotHost = "api.githubcopilot.com",
    string CopilotModelsUrl = "https://api.githubcopilot.com/v1/models",
    string DockerRootDir = "/var/lib/docker",
    long MinFreeBytes = 10L * 1024 * 1024 * 1024,
    // --- jeopardy-llm-provider-deps ---
    Drederick.Jeopardy.Llm.LlmProvider LlmProvider = Drederick.Jeopardy.Llm.LlmProvider.Copilot,
    string? AzureEndpoint = null,
    string? LlamaCppUrl = null);
// --- end jeopardy-llm-provider-deps ---

/// <summary>
/// Factory that builds all ten Jeopardy checks. Kept as a single public entry
/// so <c>Program.cs</c> wiring under <c>// --- jeopardy-doctor-wiring ---</c>
/// is a one-liner.
/// </summary>
public static class JeopardyDoctorChecks
{
    public const string CategoryName = "jeopardy";

    public static IReadOnlyList<IDoctorCheck> All(JeopardyDoctorDeps deps)
    {
        return new IDoctorCheck[]
        {
            new DockerInstalledCheck(deps),
            new DockerDaemonCheck(deps),
            new SandboxImageCheck(deps),
            new SandboxHealthcheckCheck(deps),
            new LlmTokenCheck(deps),
            new LlmReachableCheck(deps),
            new CtfdConfiguredCheck(deps),
            new CtfdReachableCheck(deps),
            new DiskSpaceCheck(deps),
            new ScopeFileCheck(deps),
        };
    }

    /// <summary>
    /// Run every check sequentially, isolating each in a try/catch so one
    /// blowing up never hides results from its siblings. Prints a grouped
    /// ✓/⚠/✗ summary to <paramref name="stdout"/>.
    /// </summary>
    public static async Task<IReadOnlyList<DoctorCheckResult>> RunAllAsync(
        JeopardyDoctorDeps deps,
        bool install,
        bool assumeYes,
        TextReader stdin,
        TextWriter stdout,
        CancellationToken ct)
    {
        var checks = All(deps);
        var results = new List<DoctorCheckResult>(checks.Count);

        stdout.WriteLine("drederick doctor: jeopardy-category checks");
        stdout.WriteLine("------------------------------------------");

        foreach (var c in checks)
        {
            DoctorCheckResult r;
            try
            {
                r = await c.RunAsync(install, assumeYes, stdin, stdout, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Surface unexpected blowups as a fail rather than crashing the
                // whole doctor pass. Log the exception type + message (not the
                // stack) so audit stays bounded.
                r = new DoctorCheckResult(c.Id, DoctorCheckStatus.Fail,
                    $"check threw {ex.GetType().Name}: {ex.Message}");
                deps.Audit.Record($"doctor.jeopardy.{c.Id}.finish", new Dictionary<string, object?>
                {
                    ["id"] = c.Id,
                    ["status"] = "fail",
                    ["detail"] = r.Detail,
                    ["threw"] = ex.GetType().FullName,
                });
            }

            results.Add(r);
            PrintOne(stdout, r);
        }

        stdout.WriteLine("------------------------------------------");
        var pass = results.Count(r => r.Status == DoctorCheckStatus.Pass);
        var warn = results.Count(r => r.Status == DoctorCheckStatus.Warn);
        var fail = results.Count(r => r.Status == DoctorCheckStatus.Fail);
        stdout.WriteLine($"summary: {pass} pass  {warn} warn  {fail} fail");
        return results;
    }

    private static void PrintOne(TextWriter w, DoctorCheckResult r)
    {
        var glyph = r.Status switch
        {
            DoctorCheckStatus.Pass => "✓",
            DoctorCheckStatus.Warn => "⚠",
            _ => "✗",
        };
        w.WriteLine($"  {glyph} {r.Id,-34} {r.Detail}");
        if (r.Status != DoctorCheckStatus.Pass && !string.IsNullOrEmpty(r.FixCommand))
        {
            w.WriteLine($"       fix: {r.FixCommand}");
            if (!string.IsNullOrEmpty(r.FixRationale))
            {
                w.WriteLine($"       why: {r.FixRationale}");
            }
        }
    }

    // ---------------------------------------------------------------------
    // Common helpers
    // ---------------------------------------------------------------------

    internal static void RecordStart(AuditLog a, string id) =>
        a.Record($"doctor.jeopardy.{id}.start", new Dictionary<string, object?> { ["id"] = id });

    internal static DoctorCheckResult Finish(
        AuditLog a,
        string id,
        DoctorCheckStatus status,
        string detail,
        string? fixCommand = null,
        string? fixRationale = null,
        bool fixApplied = false)
    {
        a.Record($"doctor.jeopardy.{id}.finish", new Dictionary<string, object?>
        {
            ["id"] = id,
            ["status"] = status.ToString().ToLowerInvariant(),
            ["detail"] = detail,
            ["fix_applied"] = fixApplied,
        });
        return new DoctorCheckResult(id, status, detail, fixCommand, fixRationale, fixApplied);
    }

    /// <summary>
    /// Scope-gate a hostname. Resolves to its first IP via <see cref="System.Net.Dns"/>
    /// and calls <c>scope.Require</c>. Returns null on success, or a failure-suitable
    /// detail string on rejection. Null scope is treated as "no scope loaded" and
    /// produces a warning-suitable message (caller decides pass/warn/fail).
    /// </summary>
    internal static string? ScopeGate(Scope.Scope? scope, string host, bool allowCopilotHost, string copilotHost)
    {
        // Allow-list the Copilot first-party endpoint before any scope checks
        // so `--allow-copilot-host` works even when no scope file is loaded.
        if (allowCopilotHost && string.Equals(host, copilotHost, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        if (scope is null)
        {
            return "scope file not loaded — cannot verify host is authorized";
        }
        try
        {
            System.Net.IPAddress[] ips;
            if (System.Net.IPAddress.TryParse(host, out var direct))
            {
                ips = new[] { direct };
            }
            else
            {
                ips = System.Net.Dns.GetHostAddresses(host);
            }
            if (ips.Length == 0)
            {
                return $"DNS: no addresses for '{host}'";
            }
            // Require every resolved address; any out-of-scope answer fails the gate.
            foreach (var ip in ips)
            {
                scope.Require(ip.ToString());
            }
            return null;
        }
        catch (ScopeException sx)
        {
            return $"scope: {sx.Message}";
        }
        catch (Exception ex)
        {
            return $"dns: {ex.GetType().Name}: {ex.Message}";
        }
    }

    internal static bool Confirm(bool assumeYes, string prompt, TextReader stdin, TextWriter stdout)
    {
        if (assumeYes) return true;
        stdout.Write(prompt);
        stdout.Flush();
        var line = stdin.ReadLine();
        return line is not null && line.Trim().Equals("y", StringComparison.OrdinalIgnoreCase);
    }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

internal sealed class DockerInstalledCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public DockerInstalledCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.docker.installed";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        try
        {
            var (exit, sout, _) = _d.Runner.Run(_d.DockerBinary, "version", 5);
            if (exit == 0)
            {
                var first = (sout ?? string.Empty).Split('\n', 2)[0].Trim();
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    string.IsNullOrEmpty(first) ? "docker present" : $"docker: {first}"));
            }
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"`docker version` exited {exit}",
                fixCommand: "install Docker Engine: apt install docker.io | dnf install docker | brew install --cask docker",
                fixRationale: "Docker is required to run the Jeopardy sandbox. Do NOT auto-install — pick the recipe for your distro."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"failed to invoke `{_d.DockerBinary} version`: {ex.Message}",
                fixCommand: "install Docker Engine: apt install docker.io | dnf install docker | brew install --cask docker"));
        }
    }
}

internal sealed class DockerDaemonCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public DockerDaemonCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.docker.daemon";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        try
        {
            var (exit, _, serr) = _d.Runner.Run(_d.DockerBinary, "info", 10);
            if (exit == 0)
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    "docker daemon reachable"));
            }
            var snippet = (serr ?? string.Empty).Replace('\n', ' ').Trim();
            if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "…";
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"`docker info` exited {exit}: {snippet}",
                fixCommand: "sudo systemctl start docker && sudo usermod -aG docker $USER && newgrp docker",
                fixRationale: "Daemon is not running or current user lacks docker group membership. drederick will NOT exec sudo for you — run the command above manually."));
        }
        catch (Exception ex)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"failed to invoke `{_d.DockerBinary} info`: {ex.Message}",
                fixCommand: "sudo systemctl start docker && sudo usermod -aG docker $USER"));
        }
    }
}

internal sealed class SandboxImageCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public SandboxImageCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.sandbox.image";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var inspectArgs = $"image inspect {_d.SandboxImage}";
        var buildCmd = $"docker build -f {_d.DockerfilePath} -t {_d.SandboxImage} {_d.SandboxBuildContext}";
        try
        {
            var (exit, _, _) = _d.Runner.Run(_d.DockerBinary, inspectArgs, 10);
            if (exit == 0)
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"image present: {_d.SandboxImage}"));
            }

            if (!install)
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    $"image missing: {_d.SandboxImage}",
                    fixCommand: buildCmd,
                    fixRationale: "Builds the Jeopardy sandbox image locally (~4 GB download + layers). Docker itself does not need sudo when your user is in the `docker` group."));
            }

            // --install path: consent-gated build.
            if (!JeopardyDoctorChecks.Confirm(assumeYes,
                    $"build sandbox image now? this will download ~4 GB. run: {buildCmd} [y/N] ",
                    stdin, stdout))
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    "image missing; build declined",
                    fixCommand: buildCmd));
            }

            stdout.WriteLine($"doctor: running: {buildCmd}");
            var (bexit, _, berr) = _d.Runner.RunShell(buildCmd, 1800);
            if (bexit == 0)
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    $"built {_d.SandboxImage} from {_d.DockerfilePath}",
                    fixApplied: true));
            }

            var snippet = (berr ?? string.Empty).Replace('\n', ' ').Trim();
            if (snippet.Length > 400) snippet = snippet.Substring(0, 400) + "…";
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"docker build failed (exit {bexit}): {snippet}",
                fixCommand: buildCmd));
        }
        catch (Exception ex)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"image inspect threw: {ex.Message}",
                fixCommand: buildCmd));
        }
    }
}

internal sealed class SandboxHealthcheckCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public SandboxHealthcheckCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.sandbox.healthcheck";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var rebuildCmd = $"docker build -f {_d.DockerfilePath} -t {_d.SandboxImage} {_d.SandboxBuildContext}";
        try
        {
            // Brief spin-up: `docker run --rm <image> echo ok` with a 30s budget.
            // This avoids pulling in SandboxManager's Scope dependency (scope may
            // be null here) while still validating the image can start.
            var runArgs = $"run --rm --pull=never {_d.SandboxImage} /bin/sh -c \"echo drederick-sandbox-ok\"";
            var (exit, sout, serr) = _d.Runner.Run(_d.DockerBinary, runArgs, 30);
            if (exit == 0 && (sout ?? string.Empty).Contains("drederick-sandbox-ok"))
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Pass,
                    "sandbox container started and exited cleanly within 30s"));
            }
            var snippet = (serr ?? string.Empty).Replace('\n', ' ').Trim();
            if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "…";
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"sandbox container failed healthcheck (exit {exit}): {snippet}",
                fixCommand: rebuildCmd,
                fixRationale: "Rebuild the image; a partial / corrupted layer is the usual cause."));
        }
        catch (TimeoutException)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                "sandbox healthcheck timed out (>30s)",
                fixCommand: rebuildCmd));
        }
        catch (Exception ex)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"sandbox healthcheck threw: {ex.Message}",
                fixCommand: rebuildCmd));
        }
    }
}

internal sealed class LlmTokenCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public LlmTokenCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.llm.token";
    public string Category => JeopardyDoctorChecks.CategoryName;

    // Preference order is load-bearing: COPILOT_TOKEN beats GH_TOKEN beats GITHUB_TOKEN beats gh auth.
    internal static readonly string[] TokenVarsInPreferenceOrder =
        { "COPILOT_TOKEN", "GH_TOKEN", "GITHUB_TOKEN" };

    internal static string? ResolveTokenVar(IEnvReader env)
    {
        foreach (var v in TokenVarsInPreferenceOrder)
        {
            var val = env.Get(v);
            if (!string.IsNullOrEmpty(val)) return v;
        }
        return null;
    }

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        switch (_d.LlmProvider)
        {
            case Drederick.Jeopardy.Llm.LlmProvider.Azure:
                {
                    var endpoint = !string.IsNullOrWhiteSpace(_d.AzureEndpoint)
                        ? _d.AzureEndpoint
                        : _d.Env.Get("AZURE_OPENAI_ENDPOINT");
                    var apiKey = _d.Env.Get("AZURE_OPENAI_API_KEY");
                    var bearer = _d.Env.Get("AZURE_OPENAI_BEARER_TOKEN");
                    var useEntra = string.Equals(_d.Env.Get("AZURE_OPENAI_USE_ENTRA"), "1", StringComparison.Ordinal);
                    var deploy = _d.Env.Get("AZURE_OPENAI_DEPLOYMENT");
                    var deployMap = _d.Env.Get("AZURE_OPENAI_DEPLOYMENT_MAP");
                    var missing = new List<string>();
                    if (string.IsNullOrWhiteSpace(endpoint)) missing.Add("AZURE_OPENAI_ENDPOINT (or --azure-endpoint)");
                    var hasAuth = !string.IsNullOrWhiteSpace(apiKey)
                        || !string.IsNullOrWhiteSpace(bearer)
                        || useEntra;
                    if (!hasAuth) missing.Add("AZURE_OPENAI_API_KEY or AZURE_OPENAI_BEARER_TOKEN or AZURE_OPENAI_USE_ENTRA=1");
                    if (string.IsNullOrWhiteSpace(deploy) && string.IsNullOrWhiteSpace(deployMap))
                        missing.Add("AZURE_OPENAI_DEPLOYMENT (or AZURE_OPENAI_DEPLOYMENT_MAP / --azure-deployment)");
                    if (missing.Count == 0)
                    {
                        var authKind = !string.IsNullOrWhiteSpace(apiKey) ? "api_key"
                            : !string.IsNullOrWhiteSpace(bearer) ? "bearer"
                            : "entra";
                        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                            DoctorCheckStatus.Pass,
                            $"Azure OpenAI configured ({authKind}) for endpoint set"));
                    }
                    return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                        DoctorCheckStatus.Fail,
                        $"Azure OpenAI config incomplete: {string.Join("; ", missing)}",
                        fixCommand: "export AZURE_OPENAI_ENDPOINT=... && export AZURE_OPENAI_API_KEY=... && export AZURE_OPENAI_DEPLOYMENT=<name>",
                        fixRationale: "See docs/LLM_SETUP.md#provider-azure for full env matrix."));
                }
            case Drederick.Jeopardy.Llm.LlmProvider.LlamaCpp:
                {
                    var url = !string.IsNullOrWhiteSpace(_d.LlamaCppUrl)
                        ? _d.LlamaCppUrl
                        : _d.Env.Get("LLAMACPP_URL");
                    if (string.IsNullOrWhiteSpace(url)) url = "http://127.0.0.1:8080";
                    if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                    {
                        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                            DoctorCheckStatus.Fail,
                            $"LLAMACPP_URL '{url}' is not a valid absolute URL",
                            fixCommand: "export LLAMACPP_URL=http://127.0.0.1:8080"));
                    }
                    return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                        DoctorCheckStatus.Pass,
                        $"llama.cpp base URL configured: {url}"));
                }
            case Drederick.Jeopardy.Llm.LlmProvider.Copilot:
            default:
                {
                    var picked = ResolveTokenVar(_d.Env);
                    if (picked is not null)
                    {
                        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                            DoctorCheckStatus.Pass,
                            $"LLM token present via ${picked}"));
                    }
                    var ghToken = CopilotAuthTokenResolver.TryReadGitHubCliToken();
                    if (!string.IsNullOrWhiteSpace(ghToken))
                    {
                        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                            DoctorCheckStatus.Pass,
                            "LLM token present via authenticated GitHub CLI (`gh auth token`)"));
                    }
                    return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                        DoctorCheckStatus.Fail,
                        "no COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN in environment and no authenticated gh CLI session",
                        fixCommand: "gh auth login --web   # or export COPILOT_TOKEN / GH_TOKEN / GITHUB_TOKEN",
                        fixRationale: "See docs/LLM_SETUP.md and docs/JEOPARDY.md for provisioning steps."));
                }
        }
    }
}

internal sealed class LlmReachableCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public LlmReachableCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.llm.reachable";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public async Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        switch (_d.LlmProvider)
        {
            case Drederick.Jeopardy.Llm.LlmProvider.Azure:
                return await CheckAzureAsync(ct).ConfigureAwait(false);
            case Drederick.Jeopardy.Llm.LlmProvider.LlamaCpp:
                return await CheckLlamaCppAsync(ct).ConfigureAwait(false);
            case Drederick.Jeopardy.Llm.LlmProvider.Copilot:
            default:
                return await CheckCopilotAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task<DoctorCheckResult> CheckCopilotAsync(CancellationToken ct)
    {
        var picked = LlmTokenCheck.ResolveTokenVar(_d.Env);
        var token = picked is not null
            ? _d.Env.Get(picked)
            : CopilotAuthTokenResolver.TryReadGitHubCliToken();
        if (string.IsNullOrWhiteSpace(token))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — no LLM token set (see jeopardy.llm.token)");
        }

        var scopeErr = JeopardyDoctorChecks.ScopeGate(_d.Scope, _d.CopilotHost, _d.AllowCopilotHost, _d.CopilotHost);
        if (scopeErr is not null)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"{_d.CopilotHost}: {scopeErr}",
                fixCommand: $"pass --allow-copilot-host, or add {_d.CopilotHost} (resolved IPs) to your scope file",
                fixRationale: "Network checks must go through scope.Require; api.githubcopilot.com is first-party Microsoft but still gated for auditability.");
        }

        var headers = new Dictionary<string, string>
        {
            ["Authorization"] = $"Bearer {token}",
            ["Accept"] = "application/json",
            ["User-Agent"] = "drederick-doctor",
        };
        int status;
        try
        {
            status = await _d.Http.GetStatusAsync(_d.CopilotModelsUrl, headers, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"GET {_d.CopilotModelsUrl} threw: {ex.Message}",
                fixCommand: "check network egress and token validity; see docs/LLM_SETUP.md");
        }

        if (status == 200)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"GET {_d.CopilotModelsUrl} → 200");
        }
        return JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"GET {_d.CopilotModelsUrl} → {(status < 0 ? "transport error" : status.ToString())}",
            fixCommand: "verify token scope/validity and proxy/egress; see docs/LLM_SETUP.md");
    }

    private async Task<DoctorCheckResult> CheckAzureAsync(CancellationToken ct)
    {
        var endpoint = !string.IsNullOrWhiteSpace(_d.AzureEndpoint)
            ? _d.AzureEndpoint
            : _d.Env.Get("AZURE_OPENAI_ENDPOINT");
        if (string.IsNullOrWhiteSpace(endpoint))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — AZURE_OPENAI_ENDPOINT not set (see jeopardy.llm.token)");
        }
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var u))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"AZURE_OPENAI_ENDPOINT '{endpoint}' is not an absolute URL");
        }

        var scopeErr = JeopardyDoctorChecks.ScopeGate(_d.Scope, u.Host, _d.AllowCopilotHost, _d.CopilotHost);
        if (scopeErr is not null)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"{u.Host}: {scopeErr}",
                fixCommand: $"drederick scope add {u.Host}",
                fixRationale: "Azure OpenAI endpoint must be in scope before doctor will probe it.");
        }

        // The data-plane root (/) typically answers 404 without auth, which is
        // still a reachability signal. We don't authenticate because we don't
        // want the api-key to leave the process for a reachability probe.
        var probe = endpoint.TrimEnd('/') + "/openai/models?api-version=" + Drederick.Jeopardy.Llm.AzureOpenAiLlmClient.DefaultApiVersion;
        int status;
        try
        {
            status = await _d.Http.GetStatusAsync(probe,
                new Dictionary<string, string> { ["Accept"] = "application/json", ["User-Agent"] = "drederick-doctor" },
                ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"GET {probe} threw: {ex.Message}",
                fixCommand: "check network egress and endpoint spelling");
        }
        // 200 = listable (rare), 401 = auth required (expected), 404 = wrong
        // path but host resolves — all three prove TCP/TLS reachability.
        if (status == 200 || status == 401 || status == 404)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"GET {probe} → {status}");
        }
        return JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"GET {probe} → {(status < 0 ? "transport error" : status.ToString())}",
            fixCommand: "verify endpoint / network egress; see docs/LLM_SETUP.md#provider-azure");
    }

    private async Task<DoctorCheckResult> CheckLlamaCppAsync(CancellationToken ct)
    {
        var url = !string.IsNullOrWhiteSpace(_d.LlamaCppUrl)
            ? _d.LlamaCppUrl
            : _d.Env.Get("LLAMACPP_URL");
        if (string.IsNullOrWhiteSpace(url)) url = "http://127.0.0.1:8080";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var baseUri))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"LLAMACPP_URL '{url}' is not a valid absolute URL");
        }

        // Localhost / loopback is always permitted without scope (the server
        // runs on the operator workstation). For remote llama-server
        // deployments the host must be in scope.
        var host = baseUri.Host;
        bool loopback = host is "127.0.0.1" or "::1" or "localhost";
        if (!loopback)
        {
            var scopeErr = JeopardyDoctorChecks.ScopeGate(_d.Scope, host, _d.AllowCopilotHost, _d.CopilotHost);
            if (scopeErr is not null)
            {
                return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    $"{host}: {scopeErr}",
                    fixCommand: $"drederick scope add {host}",
                    fixRationale: "Remote llama.cpp endpoint must be in scope before doctor will probe it.");
            }
        }

        var probe = url.TrimEnd('/') + "/v1/models";
        int status;
        try
        {
            // 2s budget: llama-server answers instantly when up; when down
            // we want a fast fail so `doctor` stays snappy.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var headers = new Dictionary<string, string>
            {
                ["Accept"] = "application/json",
                ["User-Agent"] = "drederick-doctor",
            };
            status = await _d.Http.GetStatusAsync(probe, headers, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"GET {probe} timed out (>2s)",
                fixCommand: "start llama-server (see docs/LLM_SETUP.md#provider-llamacpp)");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"GET {probe} threw: {ex.Message}",
                fixCommand: "start llama-server (see docs/LLM_SETUP.md#provider-llamacpp)");
        }
        // 200 = healthy, 404 = slim build without /v1/models but reachable,
        // 401 = reverse-proxy in front requiring auth but reachable.
        if (status == 200 || status == 404 || status == 401)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"GET {probe} → {status}");
        }
        return JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"GET {probe} → {(status < 0 ? "transport error" : status.ToString())}",
            fixCommand: "start/restart llama-server; see docs/LLM_SETUP.md#provider-llamacpp");
    }
}

internal sealed class CtfdConfiguredCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public CtfdConfiguredCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.ctfd.configured";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var url = _d.Env.Get("CTFD_URL");
        var token = _d.Env.Get("CTFD_TOKEN");
        if (!string.IsNullOrEmpty(url) && !string.IsNullOrEmpty(token))
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                "CTFD_URL and CTFD_TOKEN set"));
        }
        // Warn-only: operator may pass these via CLI flags on the actual run.
        var missing = new List<string>();
        if (string.IsNullOrEmpty(url)) missing.Add("CTFD_URL");
        if (string.IsNullOrEmpty(token)) missing.Add("CTFD_TOKEN");
        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Warn,
            $"CTFd env unset ({string.Join(", ", missing)}) — ok if you pass via CLI",
            fixCommand: "export CTFD_URL=https://<host>  && export CTFD_TOKEN=<token>",
            fixRationale: "See docs/JEOPARDY.md. These may also be supplied via CLI at run time."));
    }
}

internal sealed class CtfdReachableCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public CtfdReachableCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.ctfd.reachable";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public async Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var url = _d.Env.Get("CTFD_URL");
        var token = _d.Env.Get("CTFD_TOKEN");
        if (string.IsNullOrEmpty(url))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — CTFD_URL not set");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var baseUri))
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"CTFD_URL '{url}' is not a valid absolute URL",
                fixCommand: "export CTFD_URL=https://<host>");
        }

        var scopeErr = JeopardyDoctorChecks.ScopeGate(_d.Scope, baseUri.Host, _d.AllowCopilotHost, _d.CopilotHost);
        if (scopeErr is not null)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"{baseUri.Host}: {scopeErr}",
                fixCommand: $"drederick scope add {baseUri.Host}",
                fixRationale: "CTFd host must be in scope before doctor will probe it.");
        }

        var probeUrl = new Uri(baseUri, "/api/v1/challenges").ToString();
        var headers = new Dictionary<string, string>
        {
            ["Accept"] = "application/json",
            ["User-Agent"] = "drederick-doctor",
        };
        if (!string.IsNullOrEmpty(token))
        {
            headers["Authorization"] = $"Token {token}";
        }

        int status;
        try
        {
            status = await _d.Http.GetStatusAsync(probeUrl, headers, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"GET {probeUrl} threw: {ex.Message}",
                fixCommand: "verify CTFD_URL reachability (DNS, TLS, VPN) and CTFD_TOKEN validity");
        }

        // 200 = authed OK, 401 = unauth but endpoint lives — both prove reachability.
        if (status == 200 || status == 401)
        {
            return JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"GET {probeUrl} → {status}");
        }
        return JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"GET {probeUrl} → {(status < 0 ? "transport error" : status.ToString())}",
            fixCommand: "verify CTFD_URL / CTFD_TOKEN; see docs/JEOPARDY.md");
    }
}

internal sealed class DiskSpaceCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public DiskSpaceCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.disk.space";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var avail = _d.DiskFree.AvailableBytes(_d.DockerRootDir);
        if (avail < 0)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                $"could not determine free space at {_d.DockerRootDir}"));
        }
        var availGb = avail / 1024.0 / 1024.0 / 1024.0;
        var minGb = _d.MinFreeBytes / 1024.0 / 1024.0 / 1024.0;
        if (avail >= _d.MinFreeBytes)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"{availGb:F1} GiB free at {_d.DockerRootDir} (>= {minGb:F0} GiB)"));
        }
        return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
            DoctorCheckStatus.Fail,
            $"only {availGb:F1} GiB free at {_d.DockerRootDir} (< {minGb:F0} GiB)",
            fixCommand: "free space, or relocate docker root via /etc/docker/daemon.json data-root",
            fixRationale: "Sandbox image + scratch volumes need ~10 GiB headroom."));
    }
}

internal sealed class ScopeFileCheck : IDoctorCheck
{
    private readonly JeopardyDoctorDeps _d;
    public ScopeFileCheck(JeopardyDoctorDeps d) => _d = d;
    public string Id => "jeopardy.scope.file";
    public string Category => JeopardyDoctorChecks.CategoryName;

    public Task<DoctorCheckResult> RunAsync(bool install, bool assumeYes, TextReader stdin, TextWriter stdout, CancellationToken ct)
    {
        JeopardyDoctorChecks.RecordStart(_d.Audit, Id);
        var url = _d.Env.Get("CTFD_URL");
        if (string.IsNullOrEmpty(url))
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — CTFD_URL not configured"));
        }
        if (_d.Scope is null)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Warn,
                "skipped — scope file not loaded (pass --scope)"));
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var baseUri))
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"CTFD_URL '{url}' is not a valid absolute URL"));
        }
        var host = baseUri.Host;
        try
        {
            System.Net.IPAddress[] ips = System.Net.IPAddress.TryParse(host, out var direct)
                ? new[] { direct }
                : System.Net.Dns.GetHostAddresses(host);
            if (ips.Length == 0)
            {
                return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                    DoctorCheckStatus.Fail,
                    $"DNS: no addresses for CTFd host '{host}'",
                    fixCommand: $"drederick scope add {host}"));
            }
            foreach (var ip in ips)
            {
                if (!_d.Scope.Contains(ip.ToString()))
                {
                    return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                        DoctorCheckStatus.Fail,
                        $"CTFd host '{host}' ({ip}) not in scope",
                        fixCommand: $"drederick scope add {host}",
                        fixRationale: "Scope is the authorization gate; add the CTFd host before running."));
                }
            }
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Pass,
                $"CTFd host '{host}' resolves entirely in-scope"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(JeopardyDoctorChecks.Finish(_d.Audit, Id,
                DoctorCheckStatus.Fail,
                $"DNS error resolving '{host}': {ex.Message}",
                fixCommand: $"drederick scope add {host}"));
        }
    }
}
