using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Init tab: a first-run setup wizard presented as a single
/// scrollable form with four distinct sections. Each section corresponds
/// to a step in <see cref="Drederick.Cli.InitCommand"/> but adapts to the
/// GUI interaction model (buttons instead of stdin prompts).
///
/// <list type="bullet">
///   <item>Section 1 — Doctor detect (read-only; displays current tool status).</item>
///   <item>Section 2 — Credentials (HTB API token, HTTP proxy) stored in
///     <c>~/.drederick/config.json</c> with 0600 permissions on Unix.</item>
///   <item>Section 3 — Sample scope file creation (<c>~/scope.txt</c>).</item>
///   <item>Section 4 — Quick-start commands for copy/paste.</item>
/// </list>
///
/// <c>@invariant-id:doctor-workstation-only</c> is preserved: tool detection
/// is read-only; any install step requires an explicit Doctor-tab consent tick.
/// </summary>
public sealed partial class InitViewModel : ObservableObject
{
    // ── Shared ──────────────────────────────────────────────────────────

    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private bool _isBusy;

    // ── Section 1: Doctor ────────────────────────────────────────────────

    [ObservableProperty]
    private string _doctorStatus = "Not run yet. Click Detect below.";

    public ObservableCollection<ToolRow> DetectedTools { get; } = new();

    [RelayCommand]
    public async Task DetectToolsAsync()
    {
        IsBusy = true;
        DoctorStatus = "Detecting…";
        IReadOnlyList<ToolInfo>? detected = null;
        try
        {
            await Task.Run(() =>
            {
                Directory.CreateDirectory(OutputDir);
                var auditPath = Path.Combine(OutputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                audit.Record("ui.init.doctor_detect", new Dictionary<string, object?> { ["initiator"] = "ui-init" });
                var runner = new DoctorRunner(audit);
                detected = runner.Detect();
            }).ConfigureAwait(true);

            DetectedTools.Clear();
            if (detected is not null)
            {
                foreach (var t in detected) DetectedTools.Add(new ToolRow(t));
                var missing = detected.Count(x => !x.Found);
                DoctorStatus = missing == 0
                    ? "All tools present."
                    : $"{missing} tool(s) missing — use the Doctor tab to install.";
            }
        }
        catch (Exception ex)
        {
            DoctorStatus = $"Detect failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ── Section 2: Credentials ───────────────────────────────────────────

    /// <summary>
    /// HackTheBox API token. Entered in a PasswordBox (masked).
    /// Stored in <c>~/.drederick/config.json</c> with 0600 permissions.
    /// Never committed to any audit log.
    /// </summary>
    [ObservableProperty]
    private string _htbToken = string.Empty;

    [ObservableProperty]
    private string _httpProxy = string.Empty;

    [ObservableProperty]
    private string _credentialStatus = string.Empty;

    [RelayCommand]
    public async Task SaveCredentialsAsync()
    {
        IsBusy = true;
        CredentialStatus = "Saving…";
        string? resultMsg = null;
        try
        {
            var token = HtbToken;
            var proxy = HttpProxy;

            await Task.Run(() =>
            {
                var configPath = GetConfigPath();

                Directory.CreateDirectory(OutputDir);
                var auditPath = Path.Combine(OutputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                // Audit the action — never log the token value.
                audit.Record("ui.init.credentials_save", new Dictionary<string, object?>
                {
                    ["has_token"] = !string.IsNullOrWhiteSpace(token),
                    ["has_proxy"] = !string.IsNullOrWhiteSpace(proxy),
                });

                var config = new Dictionary<string, object?> { ["version"] = ConfigVersion, ["created_at"] = DateTimeOffset.UtcNow.ToString("o") };
                if (!string.IsNullOrWhiteSpace(token)) config["htb_api_token"] = token;
                if (!string.IsNullOrWhiteSpace(proxy)) config["http_proxy"] = proxy;

                var dir = Path.GetDirectoryName(configPath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                File.WriteAllText(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));

                // Attempt to restrict permissions to owner-only on Unix.
                try
                {
#pragma warning disable CA1416
                    File.SetUnixFileMode(configPath,
                        System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite);
#pragma warning restore CA1416
                }
                catch (PlatformNotSupportedException) { /* Windows — caller is responsible */ }

                resultMsg = $"Credentials saved to {configPath}";
            }).ConfigureAwait(true);

            CredentialStatus = resultMsg ?? "Done.";
        }
        catch (UnauthorizedAccessException)
        {
            CredentialStatus = "Permission denied writing config file.";
        }
        catch (Exception ex)
        {
            CredentialStatus = $"Failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ── Section 3: Sample scope file ─────────────────────────────────────

    [ObservableProperty]
    private string _scopeStatus = string.Empty;

    [RelayCommand]
    public async Task CreateSampleScopeAsync()
    {
        IsBusy = true;
        ScopeStatus = "Creating…";
        string? resultMsg = null;
        try
        {
            await Task.Run(() =>
            {
                var home = GetHomeDirectory();
                var scopePath = Path.Combine(home, "scope.txt");

                Directory.CreateDirectory(OutputDir);
                var auditPath = Path.Combine(OutputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                audit.Record("ui.init.create_scope", new Dictionary<string, object?>
                {
                    ["path"] = scopePath,
                    ["already_exists"] = File.Exists(scopePath),
                });

                if (File.Exists(scopePath))
                {
                    resultMsg = $"{scopePath} already exists — not overwritten.";
                    return;
                }

                const string example = """
                    # Example scope — one CIDR or IP per line.
                    # Lines starting with # are comments.
                    # Lab environment examples:
                    10.0.0.0/24
                    192.168.1.0/24
                    """;
                File.WriteAllText(scopePath, example);
                resultMsg = $"Sample scope created at {scopePath}";
            }).ConfigureAwait(true);

            ScopeStatus = resultMsg ?? "Done.";
        }
        catch (Exception ex)
        {
            ScopeStatus = $"Failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ── Section 4: Quick-start summary ───────────────────────────────────

    /// <summary>
    /// Pre-formatted quick-start cheatsheet shown at the bottom of the tab.
    /// Static — the operator can copy/paste from this.
    /// </summary>
    public static string QuickStart { get; } = """
        # Verify tools
        drederick doctor

        # Run a recon pass
        drederick --scope ~/scope.txt --target 10.10.10.42 --out out/

        # Browse results in Datasette
        drederick serve --out out/

        # Full docs
        https://github.com/SchwartzKamel/drederick/tree/main/docs
        """;

    // ── Helpers ──────────────────────────────────────────────────────────

    public static string GetConfigPath()
    {
        return Path.Combine(GetHomeDirectory(), ".drederick", "config.json");
    }

    private static string GetHomeDirectory() =>
        Environment.GetEnvironmentVariable("HOME")
        ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private const int ConfigVersion = 1;
}
