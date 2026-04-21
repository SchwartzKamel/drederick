using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Audit;
using Drederick.Recon.Binary;
using Drederick.Scope;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Analyze tab. Wraps <see cref="BinaryAnalyzer"/> for local-file
/// binary security analysis (ELF/PE/Mach-O). The binary path is entered
/// (or browsed to) in the UI; analysis runs on a thread-pool thread.
///
/// <para>
/// Invariant posture:
/// <list type="bullet">
///   <item><see cref="BinaryAnalyzer"/> calls <c>_scope.RequireFile(filePath)</c>
///   as its first operation, which verifies file existence + readability. A
///   minimal local-only scope is constructed for this purpose — the tool
///   invariant is satisfied without a network CIDR scope, because the
///   analyzer only reads a local file.</item>
///   <item><c>@invariant-id:aggregate-not-execute</c> — findings are displayed
///   and optionally saved to JSON; the binary is never executed.</item>
/// </list>
/// </para>
/// </summary>
public sealed partial class AnalyzeViewModel : ObservableObject
{
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    private string _binaryPath = string.Empty;

    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private bool _verbose;

    [ObservableProperty]
    private bool _saveJson;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusLine = "Select a binary file and click Analyze.";

    [ObservableProperty]
    private string _reportText = string.Empty;

    public ObservableCollection<AnalyzeFindingRow> Findings { get; } = new();

    private const string LocalAnalysisScope = "127.0.0.1/32";
    private const string LocalAnalysisScopeSource = "<analyze-local>";

    private bool CanAnalyze() => !IsBusy && !string.IsNullOrWhiteSpace(BinaryPath);

    [RelayCommand(CanExecute = nameof(CanAnalyze))]
    public async Task AnalyzeAsync(CancellationToken ct)
    {
        IsBusy = true;
        StatusLine = "Analyzing…";
        ReportText = string.Empty;
        Findings.Clear();

        try
        {
            // Run I/O on the thread pool; capture the binary path / options
            // now so the background work doesn't race with UI edits.
            var binaryPath = BinaryPath;
            var outputDir = OutputDir;
            var verbose = Verbose;
            var saveJson = SaveJson;

            var (report, error) = await Task.Run(async () =>
            {
                Directory.CreateDirectory(outputDir);
                var auditPath = Path.Combine(outputDir, "audit.jsonl");
                using var audit = new AuditLog(auditPath);
                audit.Record("ui.analyze.start", new Dictionary<string, object?>
                {
                    ["file_path"] = binaryPath,
                    ["verbose"] = verbose,
                    ["save_json"] = saveJson,
                });

                // Minimal local scope. BinaryAnalyzer's first statement is
                // _scope.RequireFile(filePath), which checks file existence
                // and readability only — no CIDR matching is involved.
                var scope = ScopeLoader.Parse(LocalAnalysisScope, LocalAnalysisScopeSource, labMode: true);
                var analyzer = new BinaryAnalyzer(scope, audit);

                BinaryAnalysisReport? report = null;
                string? error = null;
                try
                {
                    report = await analyzer.AnalyzeAsync(binaryPath, ct).ConfigureAwait(false);
                }
                catch (FileNotFoundException ex)
                {
                    error = $"File not found: {ex.FileName ?? binaryPath}";
                    audit.Record("ui.analyze.error", new Dictionary<string, object?> { ["error"] = "file-not-found" });
                }
                catch (UnauthorizedAccessException)
                {
                    error = $"Permission denied reading: {binaryPath}";
                    audit.Record("ui.analyze.error", new Dictionary<string, object?> { ["error"] = "permission-denied" });
                }

                if (report is not null)
                {
                    audit.Record("ui.analyze.finish", new Dictionary<string, object?>
                    {
                        ["findings"] = report.Findings.Count,
                        ["file_type"] = report.Metadata.FileType,
                        ["arch"] = report.Metadata.Architecture,
                    });
                }

                return (report, error);
            }, ct).ConfigureAwait(true);

            if (error is not null)
            {
                StatusLine = error;
                return;
            }

            // Format the text report (on the caller's thread after ConfigureAwait(true)).
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"═══ BINARY ANALYSIS: {Path.GetFileName(report!.FilePath)} ═══");
            sb.AppendLine($"  Analyzed:  {report.Timestamp}");
            sb.AppendLine();
            AppendMetadata(sb, report);
            sb.AppendLine();
            AppendSecurity(sb, report);
            sb.AppendLine();
            AppendDependencies(sb, report, verbose);
            if (verbose
                || report.Strings.SuspiciousKeywords.Count > 0
                || report.Strings.CryptoIndicators.Count > 0)
            {
                sb.AppendLine();
                AppendStrings(sb, report);
            }
            if (report.Findings.Count > 0)
            {
                sb.AppendLine();
                AppendFindings(sb, report);
            }
            ReportText = sb.ToString();

            // Optionally write JSON.
            if (saveJson)
            {
                // GetFileName strips the directory; the extra check
                // defends against unusual file names that still contain
                // path-separator characters after GetFileName.
                var safeName = Path.GetFileName(binaryPath);
                if (safeName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                    safeName = "binary";
                var jsonPath = Path.Combine(outputDir, safeName + ".analysis.json");
                await Task.Run(() => File.WriteAllText(jsonPath, JsonSerializer.Serialize(report,
                    new JsonSerializerOptions { WriteIndented = true })), ct).ConfigureAwait(true);
            }

            foreach (var row in report.Findings.Select(f => new AnalyzeFindingRow(f)))
                Findings.Add(row);

            var critical = Findings.Count(r => r.Severity == "Critical");
            var warnings = Findings.Count(r => r.Severity == "Warning");
            StatusLine = $"{report.Metadata.FileType} {report.Metadata.Architecture}"
                + $" — {critical} critical, {warnings} warning(s), {Findings.Count - critical - warnings} info.";
        }
        catch (OperationCanceledException)
        {
            StatusLine = "Cancelled.";
        }
        catch (Exception ex)
        {
            StatusLine = $"Error: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    // ── Text formatters (mirrors AnalyzeBinaryCommand, kept here so the
    //    UI project doesn't depend on the CLI assembly) ──────────────────

    private static void AppendMetadata(System.Text.StringBuilder sb, BinaryAnalysisReport r)
    {
        sb.AppendLine("─ METADATA");
        sb.AppendLine($"  File Type:   {r.Metadata.FileType}");
        sb.AppendLine($"  Arch:        {r.Metadata.Architecture}");
        sb.AppendLine($"  Platform:    {r.Metadata.Platform}");
        if (!string.IsNullOrEmpty(r.Metadata.EntryPoint))
            sb.AppendLine($"  Entry:       {r.Metadata.EntryPoint}");
        if (!string.IsNullOrEmpty(r.Metadata.Sha256))
            sb.AppendLine($"  SHA256:      {r.Metadata.Sha256}");
        if (r.Metadata.Sections.Count > 0)
            sb.AppendLine($"  Sections:    {string.Join(", ", r.Metadata.Sections)}");
    }

    private static void AppendSecurity(System.Text.StringBuilder sb, BinaryAnalysisReport r)
    {
        var s = r.Security;
        sb.AppendLine("─ SECURITY POSTURE");
        sb.AppendLine($"  ASLR:           {FormatBool(s.IsAslrEnabled)}");
        sb.AppendLine($"  NX:             {FormatBool(s.IsNxEnabled)}");
        sb.AppendLine($"  PIE:            {FormatBool(s.IsPieEnabled)}");
        sb.AppendLine($"  Stack Canary:   {FormatBool(s.HasCanary)}");
        sb.AppendLine($"  Stack SSP:      {FormatBool(s.HasStackSmashing)}");
        sb.AppendLine($"  Format Strings: {FormatBool(s.HasFormatStrings)}");
        if (s.DangerousFunctions.Count > 0)
            sb.AppendLine($"  Dangerous Fns:  {string.Join(", ", s.DangerousFunctions)}");
    }

    private static void AppendDependencies(System.Text.StringBuilder sb, BinaryAnalysisReport r, bool verbose)
    {
        var libs = r.Dependencies.ImportedLibs;
        sb.AppendLine("─ DEPENDENCIES");
        if (libs.Count == 0)
        {
            sb.AppendLine("  (none)");
        }
        else
        {
            var shown = verbose ? libs : libs.Take(5).ToList();
            foreach (var lib in shown) sb.AppendLine($"  • {lib}");
            if (!verbose && libs.Count > 5)
                sb.AppendLine($"  … +{libs.Count - 5} more (tick Verbose for all)");
        }
        if (!string.IsNullOrEmpty(r.Dependencies.Rpath))
            sb.AppendLine($"  RPATH:    {r.Dependencies.Rpath}");
        if (!string.IsNullOrEmpty(r.Dependencies.Runpath))
            sb.AppendLine($"  RUNPATH:  {r.Dependencies.Runpath}");
    }

    private static void AppendStrings(System.Text.StringBuilder sb, BinaryAnalysisReport r)
    {
        sb.AppendLine("─ STRINGS");
        sb.AppendLine($"  Total: {r.Strings.Count}");
        if (r.Strings.SuspiciousKeywords.Count > 0)
            sb.AppendLine($"  Suspicious:  {string.Join(", ", r.Strings.SuspiciousKeywords)}");
        if (r.Strings.CryptoIndicators.Count > 0)
            sb.AppendLine($"  Crypto:      {string.Join(", ", r.Strings.CryptoIndicators)}");
    }

    private static void AppendFindings(System.Text.StringBuilder sb, BinaryAnalysisReport r)
    {
        sb.AppendLine("─ FINDINGS");
        foreach (var f in r.Findings.OrderByDescending(x => x.Severity))
        {
            sb.AppendLine($"  [{f.Severity}] {f.Category}: {f.Title}");
            sb.AppendLine($"    {f.Description}");
            if (!string.IsNullOrEmpty(f.Remediation))
                sb.AppendLine($"    Remedy: {f.Remediation}");
        }
    }

    private static string FormatBool(bool? v) => v switch
    {
        true => "✓ yes",
        false => "✗ no",
        null => "?",
    };
}

/// <summary>Presentation-layer row for a binary analysis finding.</summary>
public sealed class AnalyzeFindingRow
{
    public AnalyzeFindingRow(BinaryFinding f)
    {
        Severity = f.Severity.ToString();
        Category = f.Category.ToString();
        Title = f.Title;
        Description = f.Description;
        Remediation = f.Remediation ?? string.Empty;
    }

    public string Severity { get; }
    public string Category { get; }
    public string Title { get; }
    public string Description { get; }
    public string Remediation { get; }
}
