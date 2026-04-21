using System.Text.Json;
using Drederick.Audit;
using Drederick.Recon.Binary;
using Drederick.Scope;

namespace Drederick.Cli;

/// <summary>
/// Handles the 'drederick analyze' subcommand.
/// Performs binary security analysis with scope enforcement.
/// </summary>
public sealed class AnalyzeBinaryCommand
{
    private readonly IBinaryAnalyzer _analyzer;
    private readonly TextWriter _out;
    private readonly TextWriter _err;

    public AnalyzeBinaryCommand(IBinaryAnalyzer analyzer, TextWriter? outWriter = null, TextWriter? errWriter = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _out = outWriter ?? Console.Out;
        _err = errWriter ?? Console.Error;
    }

    /// <summary>
    /// Executes the analyze subcommand with the given options.
    /// Returns exit code: 0 on success, 2 on validation/missing file, 3 on permission denied, 1 on error.
    /// </summary>
    public async Task<int> ExecuteAsync(CommandLineOptions opts)
    {
        if (string.IsNullOrEmpty(opts.BinaryPath))
        {
            _err.WriteLine("analyze: binary path required. Usage: drederick analyze <binary-path> [options]");
            return 2;
        }

        try
        {
            var report = await _analyzer.AnalyzeAsync(opts.BinaryPath, CancellationToken.None);

            string output;
            if (opts.AnalyzeJson)
            {
                output = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            }
            else
            {
                output = FormatReport(report, opts.AnalyzeVerbose);
            }

            if (!string.IsNullOrEmpty(opts.AnalyzeOutput))
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(opts.AnalyzeOutput) ?? ".");
                    File.WriteAllText(opts.AnalyzeOutput, output);
                    _out.WriteLine($"analyze: report written to {opts.AnalyzeOutput}");
                }
                catch (UnauthorizedAccessException)
                {
                    _err.WriteLine($"analyze: permission denied writing to {opts.AnalyzeOutput}");
                    return 3;
                }
                catch (Exception ex)
                {
                    _err.WriteLine($"analyze: failed to write output: {ex.Message}");
                    return 1;
                }
            }
            else
            {
                _out.Write(output);
            }

            return 0;
        }
        catch (FileNotFoundException)
        {
            _err.WriteLine($"analyze: file not found: {opts.BinaryPath}");
            return 2;
        }
        catch (UnauthorizedAccessException)
        {
            _err.WriteLine($"analyze: permission denied reading {opts.BinaryPath}");
            return 3;
        }
        catch (ScopeException ex)
        {
            _err.WriteLine($"analyze: {ex.Message}");
            return 2;
        }
        catch (Exception ex)
        {
            _err.WriteLine($"analyze: error: {ex.Message}");
            return 1;
        }
    }

    private static string FormatReport(BinaryAnalysisReport report, bool verbose)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("╔═══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║                   BINARY ANALYSIS REPORT                      ║");
        sb.AppendLine("╚═══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();

        sb.AppendLine($"File:        {report.FilePath}");
        sb.AppendLine($"Analyzed:    {report.Timestamp}");
        sb.AppendLine($"Analyzer:    {report.AnalyzerVersion}");
        sb.AppendLine();

        FormatMetadata(sb, report.Metadata);
        sb.AppendLine();

        FormatDependencies(sb, report.Dependencies, verbose);
        sb.AppendLine();

        if (verbose || report.Strings.SuspiciousKeywords.Count > 0 || report.Strings.CryptoIndicators.Count > 0)
        {
            FormatStrings(sb, report.Strings);
            sb.AppendLine();
        }

        FormatSecurity(sb, report.Security);
        sb.AppendLine();

        if (report.Findings.Count > 0)
        {
            FormatFindings(sb, report.Findings);
            sb.AppendLine();
        }

        return sb.ToString();
    }

    private static void FormatMetadata(System.Text.StringBuilder sb, BinaryMetadata metadata)
    {
        sb.AppendLine("─ METADATA");
        sb.AppendLine($"  File Type:      {metadata.FileType}");
        sb.AppendLine($"  Architecture:   {metadata.Architecture}");
        sb.AppendLine($"  Platform:       {metadata.Platform}");

        if (metadata.Sections.Count > 0)
        {
            sb.Append($"  Sections:       ");
            sb.AppendLine(string.Join(", ", metadata.Sections));
        }

        if (!string.IsNullOrEmpty(metadata.EntryPoint))
        {
            sb.AppendLine($"  Entry Point:    {metadata.EntryPoint}");
        }

        if (!string.IsNullOrEmpty(metadata.Sha256))
        {
            sb.AppendLine($"  SHA256:         {metadata.Sha256}");
        }
    }

    private static void FormatDependencies(System.Text.StringBuilder sb, BinaryDependencies dependencies, bool verbose)
    {
        sb.AppendLine("─ DEPENDENCIES");

        if (dependencies.ImportedLibs.Count > 0)
        {
            if (verbose)
            {
                sb.AppendLine($"  Imported Libraries ({dependencies.ImportedLibs.Count}):");
                foreach (var lib in dependencies.ImportedLibs)
                {
                    sb.AppendLine($"    • {lib}");
                }
            }
            else
            {
                sb.AppendLine($"  Imported Libraries: {dependencies.ImportedLibs.Count} found");
                foreach (var lib in dependencies.ImportedLibs.Take(5))
                {
                    sb.AppendLine($"    • {lib}");
                }
                if (dependencies.ImportedLibs.Count > 5)
                {
                    sb.AppendLine($"    ... and {dependencies.ImportedLibs.Count - 5} more (use --verbose for all)");
                }
            }
        }

        if (!string.IsNullOrEmpty(dependencies.Rpath))
        {
            sb.AppendLine($"  RPATH:          {dependencies.Rpath}");
        }

        if (!string.IsNullOrEmpty(dependencies.Runpath))
        {
            sb.AppendLine($"  RUNPATH:        {dependencies.Runpath}");
        }
    }

    private static void FormatStrings(System.Text.StringBuilder sb, BinaryStrings strings)
    {
        sb.AppendLine("─ STRINGS & KEYWORDS");
        sb.AppendLine($"  Total Strings:  {strings.Count}");

        if (strings.SuspiciousKeywords.Count > 0)
        {
            sb.AppendLine($"  Suspicious Keywords:");
            foreach (var kw in strings.SuspiciousKeywords)
            {
                sb.AppendLine($"    • {kw}");
            }
        }

        if (strings.CryptoIndicators.Count > 0)
        {
            sb.AppendLine($"  Crypto Indicators:");
            foreach (var ind in strings.CryptoIndicators)
            {
                sb.AppendLine($"    • {ind}");
            }
        }
    }

    private static void FormatSecurity(System.Text.StringBuilder sb, BinarySecurity security)
    {
        sb.AppendLine("─ SECURITY POSTURE");

        sb.Append("  ASLR:           ");
        sb.AppendLine(FormatBoolValue(security.IsAslrEnabled));

        sb.Append("  NX:             ");
        sb.AppendLine(FormatBoolValue(security.IsNxEnabled));

        sb.Append("  PIE:            ");
        sb.AppendLine(FormatBoolValue(security.IsPieEnabled));

        sb.Append("  Stack Canary:   ");
        sb.AppendLine(FormatBoolValue(security.HasCanary));

        sb.Append("  Stack Smashing: ");
        sb.AppendLine(FormatBoolValue(security.HasStackSmashing));

        sb.Append("  Format Strings: ");
        sb.AppendLine(FormatBoolValue(security.HasFormatStrings));

        if (security.DangerousFunctions.Count > 0)
        {
            sb.AppendLine($"  Dangerous Functions:");
            foreach (var func in security.DangerousFunctions)
            {
                sb.AppendLine($"    • {func}");
            }
        }
    }

    private static void FormatFindings(System.Text.StringBuilder sb, List<BinaryFinding> findings)
    {
        sb.AppendLine("─ FINDINGS");

        var critical = findings.Where(f => f.Severity == FindingSeverity.Critical).ToList();
        var warnings = findings.Where(f => f.Severity == FindingSeverity.Warning).ToList();
        var info = findings.Where(f => f.Severity == FindingSeverity.Info).ToList();

        if (critical.Count > 0)
        {
            sb.AppendLine($"  🔴 CRITICAL ({critical.Count}):");
            foreach (var finding in critical)
            {
                sb.AppendLine($"    [{finding.Category}] {finding.Title}");
                sb.AppendLine($"      {finding.Description}");
                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"      Remedy: {finding.Remediation}");
                }
            }
        }

        if (warnings.Count > 0)
        {
            sb.AppendLine($"  🟡 WARNING ({warnings.Count}):");
            foreach (var finding in warnings)
            {
                sb.AppendLine($"    [{finding.Category}] {finding.Title}");
                sb.AppendLine($"      {finding.Description}");
                if (!string.IsNullOrEmpty(finding.Remediation))
                {
                    sb.AppendLine($"      Remedy: {finding.Remediation}");
                }
            }
        }

        if (info.Count > 0)
        {
            sb.AppendLine($"  ℹ️  INFO ({info.Count}):");
            foreach (var finding in info)
            {
                sb.AppendLine($"    [{finding.Category}] {finding.Title}");
            }
        }
    }

    private static string FormatBoolValue(bool? value) => value switch
    {
        true => "✓ Enabled",
        false => "✗ Disabled",
        null => "? Unknown",
    };
}
