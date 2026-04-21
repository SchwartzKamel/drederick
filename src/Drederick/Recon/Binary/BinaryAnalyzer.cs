using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Binary;

/// <summary>
/// Analyzes binary files (ELF, PE, Mach-O) for metadata, dependencies, and security
/// hardening features (ASLR, NX, PIE, stack canaries, dangerous functions, format strings).
/// </summary>
public sealed class BinaryAnalyzer : IBinaryAnalyzer
{
    public string Name => "binary-analyzer";

    public string Description =>
        "Performs static analysis on binary files to extract metadata, dependencies, and " +
        "security hardening features (ASLR, NX, PIE, stack canaries, format strings, dangerous functions).";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string? _readelfPath;
    private readonly string? _nmPath;
    private readonly string? _objdumpPath;
    private readonly string? _stringsPath;
    private readonly string? _filePath;

    public BinaryAnalyzer(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
        _readelfPath = WhichTool("readelf");
        _nmPath = WhichTool("nm");
        _objdumpPath = WhichTool("objdump");
        _stringsPath = WhichTool("strings");
        _filePath = WhichTool("file");
    }

    public async Task<BinaryAnalysisReport> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
    {
        // Verify the file exists and is readable
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"Binary file not found: {filePath}");
        }

        var startTime = DateTime.UtcNow;
        var report = new BinaryAnalysisReport
        {
            FilePath = filePath,
            Timestamp = startTime.ToString("o"),
            AnalyzerVersion = "1.0.0",
        };

        _audit.Record("binary-analyzer.start", new Dictionary<string, object?>
        {
            ["file_path"] = filePath,
        });

        try
        {
            // Extract metadata
            report.Metadata = await ExtractMetadataAsync(filePath, cancellationToken);

            // Extract dependencies
            if (!string.IsNullOrEmpty(report.Metadata.Platform))
            {
                report.Dependencies = await ExtractDependenciesAsync(filePath, report.Metadata.Platform, cancellationToken);
            }

            // Extract strings
            report.Strings = await ExtractStringsAsync(filePath, cancellationToken);

            // Analyze security hardening
            if (!string.IsNullOrEmpty(report.Metadata.Platform))
            {
                report.Security = await AnalyzeSecurityAsync(filePath, report.Metadata.Platform, report.Metadata.FileType, cancellationToken);
            }

            // Generate findings based on security analysis
            report.Findings.AddRange(GenerateSecurityFindings(report.Security));

            _audit.Record("binary-analyzer.finish", new Dictionary<string, object?>
            {
                ["file_path"] = filePath,
                ["findings_count"] = report.Findings.Count,
                ["duration_ms"] = (int)(DateTime.UtcNow - startTime).TotalMilliseconds,
            });
        }
        catch (Exception ex)
        {
            _audit.Record("binary-analyzer.error", new Dictionary<string, object?>
            {
                ["file_path"] = filePath,
                ["error"] = ex.Message,
            });

            report.Findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.Metadata,
                Title = "Analysis Error",
                Description = $"An error occurred during binary analysis: {ex.Message}",
            });
        }

        return report;
    }

    /// <summary>
    /// Extracts binary metadata using the 'file' command and readelf/objdump.
    /// </summary>
    private async Task<BinaryMetadata> ExtractMetadataAsync(string filePath, CancellationToken ct)
    {
        var metadata = new BinaryMetadata();

        try
        {
            // Get file type, architecture, and platform using 'file'
            var fileOutput = await RunCommandAsync(_filePath ?? "file", $"\"{filePath}\"", ct);
            ParseFileOutput(fileOutput, metadata);

            // Extract sections using readelf or objdump
            if (metadata.Platform == "ELF" && _readelfPath != null)
            {
                var sectionsOutput = await RunCommandAsync(_readelfPath, $"-S \"{filePath}\"", ct);
                metadata.Sections = ParseElfSections(sectionsOutput);

                // Extract entry point from ELF header
                var headerOutput = await RunCommandAsync(_readelfPath, $"-h \"{filePath}\"", ct);
                metadata.EntryPoint = ExtractElfEntryPoint(headerOutput);
            }
            else if (metadata.Platform == "PE" && _objdumpPath != null)
            {
                var headerOutput = await RunCommandAsync(_objdumpPath, $"-h \"{filePath}\"", ct);
                metadata.Sections = ParsePeSections(headerOutput);
            }

            // Calculate SHA256
            metadata.Sha256 = await CalculateSha256Async(filePath, ct);
        }
        catch (Exception)
        {
            // Gracefully handle metadata extraction failures
        }

        return metadata;
    }

    /// <summary>
    /// Extracts dependencies (imported libraries, RPATH, RUNPATH).
    /// </summary>
    private async Task<BinaryDependencies> ExtractDependenciesAsync(string filePath, string platform, CancellationToken ct)
    {
        var deps = new BinaryDependencies();

        try
        {
            if (platform == "ELF" && _readelfPath != null)
            {
                // Extract dynamic section to find library dependencies and RPATH/RUNPATH
                var dynamicOutput = await RunCommandAsync(_readelfPath, $"-d \"{filePath}\"", ct);
                ParseElfDynamic(dynamicOutput, deps);
            }
            else if (platform == "PE" && _objdumpPath != null)
            {
                // Extract PE imports
                var importsOutput = await RunCommandAsync(_objdumpPath, $"-p \"{filePath}\"", ct);
                deps.ImportedLibs = ParsePeImports(importsOutput);
            }
        }
        catch (Exception)
        {
            // Gracefully handle dependency extraction failures
        }

        return deps;
    }

    /// <summary>
    /// Extracts strings and searches for suspicious keywords and crypto indicators.
    /// </summary>
    private async Task<BinaryStrings> ExtractStringsAsync(string filePath, CancellationToken ct)
    {
        var strings = new BinaryStrings();

        try
        {
            if (_stringsPath == null)
                return strings;

            var stringsOutput = await RunCommandAsync(_stringsPath, $"\"{filePath}\"", ct);
            var allStrings = stringsOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            strings.Count = allStrings.Length;

            // Detect suspicious keywords
            var suspiciousKeywords = new[] { "cmd", "powershell", "curl", "/bin/sh", "/bin/bash", "wget", "nc", "ncat" };
            foreach (var keyword in suspiciousKeywords)
            {
                if (allStrings.Any(s => s.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
                {
                    strings.SuspiciousKeywords.Add(keyword);
                }
            }

            // Detect crypto indicators
            var cryptoPatterns = new[] { "AES", "RSA", "SHA", "MD5", "DES", "ECC", "ECDSA" };
            foreach (var pattern in cryptoPatterns)
            {
                if (allStrings.Any(s => s.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    strings.CryptoIndicators.Add(pattern);
                }
            }
        }
        catch (Exception)
        {
            // Gracefully handle string extraction failures
        }

        return strings;
    }

    /// <summary>
    /// Analyzes security hardening features: ASLR, NX, PIE, stack canaries, format strings, dangerous functions.
    /// </summary>
    private async Task<BinarySecurity> AnalyzeSecurityAsync(string filePath, string platform, string fileType, CancellationToken ct)
    {
        var security = new BinarySecurity();

        try
        {
            if (platform == "ELF")
            {
                await AnalyzeElfSecurityAsync(filePath, security, ct);
            }
            else if (platform == "PE")
            {
                await AnalyzePeSecurityAsync(filePath, security, ct);
            }
            else if (platform == "Mach-O")
            {
                await AnalyzeMachOSecurityAsync(filePath, security, ct);
            }

            // Detect dangerous functions (works across platforms via symbols)
            await DetectDangerousFunctionsAsync(filePath, security, ct);

            // Detect format string vulnerabilities
            await DetectFormatStringsAsync(filePath, security, ct);
        }
        catch (Exception)
        {
            // Gracefully handle security analysis failures
        }

        return security;
    }

    /// <summary>
    /// Analyzes ELF-specific security features (ASLR, NX, PIE, stack canary).
    /// </summary>
    private async Task AnalyzeElfSecurityAsync(string filePath, BinarySecurity security, CancellationToken ct)
    {
        if (_readelfPath == null)
            return;

        try
        {
            // Get ELF header to check for ET_DYN (PIE/ASLR-capable)
            var headerOutput = await RunCommandAsync(_readelfPath, $"-h \"{filePath}\"", ct);
            var elfType = ExtractElfType(headerOutput);

            // ET_DYN (type 3) means position-independent and ASLR-capable
            security.IsAslrEnabled = elfType == 3;
            security.IsPieEnabled = elfType == 3;

            // Check for NX bit via program headers
            var programHeadersOutput = await RunCommandAsync(_readelfPath, $"-l \"{filePath}\"", ct);
            security.IsNxEnabled = CheckElfNxBit(programHeadersOutput);

            // Check for stack canary via symbol table
            var symbolsOutput = await RunCommandAsync(_readelfPath, $"--symbols \"{filePath}\"", ct);
            security.HasCanary = CheckStackCanary(symbolsOutput);
            security.HasStackSmashing = security.HasCanary;
        }
        catch (Exception)
        {
            // Tool might not be available; findings will reflect unknown status
        }
    }

    /// <summary>
    /// Analyzes PE-specific security features (ASLR, NX, PIE).
    /// </summary>
    private async Task AnalyzePeSecurityAsync(string filePath, BinarySecurity security, CancellationToken ct)
    {
        if (_objdumpPath == null)
            return;

        try
        {
            // For PE files, we parse the header for DLL characteristics
            var headerOutput = await RunCommandAsync(_objdumpPath, $"-h \"{filePath}\"", ct);

            // PE files are inherently position-independent
            security.IsPieEnabled = true;

            // Check for ASLR and NX flags in header (simplified; real implementation would parse binary)
            security.IsAslrEnabled = headerOutput.Contains("Dynamic", StringComparison.OrdinalIgnoreCase);
            security.IsNxEnabled = headerOutput.Contains("NX", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            // Tool might not be available; findings will reflect unknown status
        }
    }

    /// <summary>
    /// Analyzes Mach-O-specific security features (PIE, code signing).
    /// </summary>
    private async Task AnalyzeMachOSecurityAsync(string filePath, BinarySecurity security, CancellationToken ct)
    {
        try
        {
            // Mach-O files are typically PIE by default on modern systems
            security.IsPieEnabled = true;

            // Check for stack canary via strings or symbol table
            if (_nmPath != null)
            {
                var symbolsOutput = await RunCommandAsync(_nmPath, $"-u \"{filePath}\"", ct);
                security.HasCanary = CheckStackCanary(symbolsOutput);
                security.HasStackSmashing = security.HasCanary;
            }
        }
        catch (Exception)
        {
            // Tool might not be available
        }
    }

    /// <summary>
    /// Detects dangerous functions that could lead to buffer overflows, format strings, etc.
    /// </summary>
    private async Task DetectDangerousFunctionsAsync(string filePath, BinarySecurity security, CancellationToken ct)
    {
        if (_nmPath == null)
            return;

        try
        {
            var symbolsOutput = await RunCommandAsync(_nmPath, $"-u \"{filePath}\"", ct);

            var dangerousFunctions = new[] { "strcpy", "strcat", "gets", "sprintf", "scanf", "printf" };

            foreach (var func in dangerousFunctions)
            {
                if (symbolsOutput.Contains(func, StringComparison.OrdinalIgnoreCase))
                {
                    security.DangerousFunctions.Add(func);
                }
            }
        }
        catch (Exception)
        {
            // Tool might not be available
        }
    }

    /// <summary>
    /// Detects potential format string vulnerabilities by searching for suspicious patterns.
    /// </summary>
    private async Task DetectFormatStringsAsync(string filePath, BinarySecurity security, CancellationToken ct)
    {
        try
        {
            if (_stringsPath == null)
                return;

            var stringsOutput = await RunCommandAsync(_stringsPath, $"\"{filePath}\"", ct);
            var allStrings = stringsOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            // Look for format string patterns: %x, %s, %n, etc.
            var formatStringPattern = new Regex(@"%[xsn]", RegexOptions.IgnoreCase);

            foreach (var str in allStrings)
            {
                if (str.Length > 4 && formatStringPattern.IsMatch(str))
                {
                    // Additional heuristic: skip common benign patterns
                    if (!str.Contains("http", StringComparison.OrdinalIgnoreCase) &&
                        !str.Contains("://", StringComparison.OrdinalIgnoreCase))
                    {
                        security.HasFormatStrings = true;
                        break;
                    }
                }
            }
        }
        catch (Exception)
        {
            // Tool might not be available
        }
    }

    /// <summary>
    /// Generates BinaryFinding objects based on security analysis results.
    /// </summary>
    private List<BinaryFinding> GenerateSecurityFindings(BinarySecurity security)
    {
        var findings = new List<BinaryFinding>();

        if (security.IsAslrEnabled == false)
        {
            findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.Security,
                Title = "ASLR Not Enabled",
                Description = "Binary is not compiled with ASLR support. Address Space Layout Randomization helps prevent exploitation by randomizing memory addresses. Attackers can predict the location of gadgets and functions.",
                Remediation = "Recompile with -fPIE and link with -pie flags (GCC/Clang) or equivalent compiler options.",
            });
        }

        if (security.IsNxEnabled == false)
        {
            findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Critical,
                Category = FindingCategory.Security,
                Title = "NX Bit Not Set",
                Description = "No-eXecute (NX) bit is not enabled. This allows code execution from data segments (stack, heap), making code injection attacks feasible.",
                Remediation = "Recompile with -z noexecstack flag (linker) or equivalent security options.",
            });
        }

        if (security.IsPieEnabled == false)
        {
            findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.Security,
                Title = "PIE Not Enabled",
                Description = "Binary is not position-independent. Fixed memory layout makes it easier to predict function and gadget locations for ROP attacks.",
                Remediation = "Recompile with -fPIE and link with -pie flags.",
            });
        }

        if (security.HasCanary == false)
        {
            findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Warning,
                Category = FindingCategory.Security,
                Title = "Stack Canary Not Detected",
                Description = "No stack canary (stack smashing protection) detected. This makes buffer overflow detection harder at runtime.",
                Remediation = "Recompile with -fstack-protector-strong or -fstack-protector-all flags.",
            });
        }

        if (security.HasFormatStrings == true)
        {
            findings.Add(new BinaryFinding
            {
                Severity = FindingSeverity.Critical,
                Category = FindingCategory.Security,
                Title = "Format String Vulnerability Detected",
                Description = "Suspicious format string patterns (%x, %s, %n) found in the binary. This could indicate format string vulnerabilities that allow reading/writing arbitrary memory.",
                Remediation = "Review code for unsafe format string usage. Use constant format strings and never pass user input as a format string argument.",
            });
        }

        if (security.DangerousFunctions.Count > 0)
        {
            var criticalFunctions = new[] { "strcpy", "gets", "scanf" };
            var isCritical = security.DangerousFunctions.Any(f => criticalFunctions.Contains(f));

            findings.Add(new BinaryFinding
            {
                Severity = isCritical ? FindingSeverity.Critical : FindingSeverity.Warning,
                Category = FindingCategory.Security,
                Title = "Dangerous Functions Detected",
                Description = $"The following unsafe functions were found: {string.Join(", ", security.DangerousFunctions)}. These functions do not perform bounds checking and can lead to buffer overflows.",
                Remediation = "Replace with safer alternatives: strcpy → strncpy/strlcpy, gets → fgets, scanf → fgets + sscanf.",
            });
        }

        return findings;
    }

    /// <summary>
    /// Extracts the ELF type from readelf -h output.
    /// </summary>
    private int ExtractElfType(string headerOutput)
    {
        var typeMatch = Regex.Match(headerOutput, @"Type:\s+(\w+)");
        if (typeMatch.Success)
        {
            return typeMatch.Groups[1].Value switch
            {
                "ET_EXEC" => 2,
                "ET_DYN" => 3,
                "ET_REL" => 1,
                _ => 0,
            };
        }

        return 0;
    }

    /// <summary>
    /// Extracts the entry point from readelf -h output.
    /// </summary>
    private string? ExtractElfEntryPoint(string headerOutput)
    {
        var entryMatch = Regex.Match(headerOutput, @"Entry point address:\s+(0x[a-f0-9]+)", RegexOptions.IgnoreCase);
        return entryMatch.Success ? entryMatch.Groups[1].Value : null;
    }

    /// <summary>
    /// Checks if NX bit is enabled by looking for PT_GNU_STACK with no execute flag.
    /// </summary>
    private bool CheckElfNxBit(string programHeadersOutput)
    {
        // PT_GNU_STACK should have RW flags, not RWE (no execute)
        var gnuStackMatch = Regex.Match(programHeadersOutput, @"GNU_STACK.*\s([RWE]+)\s");
        if (gnuStackMatch.Success)
        {
            var flags = gnuStackMatch.Groups[1].Value;
            return !flags.Contains('E');
        }

        // If PT_GNU_STACK not found, NX is generally not disabled on modern systems
        return !programHeadersOutput.Contains("GNU_STACK");
    }

    /// <summary>
    /// Checks for stack canary (__stack_chk_fail) in symbol table.
    /// </summary>
    private bool CheckStackCanary(string symbolsOutput)
    {
        return symbolsOutput.Contains("__stack_chk_fail", StringComparison.OrdinalIgnoreCase) ||
               symbolsOutput.Contains("__stack_protector", StringComparison.OrdinalIgnoreCase) ||
               symbolsOutput.Contains("stack_chk", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Parses file command output to extract file type, architecture, and platform.
    /// </summary>
    private void ParseFileOutput(string fileOutput, BinaryMetadata metadata)
    {
        if (fileOutput.Contains("ELF", StringComparison.OrdinalIgnoreCase))
        {
            metadata.Platform = "ELF";
            metadata.FileType = "ELF";
        }
        else if (fileOutput.Contains("PE32", StringComparison.OrdinalIgnoreCase) ||
                 fileOutput.Contains("PE32+", StringComparison.OrdinalIgnoreCase))
        {
            metadata.Platform = "PE";
            metadata.FileType = fileOutput.Contains("PE32+") ? "PE32+" : "PE32";
        }
        else if (fileOutput.Contains("Mach-O", StringComparison.OrdinalIgnoreCase))
        {
            metadata.Platform = "Mach-O";
            metadata.FileType = "Mach-O";
        }

        // Extract architecture
        if (fileOutput.Contains("x86-64", StringComparison.OrdinalIgnoreCase) || fileOutput.Contains("x64", StringComparison.OrdinalIgnoreCase))
            metadata.Architecture = "x64";
        else if (fileOutput.Contains("x86", StringComparison.OrdinalIgnoreCase) || fileOutput.Contains("Intel 80386", StringComparison.OrdinalIgnoreCase))
            metadata.Architecture = "x86";
        else if (fileOutput.Contains("ARM aarch64", StringComparison.OrdinalIgnoreCase) || fileOutput.Contains("aarch64", StringComparison.OrdinalIgnoreCase))
            metadata.Architecture = "arm64";
        else if (fileOutput.Contains("ARM", StringComparison.OrdinalIgnoreCase))
            metadata.Architecture = "arm";
    }

    /// <summary>
    /// Parses ELF sections from readelf -S output.
    /// </summary>
    private List<string> ParseElfSections(string sectionsOutput)
    {
        var sections = new List<string>();
        var lines = sectionsOutput.Split('\n');

        foreach (var line in lines)
        {
            var match = Regex.Match(line, @"\[\s*\d+\]\s+(\.\S+)");
            if (match.Success)
            {
                sections.Add(match.Groups[1].Value);
            }
        }

        return sections;
    }

    /// <summary>
    /// Parses PE sections from objdump -h output.
    /// </summary>
    private List<string> ParsePeSections(string headerOutput)
    {
        var sections = new List<string>();
        var lines = headerOutput.Split('\n');

        foreach (var line in lines)
        {
            var match = Regex.Match(line, @"^\s*(\.\S+)");
            if (match.Success && line.Contains("ALLOC"))
            {
                sections.Add(match.Groups[1].Value);
            }
        }

        return sections;
    }

    /// <summary>
    /// Parses ELF dynamic section to extract libraries and RPATH/RUNPATH.
    /// </summary>
    private void ParseElfDynamic(string dynamicOutput, BinaryDependencies deps)
    {
        var lines = dynamicOutput.Split('\n');

        foreach (var line in lines)
        {
            if (line.Contains("NEEDED", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(line, @"NEEDED\s+Shared library:\s+\[(.+)\]");
                if (match.Success)
                {
                    deps.ImportedLibs.Add(match.Groups[1].Value);
                }
            }
            else if (line.Contains("RPATH", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(line, @"RPATH\s+Library rpath:\s+\[(.+)\]");
                if (match.Success)
                {
                    deps.Rpath = match.Groups[1].Value;
                }
            }
            else if (line.Contains("RUNPATH", StringComparison.OrdinalIgnoreCase))
            {
                var match = Regex.Match(line, @"RUNPATH\s+Library runpath:\s+\[(.+)\]");
                if (match.Success)
                {
                    deps.Runpath = match.Groups[1].Value;
                }
            }
        }
    }

    /// <summary>
    /// Parses PE imports from objdump -p output.
    /// </summary>
    private List<string> ParsePeImports(string importsOutput)
    {
        var imports = new List<string>();
        var lines = importsOutput.Split('\n');

        foreach (var line in lines)
        {
            var match = Regex.Match(line, @"DLL Name:\s+(\S+)");
            if (match.Success)
            {
                imports.Add(match.Groups[1].Value);
            }
        }

        return imports;
    }

    /// <summary>
    /// Runs a shell command and returns its output.
    /// </summary>
    private async Task<string> RunCommandAsync(string command, string arguments, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(command)
        {
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi);
        if (proc == null)
            return "";

        var output = await proc.StandardOutput.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);

        return output;
    }

    /// <summary>
    /// Attempts to find a tool in PATH.
    /// </summary>
    private string? WhichTool(string toolName)
    {
        try
        {
            var psi = new ProcessStartInfo("which")
            {
                Arguments = toolName,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return null;

            var output = proc.StandardOutput.ReadToEnd().Trim();
            proc.WaitForExit();

            return string.IsNullOrEmpty(output) ? null : output;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Calculates SHA256 hash of the binary file.
    /// </summary>
    private async Task<string> CalculateSha256Async(string filePath, CancellationToken ct)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using var sha256 = SHA256.Create();

        var hash = await sha256.ComputeHashAsync(stream, ct);
        return Convert.ToHexString(hash);
    }
}
