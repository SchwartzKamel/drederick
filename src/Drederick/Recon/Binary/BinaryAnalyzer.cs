using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon.Binary;

/// <summary>
/// Analyzes binary files (ELF, PE, Mach-O) for metadata, dependencies, and
/// security hardening features using native .NET byte-level parsing.
/// No external tools (file, readelf, nm, strings, objdump, ldd) are required.
/// </summary>
public sealed class BinaryAnalyzer : IBinaryAnalyzer
{
    public string Name => "binary-analyzer";

    public string Description =>
        "Performs static analysis on binary files to extract metadata, dependencies, and " +
        "security hardening features (ASLR, NX, PIE, stack canaries, format strings, dangerous functions).";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly MagikaDetector? _magika;

    public BinaryAnalyzer(Scope.Scope scope, AuditLog audit)
        : this(scope, audit, new MagikaDetector(audit))
    {
    }

    public BinaryAnalyzer(Scope.Scope scope, AuditLog audit, MagikaDetector? magika)
    {
        _scope = scope;
        _audit = audit;
        _magika = magika;
    }

    public async Task<BinaryAnalysisReport> AnalyzeAsync(
        string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Binary file not found: {filePath}");

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
            // Magika pre-pass (first step, non-fatal): gives a fast, ML-based
            // verdict that downstream steps can cross-check against our magic detection.
            if (_magika is not null)
            {
                try
                {
                    report.Magika = await _magika.DetectAsync(filePath, cancellationToken);
                }
                catch (ArgumentException)
                {
                    report.Magika = null;
                }
            }

            // Read file bytes once for all native parsers.
            byte[] fileData = await File.ReadAllBytesAsync(filePath, cancellationToken);

            // Extract metadata (format, architecture, sections, entry point, SHA256).
            report.Metadata = ExtractMetadata(filePath, fileData);

            // Extract dependencies (shared libs, RPATH/RUNPATH, PE imports).
            if (!string.IsNullOrEmpty(report.Metadata.Platform))
                report.Dependencies = ExtractDependencies(fileData, report.Metadata.Platform);

            // Extract strings (native byte-scan replacement for strings(1)).
            report.Strings = ExtractStrings(fileData);

            // Analyze security hardening features.
            if (!string.IsNullOrEmpty(report.Metadata.Platform))
                report.Security = AnalyzeSecurity(fileData, report.Metadata.Platform);

            // Generate findings based on security analysis.
            report.Findings.AddRange(GenerateSecurityFindings(report.Security));

            // Magika vs native-parser cross-check: warn when magika thinks the
            // artifact is NOT actually an executable (polyglot, mislabeled, etc.).
            if (report.Magika is not null && !string.IsNullOrEmpty(report.Metadata.Platform))
            {
                var magikaGroup = report.Magika.Group ?? string.Empty;
                var magikaLabel = report.Magika.Label ?? string.Empty;
                var execGroups = new[] { "executable", "code" };
                var execLabels = new[] { "elf", "pe", "pebin", "macho", "coff", "wasm", "dyld" };
                bool looksExec =
                    execGroups.Any(g => magikaGroup.Equals(g, StringComparison.OrdinalIgnoreCase)) ||
                    execLabels.Any(l => magikaLabel.Equals(l, StringComparison.OrdinalIgnoreCase));
                if (!looksExec && report.Magika.Confidence >= 0.5)
                {
                    report.Findings.Add(new BinaryFinding
                    {
                        Severity = FindingSeverity.Warning,
                        Category = FindingCategory.Metadata,
                        Title = "Magika disagrees with binary classification",
                        Description =
                            $"Native parser reports {report.Metadata.Platform} ({report.Metadata.FileType}) " +
                            $"but magika classifies this artifact as '{magikaLabel}' " +
                            $"(group '{magikaGroup}', confidence {report.Magika.Confidence:F2}). " +
                            "This is a strong hint of a disguised, polyglot, or mislabeled artifact — " +
                            "common in CTF reversing challenges and malware droppers.",
                        Remediation = "Inspect the file header bytes manually; consider sandboxed detonation rather than native execution.",
                    });
                }
            }

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

    // ── metadata ──────────────────────────────────────────────────────────

    private static BinaryMetadata ExtractMetadata(string filePath, byte[] data)
    {
        var meta = new BinaryMetadata();

        try
        {
            var format = ElfParser.DetectFormat(data);
            meta.Sha256 = Convert.ToHexString(SHA256.HashData(data));

            switch (format)
            {
                case BinaryFormat.Elf32:
                case BinaryFormat.Elf64:
                    meta.Platform = "ELF";
                    meta.FileType = format == BinaryFormat.Elf64 ? "ELF64" : "ELF32";
                    PopulateElfMetadata(data, meta);
                    break;

                case BinaryFormat.Pe32:
                case BinaryFormat.Pe64:
                    meta.Platform = "PE";
                    meta.FileType = format == BinaryFormat.Pe64 ? "PE32+" : "PE32";
                    meta.Architecture = PeParser.DetectArchitecture(data);
                    meta.EntryPoint = $"0x{PeParser.GetEntryPoint(data):x}";
                    meta.Sections = PeParser.GetSectionNames(data).ToList();
                    break;

                case BinaryFormat.MachO:
                    meta.Platform = "Mach-O";
                    meta.FileType = "Mach-O";
                    PopulateMachOMetadata(data, meta);
                    break;

                case BinaryFormat.Script:
                    meta.Platform = "Script";
                    meta.FileType = "Script";
                    break;

                case BinaryFormat.Zip:
                    meta.Platform = "Archive";
                    meta.FileType = "ZIP";
                    break;
            }
        }
        catch (Exception)
        {
            // Gracefully handle metadata extraction failures.
        }

        return meta;
    }

    private static void PopulateElfMetadata(byte[] data, BinaryMetadata meta)
    {
        var header = ElfParser.ParseHeader(data);
        if (header is null)
            return;

        meta.Architecture = ElfParser.MachineToArchitecture(header.Machine);
        meta.EntryPoint = $"0x{header.EntryPoint:x}";
        meta.Sections = ElfParser.GetSectionNames(data, header)
            .Where(n => n.StartsWith('.'))
            .ToList();
    }

    private static void PopulateMachOMetadata(byte[] data, BinaryMetadata meta)
    {
        if (data.Length < 12)
            return;

        // Determine endianness from magic.
        bool isLE = data[0] == 0xCE || data[0] == 0xCF;
        bool is64 = data[0] == 0xCF || data[3] == 0xCF;

        uint cputype = isLE
            ? BitConverter.ToUInt32(data, 4)
            : (uint)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);

        meta.Architecture = (cputype & 0x00FFFFFF) switch
        {
            7 => is64 ? "x64" : "x86",    // CPU_TYPE_X86(_64)
            12 => is64 ? "arm64" : "arm",  // CPU_TYPE_ARM(_64)
            18 => "powerpc",               // CPU_TYPE_POWERPC
            _ => "",
        };
    }

    // ── dependencies ──────────────────────────────────────────────────────

    private static BinaryDependencies ExtractDependencies(byte[] data, string platform)
    {
        var deps = new BinaryDependencies();

        try
        {
            if (platform == "ELF")
            {
                var header = ElfParser.ParseHeader(data);
                if (header is not null)
                {
                    var (needed, rpath, runpath) = ElfParser.ExtractDynamicEntries(data, header);
                    deps.ImportedLibs = needed.ToList();
                    deps.Rpath = rpath;
                    deps.Runpath = runpath;
                }
            }
            else if (platform == "PE")
            {
                deps.ImportedLibs = PeParser.ParseImportedDlls(data).ToList();
            }
        }
        catch (Exception)
        {
            // Gracefully handle dependency extraction failures.
        }

        return deps;
    }

    // ── strings ───────────────────────────────────────────────────────────

    private static BinaryStrings ExtractStrings(byte[] data)
    {
        var result = new BinaryStrings();

        try
        {
            var allStrings = ElfParser.ExtractStrings(data, minLength: 4);
            result.Count = allStrings.Count;

            var suspiciousKeywords = new[] { "cmd", "powershell", "curl", "/bin/sh", "/bin/bash", "wget", "nc", "ncat" };
            foreach (var keyword in suspiciousKeywords)
            {
                if (allStrings.Any(s => s.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
                    result.SuspiciousKeywords.Add(keyword);
            }

            var cryptoPatterns = new[] { "AES", "RSA", "SHA", "MD5", "DES", "ECC", "ECDSA" };
            foreach (var pattern in cryptoPatterns)
            {
                if (allStrings.Any(s => s.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                    result.CryptoIndicators.Add(pattern);
            }
        }
        catch (Exception)
        {
            // Gracefully handle string extraction failures.
        }

        return result;
    }

    // ── security analysis ─────────────────────────────────────────────────

    private static BinarySecurity AnalyzeSecurity(byte[] data, string platform)
    {
        var security = new BinarySecurity();

        try
        {
            switch (platform)
            {
                case "ELF":
                    AnalyzeElfSecurity(data, security);
                    break;
                case "PE":
                    AnalyzePeSecurity(data, security);
                    break;
                case "Mach-O":
                    AnalyzeMachOSecurity(data, security);
                    break;
            }

            // Dangerous function detection (ELF symbol scan or string scan for PE/Mach-O).
            DetectDangerousFunctions(data, platform, security);

            // Format string detection via native string extraction.
            DetectFormatStrings(data, security);
        }
        catch (Exception)
        {
            // Gracefully handle security analysis failures.
        }

        return security;
    }

    private static void AnalyzeElfSecurity(byte[] data, BinarySecurity security)
    {
        var header = ElfParser.ParseHeader(data);
        if (header is null)
            return;

        // ET_DYN (type 3) = position-independent → PIE / ASLR-capable.
        security.IsPieEnabled = header.Type == 3;
        security.IsAslrEnabled = header.Type == 3;

        // NX bit: check PT_GNU_STACK program header.
        var phdrs = ElfParser.ParseProgramHeaders(data, header);
        var gnuStack = phdrs.FirstOrDefault(p => p.Type == ElfParser.PT_GNU_STACK);
        if (gnuStack is not null)
        {
            // NX is enabled when the stack is NOT executable (PF_X not set).
            security.IsNxEnabled = (gnuStack.Flags & ElfParser.PF_X) == 0;
        }
        else
        {
            // No PT_GNU_STACK entry — modern kernels assume NX unless overridden.
            security.IsNxEnabled = true;
        }

        // Stack canary: look for __stack_chk_fail in the dynamic symbol table.
        var symbols = ElfParser.ExtractSymbolNames(data, header);
        bool hasCanary = symbols.Any(s =>
            s.Contains("__stack_chk_fail", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("__stack_protector", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("stack_chk", StringComparison.OrdinalIgnoreCase));
        security.HasCanary = hasCanary;
        security.HasStackSmashing = hasCanary;
    }

    private static void AnalyzePeSecurity(byte[] data, BinarySecurity security)
    {
        // PE files are position-independent by design.
        security.IsPieEnabled = true;
        security.IsAslrEnabled = PeParser.HasASLR(data);
        security.IsNxEnabled = PeParser.HasNXBit(data);
    }

    private static void AnalyzeMachOSecurity(byte[] data, BinarySecurity security)
    {
        // Modern macOS binaries default to PIE.
        security.IsPieEnabled = true;

        // Check MH_PIE flag (0x200000) in the Mach-O header flags field.
        if (data.Length >= 28)
        {
            bool isLE = data[0] == 0xCE || data[0] == 0xCF;
            uint flags = isLE
                ? BitConverter.ToUInt32(data, 24)
                : (uint)((data[24] << 24) | (data[25] << 16) | (data[26] << 8) | data[27]);
            security.IsPieEnabled = (flags & 0x200000) != 0;
        }

        // Canary: scan strings for __stack_chk_fail (sufficient for symbol detection).
        var strings = ElfParser.ExtractStrings(data, minLength: 4);
        bool hasCanary = strings.Any(s =>
            s.Contains("__stack_chk_fail", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("stack_chk", StringComparison.OrdinalIgnoreCase));
        security.HasCanary = hasCanary;
        security.HasStackSmashing = hasCanary;
    }

    private static void DetectDangerousFunctions(byte[] data, string platform, BinarySecurity security)
    {
        var dangerousFunctions = new[] { "strcpy", "strcat", "gets", "sprintf", "scanf", "printf" };

        IEnumerable<string> symbolSource;

        if (platform == "ELF")
        {
            var header = ElfParser.ParseHeader(data);
            symbolSource = header is not null
                ? ElfParser.ExtractSymbolNames(data, header)
                : ElfParser.ExtractStrings(data, minLength: 4);
        }
        else
        {
            // For PE and Mach-O, use extracted strings as a proxy for symbol names.
            symbolSource = ElfParser.ExtractStrings(data, minLength: 4);
        }

        foreach (var func in dangerousFunctions)
        {
            if (symbolSource.Any(s => s.Contains(func, StringComparison.OrdinalIgnoreCase)))
                security.DangerousFunctions.Add(func);
        }
    }

    private static void DetectFormatStrings(byte[] data, BinarySecurity security)
    {
        var strings = ElfParser.ExtractStrings(data, minLength: 4);
        var formatStringPattern = new Regex(@"%[xsn]", RegexOptions.IgnoreCase);

        foreach (var str in strings)
        {
            if (str.Length > 4 && formatStringPattern.IsMatch(str))
            {
                if (!str.Contains("http", StringComparison.OrdinalIgnoreCase) &&
                    !str.Contains("://", StringComparison.OrdinalIgnoreCase))
                {
                    security.HasFormatStrings = true;
                    break;
                }
            }
        }
    }

    // ── findings generation ───────────────────────────────────────────────

    private static List<BinaryFinding> GenerateSecurityFindings(BinarySecurity security)
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
            bool isCritical = security.DangerousFunctions.Any(f => criticalFunctions.Contains(f));

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
}
