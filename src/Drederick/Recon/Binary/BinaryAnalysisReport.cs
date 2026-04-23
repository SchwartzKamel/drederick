using System.Text.Json.Serialization;

namespace Drederick.Recon.Binary;

/// <summary>
/// Complete report of binary analysis, including metadata, dependencies,
/// security posture, and discovered findings.
/// </summary>
public sealed class BinaryAnalysisReport
{
    /// <summary>
    /// Relative path to the analyzed binary file (relative to scope root).
    /// </summary>
    [JsonPropertyName("file_path")]
    public string FilePath { get; set; } = "";

    /// <summary>
    /// ISO 8601 timestamp when the analysis began.
    /// </summary>
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = "";

    /// <summary>
    /// Version of the analyzer that produced this report.
    /// </summary>
    [JsonPropertyName("analyzer_version")]
    public string AnalyzerVersion { get; set; } = "";

    /// <summary>
    /// Binary metadata extracted from the file.
    /// </summary>
    [JsonPropertyName("metadata")]
    public BinaryMetadata Metadata { get; set; } = new();

    /// <summary>
    /// Information about imported libraries and runtime paths.
    /// </summary>
    [JsonPropertyName("dependencies")]
    public BinaryDependencies Dependencies { get; set; } = new();

    /// <summary>
    /// Analysis of embedded strings and suspicious keywords.
    /// </summary>
    [JsonPropertyName("strings")]
    public BinaryStrings Strings { get; set; } = new();

    /// <summary>
    /// Security features and protections present in the binary.
    /// </summary>
    [JsonPropertyName("security")]
    public BinarySecurity Security { get; set; } = new();

    /// <summary>
    /// List of all discovered findings during analysis.
    /// </summary>
    [JsonPropertyName("findings")]
    public List<BinaryFinding> Findings { get; set; } = new();

    /// <summary>
    /// Optional magika pre-pass verdict. Null when magika is not installed or
    /// its output could not be parsed. See <see cref="MagikaDetector"/>.
    /// </summary>
    [JsonPropertyName("magika")]
    public MagikaVerdict? Magika { get; set; }
}

/// <summary>
/// Binary file metadata: type, architecture, platform, sections, entry point, and checksums.
/// </summary>
public sealed class BinaryMetadata
{
    /// <summary>
    /// File type (e.g., ELF, PE, Mach-O, etc.)
    /// </summary>
    [JsonPropertyName("file_type")]
    public string FileType { get; set; } = "";

    /// <summary>
    /// Architecture: x86, x64, arm, arm64, etc.
    /// </summary>
    [JsonPropertyName("architecture")]
    public string Architecture { get; set; } = "";

    /// <summary>
    /// Platform: ELF (Linux), PE (Windows), Mach-O (macOS), etc.
    /// </summary>
    [JsonPropertyName("platform")]
    public string Platform { get; set; } = "";

    /// <summary>
    /// List of sections in the binary (e.g., .text, .data, .rodata, etc.)
    /// </summary>
    [JsonPropertyName("sections")]
    public List<string> Sections { get; set; } = new();

    /// <summary>
    /// Entry point address (as hex string).
    /// </summary>
    [JsonPropertyName("entry_point")]
    public string? EntryPoint { get; set; }

    /// <summary>
    /// SHA256 checksum of the binary file.
    /// </summary>
    [JsonPropertyName("sha256")]
    public string? Sha256 { get; set; }
}

/// <summary>
/// Dependencies information: imported libraries, runtime paths (RPATH/RUNPATH).
/// </summary>
public sealed class BinaryDependencies
{
    /// <summary>
    /// List of imported/dependent libraries.
    /// </summary>
    [JsonPropertyName("imported_libs")]
    public List<string> ImportedLibs { get; set; } = new();

    /// <summary>
    /// RPATH value if present (affects library search order at runtime).
    /// </summary>
    [JsonPropertyName("rpath")]
    public string? Rpath { get; set; }

    /// <summary>
    /// RUNPATH value if present (overrides RPATH on modern systems).
    /// </summary>
    [JsonPropertyName("runpath")]
    public string? Runpath { get; set; }
}

/// <summary>
/// Analysis of embedded strings and suspicious keyword detection.
/// </summary>
public sealed class BinaryStrings
{
    /// <summary>
    /// Total count of strings found in the binary.
    /// </summary>
    [JsonPropertyName("count")]
    public int Count { get; set; }

    /// <summary>
    /// Suspicious keywords detected (e.g., "cmd", "powershell", "curl").
    /// </summary>
    [JsonPropertyName("suspicious_keywords")]
    public List<string> SuspiciousKeywords { get; set; } = new();

    /// <summary>
    /// Common crypto/encoding indicators detected.
    /// </summary>
    [JsonPropertyName("crypto_indicators")]
    public List<string> CryptoIndicators { get; set; } = new();
}

/// <summary>
/// Security features and protections present in or absent from the binary.
/// </summary>
public sealed class BinarySecurity
{
    /// <summary>
    /// Address Space Layout Randomization enabled.
    /// </summary>
    [JsonPropertyName("is_aslr_enabled")]
    public bool? IsAslrEnabled { get; set; }

    /// <summary>
    /// No-eXecute (NX) bit set, preventing code execution from data segments.
    /// </summary>
    [JsonPropertyName("is_nx_enabled")]
    public bool? IsNxEnabled { get; set; }

    /// <summary>
    /// Position Independent Executable (PIE) enabled.
    /// </summary>
    [JsonPropertyName("is_pie_enabled")]
    public bool? IsPieEnabled { get; set; }

    /// <summary>
    /// Stack canary present for buffer overflow detection.
    /// </summary>
    [JsonPropertyName("has_canary")]
    public bool? HasCanary { get; set; }

    /// <summary>
    /// Stack smashing protector enabled.
    /// </summary>
    [JsonPropertyName("has_stack_smashing")]
    public bool? HasStackSmashing { get; set; }

    /// <summary>
    /// Format string vulnerabilities detected.
    /// </summary>
    [JsonPropertyName("has_format_strings")]
    public bool? HasFormatStrings { get; set; }

    /// <summary>
    /// Dangerous functions detected (e.g., strcpy, sprintf without bounds checking).
    /// </summary>
    [JsonPropertyName("dangerous_functions")]
    public List<string> DangerousFunctions { get; set; } = new();
}
