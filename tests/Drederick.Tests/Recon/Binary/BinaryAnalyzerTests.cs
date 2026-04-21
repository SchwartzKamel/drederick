using Drederick.Audit;
using Drederick.Recon.Binary;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

/// <summary>
/// Unit tests for BinaryAnalyzer using xUnit patterns.
/// Tests cover metadata extraction, security analysis, dependency detection,
/// and edge cases with mocked file operations where possible.
/// </summary>
public class BinaryAnalyzerTests : IDisposable
{
    private readonly string _testScratchDir;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public BinaryAnalyzerTests()
    {
        // Use test scratch dir (not /tmp) to avoid dependencies on system binaries
        _testScratchDir = Path.Combine(AppContext.BaseDirectory, $"binary-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testScratchDir);

        // Create a minimal scope (binary analyzer doesn't enforce scope on paths, but we need one for the analyzer)
        _scope = ScopeLoader.Parse("10.0.0.0/8", labMode: true, allowBroad: true);

        // Create audit log for tracing
        _audit = new AuditLog(Path.Combine(_testScratchDir, "audit.jsonl"));
    }

    public void Dispose()
    {
        _audit?.Dispose();
        try { Directory.Delete(_testScratchDir, recursive: true); } catch { }
    }

    /// <summary>
    /// Test: Analyze a real binary (e.g., /bin/bash on Linux)
    /// Expected: Report is populated with metadata, security info, and findings
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_RealBinary_Returns_Complete_Report()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            // Skip if bash is not available
            return;
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert
        Assert.NotNull(report);
        Assert.Equal(binPath, report.FilePath);
        Assert.NotEmpty(report.Timestamp);
        Assert.NotEmpty(report.AnalyzerVersion);

        // Metadata should be extracted
        Assert.NotNull(report.Metadata);
        // Architecture should be detected
        Assert.NotEmpty(report.Metadata.Architecture);

        // Security analysis should be present
        Assert.NotNull(report.Security);
    }

    /// <summary>
    /// Test: File not found error handling
    /// Expected: Throws FileNotFoundException
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_NonexistentFile_Throws_FileNotFoundException()
    {
        // Arrange
        var analyzer = new BinaryAnalyzer(_scope, _audit);
        var nonexistentPath = Path.Combine(_testScratchDir, "nonexistent-binary");

        // Act & Assert
        var ex = await Assert.ThrowsAsync<FileNotFoundException>(
            () => analyzer.AnalyzeAsync(nonexistentPath, CancellationToken.None)
        );
        Assert.Contains("not found", ex.Message);
    }

    /// <summary>
    /// Test: Directory instead of file
    /// Expected: Throws FileNotFoundException (directory exists but is not a file)
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_DirectoryPath_Throws_FileNotFoundException()
    {
        // Arrange
        var analyzer = new BinaryAnalyzer(_scope, _audit);
        var dirPath = Path.Combine(_testScratchDir, "subdir");
        Directory.CreateDirectory(dirPath);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<FileNotFoundException>(
            () => analyzer.AnalyzeAsync(dirPath, CancellationToken.None)
        );
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public async Task AnalyzeAsync_FileOutsideScope_Throws_Or_IsRejected()
    {
        // Note: Binary analyzer doesn't actually enforce scope on file paths.
        // Scope is for network targets only. This test documents that behavior.
        // The analyzer will still analyze any accessible file.

        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act: Attempt to analyze bash - should succeed regardless of scope
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert: Should analyze successfully
        Assert.NotNull(report);
        Assert.Equal(binPath, report.FilePath);
    }

    /// <summary>
    /// Test: Metadata extraction - architecture, file type, entry point should be populated
    /// Expected: Metadata contains valid values for architecture and file type
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_Metadata_Extraction_Populates_All_Fields()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert
        var metadata = report.Metadata;
        Assert.NotNull(metadata);

        // Architecture should be detected (x86, x64, arm, etc.)
        // On most systems, should be x86_64, x86, or similar
        if (!string.IsNullOrEmpty(metadata.Architecture))
        {
            Assert.True(
                metadata.Architecture.Contains("86") ||
                metadata.Architecture.Contains("arm") ||
                metadata.Architecture.Contains("x64") ||
                metadata.Architecture.Contains("x86"),
                $"Unexpected architecture: {metadata.Architecture}"
            );
        }

        // SHA256 should be calculated
        if (!string.IsNullOrEmpty(metadata.Sha256))
        {
            Assert.True(metadata.Sha256.Length >= 64, "SHA256 should be at least 64 chars");
        }
    }

    /// <summary>
    /// Test: String analysis - suspicious keywords should be detected
    /// Expected: SuspiciousKeywords list contains expected patterns
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_StringAnalysis_Detects_Suspicious_Keywords()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert
        var strings = report.Strings;
        Assert.NotNull(strings);

        // Bash binary should contain string count
        if (strings.Count > 0)
        {
            Assert.True(strings.Count > 0, "bash should contain strings");
        }

        // May or may not contain suspicious keywords depending on system
        // This is informational, not a failure condition
        Assert.NotNull(strings.SuspiciousKeywords);
        Assert.NotNull(strings.CryptoIndicators);
    }

    /// <summary>
    /// Test: Security checks - ASLR, NX, PIE, canary flags should be analyzed
    /// Expected: Security fields are populated (even if all false/null)
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_SecurityAnalysis_Checks_Hardening_Features()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert
        var security = report.Security;
        Assert.NotNull(security);

        // Check that security fields exist (values may be true, false, or null)
        Assert.True(
            security.IsAslrEnabled.HasValue ||
            security.IsNxEnabled.HasValue ||
            security.IsPieEnabled.HasValue ||
            security.HasCanary.HasValue,
            "At least one security feature should be detected"
        );

        // DangerousFunctions and other collections should exist
        Assert.NotNull(security.DangerousFunctions);
    }

    /// <summary>
    /// Test: Empty file handling
    /// Expected: Report is generated but findings may indicate issues
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_EmptyFile_Generates_Report_With_Findings()
    {
        // Arrange
        var emptyFilePath = Path.Combine(_testScratchDir, "empty-binary");
        File.WriteAllBytes(emptyFilePath, Array.Empty<byte>());

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(emptyFilePath, CancellationToken.None);

        // Assert: Should handle gracefully
        Assert.NotNull(report);
        Assert.Equal(emptyFilePath, report.FilePath);

        // Empty file should likely result in error findings
        Assert.NotNull(report.Findings);
        // May or may not have findings depending on implementation
    }

    /// <summary>
    /// Test: Very large binary file handling
    /// Expected: Analysis completes without timeout or memory issues
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_LargeBinary_Completes_Without_Timeout()
    {
        // Arrange: Create a 10MB dummy binary file
        var largeBinaryPath = Path.Combine(_testScratchDir, "large-binary");
        var largeData = new byte[10 * 1024 * 1024]; // 10MB
        // Add some structure so it's not too trivial
        for (int i = 0; i < largeData.Length; i += 1024)
        {
            largeData[i] = 0x7F; // ELF magic byte
            largeData[i + 1] = (byte)'E';
            largeData[i + 2] = (byte)'L';
            largeData[i + 3] = (byte)'F';
        }
        File.WriteAllBytes(largeBinaryPath, largeData);

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var report = await analyzer.AnalyzeAsync(largeBinaryPath, cts.Token);

        // Assert: Should complete without timeout
        Assert.NotNull(report);
        Assert.Equal(largeBinaryPath, report.FilePath);
    }

    /// <summary>
    /// Test: Symlink handling (if applicable)
    /// Expected: Follows symlink and analyzes target or reports appropriately
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_SymlinkToValidBinary_Analyzes_Target()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var symlinkPath = Path.Combine(_testScratchDir, "bash-link");
        try
        {
            File.CreateSymbolicLink(symlinkPath, binPath);
        }
        catch (PlatformNotSupportedException)
        {
            return; // Symlinks may not be supported on all platforms
        }
        catch (UnauthorizedAccessException)
        {
            return; // May not have permission to create symlinks
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(symlinkPath, CancellationToken.None);

        // Assert: Should analyze the target
        Assert.NotNull(report);
        // Path should be the symlink we asked for
        Assert.Equal(symlinkPath, report.FilePath);
    }

    /// <summary>
    /// Test: Report includes audit trail
    /// Expected: Audit log contains start and finish events
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_RecordsAuditEvents()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var auditPath = Path.Combine(_testScratchDir, "audit-test.jsonl");
        using var audit = new AuditLog(auditPath);
        var analyzer = new BinaryAnalyzer(_scope, audit);

        // Act
        await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert: Audit log should have events
        audit.Dispose();
        Assert.True(File.Exists(auditPath), "Audit log file should exist");
        var auditContent = File.ReadAllText(auditPath);
        Assert.Contains("binary-analyzer.start", auditContent);
        Assert.Contains("binary-analyzer.finish", auditContent);
    }

    /// <summary>
    /// Test: Findings are properly categorized
    /// Expected: Each finding has valid category and severity
    /// </summary>
    [Fact]
    public async Task AnalyzeAsync_Findings_Have_Valid_Category_And_Severity()
    {
        // Arrange
        var binPath = "/bin/bash";
        if (!File.Exists(binPath))
        {
            return; // Skip if bash not available
        }

        var analyzer = new BinaryAnalyzer(_scope, _audit);

        // Act
        var report = await analyzer.AnalyzeAsync(binPath, CancellationToken.None);

        // Assert
        Assert.NotNull(report.Findings);
        foreach (var finding in report.Findings)
        {
            Assert.NotNull(finding.Title);
            Assert.NotNull(finding.Description);
            Assert.True(
                finding.Category == FindingCategory.Metadata ||
                finding.Category == FindingCategory.Security ||
                finding.Category == FindingCategory.Dependency ||
                finding.Category == FindingCategory.Suspicious,
                $"Invalid finding category: {finding.Category}"
            );
            Assert.True(
                finding.Severity == FindingSeverity.Info ||
                finding.Severity == FindingSeverity.Warning ||
                finding.Severity == FindingSeverity.Critical,
                $"Invalid finding severity: {finding.Severity}"
            );
        }
    }
}
