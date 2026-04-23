using System.Text.Json;
using Drederick.Audit;
using Drederick.Recon.Binary;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Recon.Binary;

/// <summary>
/// Unit tests for <see cref="MagikaDetector"/>. Always uses a fake
/// <see cref="IMagikaProcessRunner"/> — never shells out to a real magika
/// binary (CI machines may not have it installed).
/// </summary>
public class MagikaDetectorTests : IDisposable
{
    private readonly string _scratchDir;
    private readonly AuditLog _audit;
    private readonly string _auditPath;
    private readonly string _sampleFile;

    public MagikaDetectorTests()
    {
        _scratchDir = Path.Combine(AppContext.BaseDirectory, $"magika-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_scratchDir);
        _auditPath = Path.Combine(_scratchDir, "audit.jsonl");
        _audit = new AuditLog(_auditPath);

        _sampleFile = Path.Combine(_scratchDir, "sample.bin");
        File.WriteAllBytes(_sampleFile, new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02 });
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_scratchDir, recursive: true); } catch { }
    }

    private MagikaDetector NewDetector(IMagikaProcessRunner runner)
        => new MagikaDetector(_audit, runner, cwdProvider: () => _scratchDir);

    private sealed class FakeRunner : IMagikaProcessRunner
    {
        public int ExitCode { get; set; } = 0;
        public string StdOut { get; set; } = string.Empty;
        public string StdErr { get; set; } = string.Empty;
        public List<string> Args { get; } = new();

        public Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(string arguments, CancellationToken ct)
        {
            Args.Add(arguments);
            return Task.FromResult((ExitCode, StdOut, StdErr));
        }
    }

    private List<Dictionary<string, JsonElement>> ReadAuditEvents()
    {
        _audit.Dispose();
        var events = new List<Dictionary<string, JsonElement>>();
        if (!File.Exists(_auditPath)) return events;
        foreach (var line in File.ReadAllLines(_auditPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var doc = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(line);
            if (doc is not null) events.Add(doc);
        }
        return events;
    }

    [Fact]
    public async Task DetectAsync_HappyPath_ReturnsParsedVerdict()
    {
        var runner = new FakeRunner
        {
            ExitCode = 0,
            StdOut = """
            {"path":"sample.bin","result":{"status":"ok","value":{"output":{"label":"elf","description":"ELF executable","group":"executable","mime_type":"application/x-executable","extensions":["elf"],"is_text":false},"score":0.987}}}
            """,
        };
        var det = NewDetector(runner);

        var verdict = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.NotNull(verdict);
        Assert.Equal("elf", verdict!.Label);
        Assert.Equal("ELF executable", verdict.Description);
        Assert.Equal("executable", verdict.Group);
        Assert.Equal("application/x-executable", verdict.MimeType);
        Assert.Equal("elf", verdict.Extension);
        Assert.False(verdict.IsText);
        Assert.InRange(verdict.Confidence, 0.98, 1.0);
        Assert.Contains("\"label\":\"elf\"", verdict.RawJson);
        Assert.Contains(_sampleFile, runner.Args.Single());
    }

    [Fact]
    public async Task DetectAsync_MagikaNotFound_ReturnsNullAndAuditsUnavailableOnce()
    {
        var runner = new FakeRunner { ExitCode = -1, StdErr = "not-found" };
        var det = NewDetector(runner);

        var first = await det.DetectAsync(_sampleFile, CancellationToken.None);
        var second = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.Null(first);
        Assert.Null(second);

        var events = ReadAuditEvents();
        var unavailable = events.Where(e => e["event"].GetString() == "magika.detect.unavailable").ToList();
        Assert.Single(unavailable);
        Assert.Equal("not-found", unavailable[0]["reason"].GetString());
    }

    [Fact]
    public async Task DetectAsync_NonZeroExit_ReturnsNullAndAudits()
    {
        var runner = new FakeRunner { ExitCode = 2, StdErr = "bad input" };
        var det = NewDetector(runner);

        var v = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.Null(v);
        var events = ReadAuditEvents();
        Assert.Contains(events, e => e["event"].GetString() == "magika.detect.unavailable"
            && e["reason"].GetString() == "exit-2");
        var finish = events.Single(e => e["event"].GetString() == "magika.detect.finish");
        Assert.Equal("exit-2", finish["status"].GetString());
    }

    [Fact]
    public async Task DetectAsync_GarbageJson_ReturnsNullAndAudits()
    {
        var runner = new FakeRunner { ExitCode = 0, StdOut = "not valid json at all" };
        var det = NewDetector(runner);

        var v = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.Null(v);
        var events = ReadAuditEvents();
        Assert.Contains(events, e => e["event"].GetString() == "magika.detect.unavailable"
            && e["reason"].GetString() == "unparseable");
    }

    [Fact]
    public async Task DetectAsync_JsonMissingLabel_ReturnsNull()
    {
        var runner = new FakeRunner
        {
            ExitCode = 0,
            // Well-formed JSON but no label/ct_label anywhere → unusable.
            StdOut = """{"path":"sample.bin","result":{"status":"ok","value":{"output":{"score":0.5}}}}""",
        };
        var det = NewDetector(runner);

        var v = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.Null(v);
    }

    [Fact]
    public async Task DetectAsync_OlderCtLabelShape_ParsesCorrectly()
    {
        var runner = new FakeRunner
        {
            ExitCode = 0,
            StdOut = """{"path":"sample.bin","output":{"ct_label":"zip","description":"Zip archive","group":"archive","mime_type":"application/zip","extensions":["zip"],"is_text":false},"score":0.91}""",
        };
        var det = NewDetector(runner);

        var v = await det.DetectAsync(_sampleFile, CancellationToken.None);

        Assert.NotNull(v);
        Assert.Equal("zip", v!.Label);
        Assert.Equal("archive", v.Group);
        Assert.InRange(v.Confidence, 0.9, 0.92);
    }

    [Fact]
    public void ValidatePath_RelativePath_Throws()
    {
        Assert.Throws<ArgumentException>(() => MagikaDetector.ValidatePath("sample.bin", _scratchDir));
    }

    [Fact]
    public void ValidatePath_EmptyPath_Throws()
    {
        Assert.Throws<ArgumentException>(() => MagikaDetector.ValidatePath("", _scratchDir));
        Assert.Throws<ArgumentException>(() => MagikaDetector.ValidatePath("   ", _scratchDir));
    }

    [Fact]
    public void ValidatePath_ParentEscape_Throws()
    {
        var bad = Path.Combine(_scratchDir, "..", "etc", "passwd");
        Assert.Throws<ArgumentException>(() => MagikaDetector.ValidatePath(bad, _scratchDir));
    }

    [Fact]
    public void ValidatePath_AbsoluteOutsideCwd_Throws()
    {
        Assert.Throws<ArgumentException>(() => MagikaDetector.ValidatePath("/etc/passwd", _scratchDir));
    }

    [Fact]
    public void ValidatePath_AbsoluteUnderCwd_Succeeds()
    {
        var ok = MagikaDetector.ValidatePath(_sampleFile, _scratchDir);
        Assert.Equal(_sampleFile, ok);
    }

    [Fact]
    public async Task DetectAsync_RecordsStartAndFinishAudit()
    {
        var runner = new FakeRunner
        {
            ExitCode = 0,
            StdOut = """{"path":"sample.bin","output":{"ct_label":"elf","description":"ELF","group":"executable","mime_type":"application/x-executable","extensions":["elf"],"is_text":false},"score":0.99}""",
        };
        var det = NewDetector(runner);
        _ = await det.DetectAsync(_sampleFile, CancellationToken.None);

        var events = ReadAuditEvents();
        var start = events.Single(e => e["event"].GetString() == "magika.detect.start");
        var finish = events.Single(e => e["event"].GetString() == "magika.detect.finish");
        Assert.Equal(_sampleFile, start["file_path"].GetString());
        // Path digest is recorded and stable SHA-256 hex.
        var digest = start["file_path_sha256"].GetString()!;
        Assert.Equal(64, digest.Length);
        Assert.Equal(digest, finish["file_path_sha256"].GetString());
        Assert.Equal("ok", finish["status"].GetString());
        Assert.Equal("elf", finish["label"].GetString());
    }

    [Fact]
    public async Task DetectAsync_NeverRecordsFileContents()
    {
        var runner = new FakeRunner { ExitCode = 0, StdOut = "not json" };
        var det = NewDetector(runner);
        _ = await det.DetectAsync(_sampleFile, CancellationToken.None);

        var raw = _audit.Path;
        _audit.Dispose();
        var text = File.ReadAllText(raw);
        // Sample file bytes were 0x7F 'E' 'L' 'F' 0x02 — these must not leak
        // into the audit log as a SHA-256 of the contents or raw bytes.
        Assert.DoesNotContain("\"file_contents\"", text);
        Assert.DoesNotContain("\"file_contents_sha256\"", text);
    }
}

/// <summary>
/// Integration tests proving <see cref="BinaryAnalyzer"/> handles both the
/// magika-present and magika-absent paths gracefully.
/// </summary>
public class BinaryAnalyzerMagikaIntegrationTests : IDisposable
{
    private readonly string _scratchDir;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _elfLikePath;

    public BinaryAnalyzerMagikaIntegrationTests()
    {
        _scratchDir = Path.Combine(AppContext.BaseDirectory, $"binary-magika-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_scratchDir);
        _scope = ScopeLoader.Parse("10.0.0.0/8", labMode: true, allowBroad: true);
        _audit = new AuditLog(Path.Combine(_scratchDir, "audit.jsonl"));
        _elfLikePath = Path.Combine(_scratchDir, "artifact.bin");
        File.WriteAllBytes(_elfLikePath, new byte[] { 0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01 });
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_scratchDir, recursive: true); } catch { }
    }

    private MagikaDetector NewMagika(IMagikaProcessRunner runner)
        => new MagikaDetector(_audit, runner, cwdProvider: () => _scratchDir);

    private sealed class FakeRunner : IMagikaProcessRunner
    {
        public int ExitCode;
        public string StdOut = string.Empty;
        public string StdErr = string.Empty;
        public Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(string arguments, CancellationToken ct)
            => Task.FromResult((ExitCode, StdOut, StdErr));
    }

    [Fact]
    public async Task AnalyzeAsync_WithMagikaPresent_PopulatesMagikaField()
    {
        var magika = NewMagika(new FakeRunner
        {
            ExitCode = 0,
            StdOut = """{"path":"artifact.bin","output":{"ct_label":"elf","description":"ELF exec","group":"executable","mime_type":"application/x-executable","extensions":["elf"],"is_text":false},"score":0.99}""",
        });
        var analyzer = new BinaryAnalyzer(_scope, _audit, magika);

        var report = await analyzer.AnalyzeAsync(_elfLikePath, CancellationToken.None);

        Assert.NotNull(report);
        Assert.NotNull(report.Magika);
        Assert.Equal("elf", report.Magika!.Label);
        Assert.Equal("executable", report.Magika.Group);
    }

    [Fact]
    public async Task AnalyzeAsync_WithMagikaAbsent_StillProducesReport()
    {
        var magika = NewMagika(new FakeRunner { ExitCode = -1, StdErr = "not-found" });
        var analyzer = new BinaryAnalyzer(_scope, _audit, magika);

        var report = await analyzer.AnalyzeAsync(_elfLikePath, CancellationToken.None);

        Assert.NotNull(report);
        Assert.Null(report.Magika);
        Assert.NotEmpty(report.Timestamp);
    }

    [Fact]
    public async Task AnalyzeAsync_WithMagikaDisabled_StillProducesReport()
    {
        var analyzer = new BinaryAnalyzer(_scope, _audit, magika: null);

        var report = await analyzer.AnalyzeAsync(_elfLikePath, CancellationToken.None);

        Assert.NotNull(report);
        Assert.Null(report.Magika);
    }

    [Fact]
    public async Task AnalyzeAsync_MagikaSaysNotExec_EmitsWarningFinding()
    {
        // File starts with the ELF magic, so `file` (if present) would call
        // it an ELF; magika disagrees and says zip. Whether the finding is
        // added depends on whether `file` is on the CI PATH — if platform
        // detection fails we simply don't have the cross-check context, so
        // this test only asserts that the magika verdict is populated; the
        // finding emission is covered implicitly when `file` is available.
        var magika = NewMagika(new FakeRunner
        {
            ExitCode = 0,
            StdOut = """{"path":"artifact.bin","output":{"ct_label":"zip","description":"ZIP archive","group":"archive","mime_type":"application/zip","extensions":["zip"],"is_text":false},"score":0.95}""",
        });
        var analyzer = new BinaryAnalyzer(_scope, _audit, magika);

        var report = await analyzer.AnalyzeAsync(_elfLikePath, CancellationToken.None);

        Assert.NotNull(report.Magika);
        Assert.Equal("zip", report.Magika!.Label);
        // Mismatch finding is emitted only when platform detection succeeded
        // (depends on `file` being on PATH). When it did, assert the warning.
        if (!string.IsNullOrEmpty(report.Metadata.Platform))
        {
            Assert.Contains(report.Findings, f =>
                f.Title.Contains("Magika", StringComparison.OrdinalIgnoreCase));
        }
    }
}

/// <summary>
/// Tests for the <see cref="MagikaToolCheck"/> doctor check.
/// </summary>
public class MagikaToolCheckTests : IDisposable
{
    private readonly string _scratchDir;
    private readonly AuditLog _audit;

    public MagikaToolCheckTests()
    {
        _scratchDir = Path.Combine(AppContext.BaseDirectory, $"magika-doctor-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_scratchDir);
        _audit = new AuditLog(Path.Combine(_scratchDir, "audit.jsonl"));
    }

    public void Dispose()
    {
        _audit.Dispose();
        try { Directory.Delete(_scratchDir, recursive: true); } catch { }
    }

    private sealed class StubRunner : Drederick.Doctor.IProcessRunner
    {
        public int ExitCode { get; set; }
        public string StdOut { get; set; } = string.Empty;
        public string StdErr { get; set; } = string.Empty;
        public Exception? Throw { get; set; }

        public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
        {
            if (Throw is not null) throw Throw;
            return (ExitCode, StdOut, StdErr);
        }
        public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
            => (0, "", "");
    }

    [Fact]
    public async Task MagikaToolCheck_Present_ReportsPass()
    {
        var runner = new StubRunner { ExitCode = 0, StdOut = "Magika version 0.6.2" };
        var check = new Drederick.Doctor.MagikaToolCheck(_audit, runner);

        var result = await check.RunAsync(install: false, assumeYes: true,
            new StringReader(""), new StringWriter(), CancellationToken.None);

        Assert.Equal("recon.magika.available", result.Id);
        Assert.Equal(Drederick.Doctor.DoctorCheckStatus.Pass, result.Status);
        Assert.Contains("Magika", result.Detail);
    }

    [Fact]
    public async Task MagikaToolCheck_Missing_WarnsNotFails()
    {
        var runner = new StubRunner { Throw = new InvalidOperationException("failed to start magika") };
        var check = new Drederick.Doctor.MagikaToolCheck(_audit, runner);

        var result = await check.RunAsync(install: false, assumeYes: true,
            new StringReader(""), new StringWriter(), CancellationToken.None);

        Assert.Equal(Drederick.Doctor.DoctorCheckStatus.Warn, result.Status);
        Assert.Contains("pipx install magika", result.FixCommand ?? string.Empty);
    }

    [Fact]
    public async Task MagikaToolCheck_NonZero_WarnsWithFixCommand()
    {
        var runner = new StubRunner { ExitCode = 127, StdErr = "command not found" };
        var check = new Drederick.Doctor.MagikaToolCheck(_audit, runner);

        var result = await check.RunAsync(install: false, assumeYes: true,
            new StringReader(""), new StringWriter(), CancellationToken.None);

        Assert.Equal(Drederick.Doctor.DoctorCheckStatus.Warn, result.Status);
        Assert.NotNull(result.FixCommand);
    }

    [Fact]
    public void InstallRecipe_MagikaWithPipx_PrefersPipx()
    {
        var r = Drederick.Doctor.InstallRecipes.Resolve(
            "magika", Drederick.Doctor.PackageManager.Apt, hasPipx: true, hasUv: false);
        Assert.NotNull(r);
        Assert.Equal("pipx install magika", r!.Command);
        Assert.Equal("cargo install magika", r.FallbackCommand);
    }

    [Fact]
    public void InstallRecipe_MagikaWithoutPipx_BootstrapsPipx()
    {
        var r = Drederick.Doctor.InstallRecipes.Resolve(
            "magika", Drederick.Doctor.PackageManager.Apt, hasPipx: false, hasUv: false);
        Assert.NotNull(r);
        Assert.Contains("pipx install magika", r!.Command);
    }
}
