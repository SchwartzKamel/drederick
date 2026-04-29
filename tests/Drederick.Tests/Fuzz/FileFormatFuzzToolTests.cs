using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public sealed class FileFormatFuzzToolTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _seedFile;
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public FileFormatFuzzToolTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"drederick-test-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);

        // Create a seed file
        _seedFile = Path.Combine(_tempDir, "seed.txt");
        File.WriteAllText(_seedFile, "This is a test seed file.\n");

        // Scope: allow localhost
        _scope = ScopeLoader.Parse("127.0.0.1/32");

        // Audit
        var auditFile = Path.Combine(_tempDir, "audit.jsonl");
        _audit = new AuditLog(auditFile);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [Fact]
    public async Task Throws_When_SeedFile_PathTraversal()
    {
        var tool = new FileFormatFuzzTool(_scope, _audit);
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await tool.MutateOnlyAsync("../etc/passwd"));
    }

    [Fact]
    public async Task Throws_When_SeedFile_Missing()
    {
        var tool = new FileFormatFuzzTool(_scope, _audit);
        await Assert.ThrowsAsync<FileNotFoundException>(
            async () => await tool.MutateOnlyAsync("/nonexistent/file.txt"));
    }

    [Fact]
    public async Task Throws_When_SeedFile_TooLarge()
    {
        // Create a file larger than 10MB
        var largeFile = Path.Combine(_tempDir, "large.bin");
        using (var fs = File.Create(largeFile))
        {
            fs.SetLength(11 * 1024 * 1024); // 11 MB
        }

        var tool = new FileFormatFuzzTool(_scope, _audit);
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await tool.MutateOnlyAsync(largeFile));
    }

    [Fact]
    public async Task Throws_When_OutputDir_PathTraversal()
    {
        var tool = new FileFormatFuzzTool(_scope, _audit);
        var opts = new FileFormatFuzzOptions { OutputDir = "../etc" };
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await tool.MutateOnlyAsync(_seedFile, opts));
    }

    [Fact]
    public async Task Throws_When_UploadUrl_OutOfScope()
    {
        var tool = new FileFormatFuzzTool(_scope, _audit);
        await Assert.ThrowsAsync<ScopeException>(
            async () => await tool.MutateAndUploadAsync(_seedFile, "http://8.8.8.8/upload"));
    }

    [Fact]
    public async Task Throws_When_UploadUrl_Invalid()
    {
        var tool = new FileFormatFuzzTool(_scope, _audit);
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await tool.MutateAndUploadAsync(_seedFile, "not-a-url"));
    }

    [Fact]
    public async Task Caps_MutationCount_At_Max()
    {
        // Create a fake runner that writes N files
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            // Parse mutation count from args
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var nIndex = Array.IndexOf(argList, "-n");
            var count = int.Parse(argList[nIndex + 1]);

            // Verify count was capped
            Assert.True(count <= 10000, $"Mutation count {count} exceeds max");

            // Write mutation files
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            for (int i = 0; i < count; i++)
            {
                var mutationFile = Path.Combine(outputDirFromPattern, $"mutation-{i}");
                File.WriteAllText(mutationFile, $"mutation {i}");
            }

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, runner: fakeRunner);

        // Request more than max
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 50000,
            MaxMutationCount = 10000,
            OutputDir = outputDir,
        };

        var result = await tool.MutateOnlyAsync(_seedFile, opts);

        // Should be capped at 10000
        Assert.Equal(10000, result.MutationsGenerated);
    }

    [Fact]
    public async Task Returns_Empty_Result_When_Radamsa_Missing()
    {
        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            throw new InvalidOperationException("failed to start radamsa");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, runner: fakeRunner);
        var result = await tool.MutateOnlyAsync(_seedFile);

        Assert.Equal(0, result.MutationsGenerated);
        Assert.Equal("radamsa not found", result.Error);
    }

    [Fact]
    public async Task Generates_Mutations_When_Radamsa_Succeeds()
    {
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            // Parse arguments to get output pattern
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var nIndex = Array.IndexOf(argList, "-n");
            var count = int.Parse(argList[nIndex + 1]);
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            // Write mutation files
            for (int i = 0; i < count; i++)
            {
                var mutationFile = Path.Combine(outputDirFromPattern, $"mutation-{i}");
                File.WriteAllText(mutationFile, $"mutated content {i}");
            }

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, runner: fakeRunner);
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 10,
            OutputDir = outputDir,
        };

        var result = await tool.MutateOnlyAsync(_seedFile, opts);

        Assert.Equal(10, result.MutationsGenerated);
        Assert.Equal(0, result.Anomalies);
        Assert.NotEmpty(result.SampleCrashInputDigests);
        Assert.True(result.SampleCrashInputDigests.Count <= 5);
    }

    [Fact]
    public async Task Detects_5xx_As_Anomaly_In_Upload_Mode()
    {
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var uploadCount = 0;
        var fakeHandler = new FakeFileFormatFuzzHttpHandler((request, ct) =>
        {
            uploadCount++;
            // Return 500 for every other upload
            var statusCode = uploadCount % 2 == 0 ? HttpStatusCode.InternalServerError : HttpStatusCode.OK;
            return Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent("response body"),
            });
        });

        var httpClient = new HttpClient(fakeHandler);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var nIndex = Array.IndexOf(argList, "-n");
            var count = int.Parse(argList[nIndex + 1]);
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            for (int i = 0; i < count; i++)
            {
                var mutationFile = Path.Combine(outputDirFromPattern, $"mutation-{i}");
                File.WriteAllText(mutationFile, $"mutation {i}");
            }

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, httpClient: httpClient, runner: fakeRunner);
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 10,
            OutputDir = outputDir,
        };

        var result = await tool.MutateAndUploadAsync(_seedFile, "http://127.0.0.1/upload", opts);

        Assert.Equal(10, result.MutationsGenerated);
        Assert.Equal(5, result.Anomalies); // Half of uploads return 500
    }

    [Fact]
    public async Task Detects_Stack_Trace_Marker_In_Body_As_Anomaly()
    {
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var uploadCount = 0;
        var fakeHandler = new FakeFileFormatFuzzHttpHandler((request, ct) =>
        {
            uploadCount++;
            var body = uploadCount == 3 ? "Error: Exception: Something went wrong" : "OK";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
        });

        var httpClient = new HttpClient(fakeHandler);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var nIndex = Array.IndexOf(argList, "-n");
            var count = int.Parse(argList[nIndex + 1]);
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            for (int i = 0; i < count; i++)
            {
                var mutationFile = Path.Combine(outputDirFromPattern, $"mutation-{i}");
                File.WriteAllText(mutationFile, $"mutation {i}");
            }

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, httpClient: httpClient, runner: fakeRunner);
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 5,
            OutputDir = outputDir,
        };

        var result = await tool.MutateAndUploadAsync(_seedFile, "http://127.0.0.1/upload", opts);

        Assert.Equal(5, result.MutationsGenerated);
        Assert.Equal(1, result.Anomalies); // Only upload #3 has stack trace
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var nIndex = Array.IndexOf(argList, "-n");
            var count = int.Parse(argList[nIndex + 1]);
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            for (int i = 0; i < count; i++)
            {
                var mutationFile = Path.Combine(outputDirFromPattern, $"mutation-{i}");
                File.WriteAllText(mutationFile, $"mutation {i}");
            }

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, runner: fakeRunner);
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 5,
            OutputDir = outputDir,
        };

        await tool.MutateOnlyAsync(_seedFile, opts);

        // Read audit log
        var auditLines = File.ReadAllLines(Path.Combine(_tempDir, "audit.jsonl"));
        Assert.Contains(auditLines, line => line.Contains("fileformat-fuzz.start"));
        Assert.Contains(auditLines, line => line.Contains("fileformat-fuzz.finish"));
    }

    [Fact]
    public async Task Audit_Has_Seed_Digest_Not_Plaintext()
    {
        var outputDir = Path.Combine(_tempDir, "mutations");
        Directory.CreateDirectory(outputDir);

        var canaryContent = "THIS_IS_A_CANARY_SECRET_12345";
        var canaryFile = Path.Combine(_tempDir, "canary.txt");
        File.WriteAllText(canaryFile, canaryContent);

        var fakeRunner = new FakeProcessRunner((file, args, timeout) =>
        {
            var argList = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var oIndex = Array.IndexOf(argList, "-o");
            var outputPattern = argList[oIndex + 1];
            var outputDirFromPattern = Path.GetDirectoryName(outputPattern)!;

            var mutationFile = Path.Combine(outputDirFromPattern, "mutation-0");
            File.WriteAllText(mutationFile, "mutation");

            return (0, "", "");
        });

        var tool = new FileFormatFuzzTool(_scope, _audit, runner: fakeRunner);
        var opts = new FileFormatFuzzOptions
        {
            MutationCount = 1,
            OutputDir = outputDir,
        };

        await tool.MutateOnlyAsync(canaryFile, opts);

        // Read audit log
        var auditContent = File.ReadAllText(Path.Combine(_tempDir, "audit.jsonl"));

        // Canary plaintext must NOT appear
        Assert.DoesNotContain(canaryContent, auditContent);

        // But the start event must exist
        Assert.Contains("fileformat-fuzz.start", auditContent);
        Assert.Contains("seed_file_digest", auditContent);
    }
}

// Fake process runner for testing
internal sealed class FakeProcessRunner : Drederick.Doctor.IProcessRunner
{
    private readonly Func<string, string, int, (int, string, string)> _runFunc;

    public FakeProcessRunner(Func<string, string, int, (int, string, string)> runFunc)
    {
        _runFunc = runFunc;
    }

    public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
    {
        return _runFunc(file, arguments, timeoutSeconds);
    }

    public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
    {
        throw new NotImplementedException();
    }
}

// Fake HTTP message handler for testing
internal sealed class FakeFileFormatFuzzHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _sendFunc;

    public FakeFileFormatFuzzHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> sendFunc)
    {
        _sendFunc = sendFunc;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return _sendFunc(request, cancellationToken);
    }
}
