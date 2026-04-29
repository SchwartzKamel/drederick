using System.Net.Http;
using System.Security.Cryptography;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Radamsa-based mutation fuzzer for file formats. Two operating modes:
///   1. Mutate-only: generate N variants of a seed file, return count + sample digests.
///   2. Mutate-and-upload: generate variants AND POST each to an upload endpoint,
///      watch for 5xx/timeouts/error markers in responses.
///
/// DESTRUCTIVE category — requires explicit <c>--allow-fuzz-mutation</c> AND
/// <c>--allow-destructive</c> opt-in even in lab mode.
/// </summary>
public sealed class FileFormatFuzzTool : IFuzzTool, IDisposable
{
    public string Name => "fileformat-fuzz";

    public string Description =>
        "Generate mutated variants of a seed file using radamsa. " +
        "Can operate in mutate-only mode (generate samples) or mutate-and-upload mode " +
        "(POST each variant to an upload endpoint and detect anomalies). " +
        "DESTRUCTIVE — requires explicit opt-in.";

    public FuzzCategory Category => FuzzCategory.Mutation;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _radamsaPath;
    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly Doctor.IProcessRunner _runner;

    private const long DefaultMaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB
    private const int DefaultUploadRateLimitRps = 5;

    public FileFormatFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string radamsaPath = "radamsa",
        HttpClient? httpClient = null,
        Doctor.IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _radamsaPath = radamsaPath;

        if (httpClient is null)
        {
            _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            _ownsHttpClient = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttpClient = false;
        }

        _runner = runner ?? new Doctor.DefaultProcessRunner();
    }

    /// <summary>
    /// Mutate-only mode: generate N variants of a seed file, return count + sample digests.
    /// No network egress; no scope check required.
    /// </summary>
    public async Task<FileFormatFuzzResult> MutateOnlyAsync(
        string seedFile,
        FileFormatFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new FileFormatFuzzOptions();
        var startedAt = DateTimeOffset.UtcNow;

        // 1. Validate seed file
        ValidateSeedFile(seedFile);

        // 2. Cap mutation count
        var mutationCount = Math.Min(opts.MutationCount, opts.MaxMutationCount);

        // 3. Validate/create output dir
        var outputDir = opts.OutputDir;
        if (outputDir is null)
        {
            outputDir = Path.Combine(Path.GetTempPath(), $"drederick-fuzz-{Guid.NewGuid()}");
            Directory.CreateDirectory(outputDir);
        }
        else
        {
            ValidateOutputDir(outputDir);
        }

        // 4. Audit start
        var seedDigest = ComputeFileDigest(seedFile);
        _audit.Record("fileformat-fuzz.start", new Dictionary<string, object?>
        {
            ["mode"] = "mutate-only",
            ["seed_file_digest"] = seedDigest,
            ["mutation_count"] = mutationCount,
            ["output_dir"] = outputDir,
        });

        // 5. Build radamsa argv
        var outputPattern = Path.Combine(outputDir, "mutation-%n");
        var args = new List<string>
        {
            "-n", mutationCount.ToString(),
            "-o", outputPattern,
            seedFile,
        };

        // 6. Validate argv
        ValidateArgv(args);

        // 7. Spawn radamsa
        int exitCode;
        string stderr;
        try
        {
            var argsStr = string.Join(" ", args);
            var result = _runner.Run(_radamsaPath, argsStr, timeoutSeconds: 120);
            exitCode = result.ExitCode;
            stderr = result.StdErr;
        }
        catch (Exception ex) when (ex.Message.Contains("failed to start"))
        {
            // Binary missing
            _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
            {
                ["error"] = "radamsa not found",
            });
            return new FileFormatFuzzResult
            {
                Target = "",
                ToolName = Name,
                StartedAt = startedAt,
                Duration = DateTimeOffset.UtcNow - startedAt,
                SeedFile = seedFile,
                MutationsGenerated = 0,
                Anomalies = 0,
                Error = "radamsa not found",
            };
        }

        if (exitCode != 0)
        {
            _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
            {
                ["error"] = $"radamsa exited with code {exitCode}: {Tail(stderr, 500)}",
            });
            return new FileFormatFuzzResult
            {
                Target = "",
                ToolName = Name,
                StartedAt = startedAt,
                Duration = DateTimeOffset.UtcNow - startedAt,
                SeedFile = seedFile,
                MutationsGenerated = 0,
                Anomalies = 0,
                Error = $"radamsa exited with code {exitCode}",
            };
        }

        // 8. Enumerate output files, compute digests
        var mutationFiles = Directory.GetFiles(outputDir, "mutation-*")
            .OrderBy(f => f)
            .ToList();

        var sampleDigests = mutationFiles
            .Take(5)
            .Select(f => $"{Path.GetFileName(f)}:{ComputeFileDigest(f)}")
            .ToList();

        // 9. Audit finish
        _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
        {
            ["mutations_generated"] = mutationFiles.Count,
        });

        return new FileFormatFuzzResult
        {
            Target = "",
            ToolName = Name,
            StartedAt = startedAt,
            Duration = DateTimeOffset.UtcNow - startedAt,
            SeedFile = seedFile,
            MutationsGenerated = mutationFiles.Count,
            Anomalies = 0,
            SampleCrashInputDigests = sampleDigests,
        };
    }

    /// <summary>
    /// Mutate-and-upload mode: generate variants AND POST each to an upload endpoint,
    /// watch for 5xx/timeouts/error markers.
    /// </summary>
    public async Task<FileFormatFuzzResult> MutateAndUploadAsync(
        string seedFile,
        string uploadUrl,
        FileFormatFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new FileFormatFuzzOptions();
        var startedAt = DateTimeOffset.UtcNow;

        // 1. Validate seed file
        ValidateSeedFile(seedFile);

        // 2. Validate upload URL
        if (!Uri.TryCreate(uploadUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new ArgumentException($"Invalid upload URL: {uploadUrl}", nameof(uploadUrl));
        }

        // 3. Scope check FIRST
        _scope.Require(uri.Host);

        // 4. Cap mutation count, validate output dir
        var mutationCount = Math.Min(opts.MutationCount, opts.MaxMutationCount);
        var outputDir = opts.OutputDir;
        if (outputDir is null)
        {
            outputDir = Path.Combine(Path.GetTempPath(), $"drederick-fuzz-{Guid.NewGuid()}");
            Directory.CreateDirectory(outputDir);
        }
        else
        {
            ValidateOutputDir(outputDir);
        }

        // 5. Audit start
        var seedDigest = ComputeFileDigest(seedFile);
        _audit.Record("fileformat-fuzz.start", new Dictionary<string, object?>
        {
            ["mode"] = "mutate-and-upload",
            ["seed_file_digest"] = seedDigest,
            ["mutation_count"] = mutationCount,
            ["output_dir"] = outputDir,
            ["url"] = uploadUrl,
            ["host"] = uri.Host,
        });

        // 6. Generate mutations
        var outputPattern = Path.Combine(outputDir, "mutation-%n");
        var args = new List<string>
        {
            "-n", mutationCount.ToString(),
            "-o", outputPattern,
            seedFile,
        };

        ValidateArgv(args);

        int exitCode;
        string stderr;
        try
        {
            var argsStr = string.Join(" ", args);
            var result = _runner.Run(_radamsaPath, argsStr, timeoutSeconds: 120);
            exitCode = result.ExitCode;
            stderr = result.StdErr;
        }
        catch (Exception ex) when (ex.Message.Contains("failed to start"))
        {
            _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
            {
                ["error"] = "radamsa not found",
            });
            return new FileFormatFuzzResult
            {
                Target = uploadUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = DateTimeOffset.UtcNow - startedAt,
                SeedFile = seedFile,
                MutationsGenerated = 0,
                Anomalies = 0,
                Error = "radamsa not found",
            };
        }

        if (exitCode != 0)
        {
            _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
            {
                ["error"] = $"radamsa exited with code {exitCode}",
            });
            return new FileFormatFuzzResult
            {
                Target = uploadUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = DateTimeOffset.UtcNow - startedAt,
                SeedFile = seedFile,
                MutationsGenerated = 0,
                Anomalies = 0,
                Error = $"radamsa exited with code {exitCode}",
            };
        }

        // 7. Upload each mutation and track anomalies
        var mutationFiles = Directory.GetFiles(outputDir, "mutation-*")
            .OrderBy(f => f)
            .ToList();

        var anomalyCount = 0;
        var anomalyDigests = new List<string>();
        var delayMs = 1000 / DefaultUploadRateLimitRps;

        foreach (var mutationFile in mutationFiles)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                var isAnomaly = await UploadAndCheckAnomalyAsync(
                    mutationFile,
                    uploadUrl,
                    opts.FormFieldName,
                    opts.AdditionalFormFields,
                    opts.RequestTimeoutSec,
                    ct).ConfigureAwait(false);

                if (isAnomaly)
                {
                    anomalyCount++;
                    anomalyDigests.Add($"{Path.GetFileName(mutationFile)}:{ComputeFileDigest(mutationFile)}");
                }

                // Rate limit
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Treat upload failures as non-anomalous for now
            }
        }

        // 8. Audit finish
        _audit.Record("fileformat-fuzz.finish", new Dictionary<string, object?>
        {
            ["mutations_generated"] = mutationFiles.Count,
            ["anomalies"] = anomalyCount,
        });

        return new FileFormatFuzzResult
        {
            Target = uploadUrl,
            ToolName = Name,
            StartedAt = startedAt,
            Duration = DateTimeOffset.UtcNow - startedAt,
            SeedFile = seedFile,
            MutationsGenerated = mutationFiles.Count,
            Anomalies = anomalyCount,
            SampleCrashInputDigests = anomalyDigests.Take(5).ToList(),
        };
    }

    private async Task<bool> UploadAndCheckAnomalyAsync(
        string filePath,
        string uploadUrl,
        string formFieldName,
        string? additionalFormFields,
        int timeoutSec,
        CancellationToken ct)
    {
        using var content = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(await File.ReadAllBytesAsync(filePath, ct).ConfigureAwait(false));
        content.Add(fileContent, formFieldName, Path.GetFileName(filePath));

        // Add additional form fields if specified
        if (!string.IsNullOrWhiteSpace(additionalFormFields))
        {
            var fields = additionalFormFields.Split('&', StringSplitOptions.RemoveEmptyEntries);
            foreach (var field in fields)
            {
                var parts = field.Split('=', 2);
                if (parts.Length == 2)
                {
                    content.Add(new StringContent(parts[1]), parts[0]);
                }
            }
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

        try
        {
            using var response = await _http.PostAsync(uploadUrl, content, cts.Token).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

            // Check for anomaly conditions
            if ((int)response.StatusCode >= 500)
            {
                return true;
            }

            // Check for stack trace markers
            if (ContainsStackTraceMarker(body))
            {
                return true;
            }

            return false;
        }
        catch (TaskCanceledException)
        {
            // Timeout or cancellation
            return !ct.IsCancellationRequested; // True if timeout (anomaly), false if user cancellation
        }
        catch (HttpRequestException)
        {
            // Connection reset or other HTTP error
            return true;
        }
    }

    private static bool ContainsStackTraceMarker(string body)
    {
        var markers = new[]
        {
            "Traceback",
            "at sun.",
            "at java.",
            "at .NET",
            "Exception:",
            "Fatal error",
            "Segmentation fault",
        };

        foreach (var marker in markers)
        {
            if (body.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static void ValidateSeedFile(string seedFile)
    {
        if (seedFile.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("Seed file path cannot contain '..'", nameof(seedFile));
        }

        if (!File.Exists(seedFile))
        {
            throw new FileNotFoundException("Seed file not found", seedFile);
        }

        var fileInfo = new FileInfo(seedFile);
        if (!fileInfo.Attributes.HasFlag(FileAttributes.Directory) == false || fileInfo.Length == 0)
        {
            // Make sure it's a regular file
            if ((fileInfo.Attributes & FileAttributes.Directory) != 0)
            {
                throw new ArgumentException("Seed file cannot be a directory", nameof(seedFile));
            }
        }

        if (fileInfo.Length > DefaultMaxFileSizeBytes)
        {
            throw new ArgumentException(
                $"Seed file too large: {fileInfo.Length} bytes (max {DefaultMaxFileSizeBytes})",
                nameof(seedFile));
        }
    }

    private static void ValidateOutputDir(string outputDir)
    {
        if (outputDir.Contains("..", StringComparison.Ordinal))
        {
            throw new ArgumentException("Output dir path cannot contain '..'", nameof(outputDir));
        }

        var parentDir = Path.GetDirectoryName(outputDir);
        if (!string.IsNullOrEmpty(parentDir) && !Directory.Exists(parentDir))
        {
            throw new ArgumentException("Output dir parent must exist", nameof(outputDir));
        }

        if (!Directory.Exists(outputDir))
        {
            Directory.CreateDirectory(outputDir);
        }
    }

    private static void ValidateArgv(List<string> args)
    {
        // Reject shell metacharacters and other unsafe patterns
        var forbidden = new[] { ";", "|", "&", "$", "`", "\n", "\r", ">", "<" };
        foreach (var arg in args)
        {
            foreach (var ch in forbidden)
            {
                if (arg.Contains(ch, StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Argv contains forbidden character: {ch}");
                }
            }
        }
    }

    private static string ComputeFileDigest(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    private static string Tail(string s, int maxLen)
    {
        if (s.Length <= maxLen) return s;
        return "..." + s.Substring(s.Length - maxLen);
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}

/// <summary>
/// Options for file-format fuzzing.
/// </summary>
public sealed class FileFormatFuzzOptions
{
    /// <summary>Number of mutations to generate (capped at <see cref="MaxMutationCount"/>).</summary>
    public int MutationCount { get; init; } = 100;

    /// <summary>Hard cap on mutation count to prevent runaway generation.</summary>
    public int MaxMutationCount { get; init; } = 10000;

    /// <summary>
    /// Output directory for mutations. If null, a temp directory is created.
    /// Path must not contain ".." and parent must exist.
    /// </summary>
    public string? OutputDir { get; init; }

    /// <summary>Form field name for the uploaded file in mutate-and-upload mode.</summary>
    public string FormFieldName { get; init; } = "file";

    /// <summary>
    /// Additional form fields for upload, formatted as "key1=value1&amp;key2=value2".
    /// </summary>
    public string? AdditionalFormFields { get; init; }

    /// <summary>Timeout in seconds for each upload request.</summary>
    public int RequestTimeoutSec { get; init; } = 30;
}
