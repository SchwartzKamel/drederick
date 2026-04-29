using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Wrapper around kiterunner (kr scan) for API route discovery using routes.kite
/// wordlist. Scope-enforced, gracefully degrades when kr or wordlist is missing.
/// </summary>
public sealed class ApiEndpointFuzzTool : IFuzzTool
{
    public string Name => "api-endpoint-fuzz";

    public string Description =>
        "Run kiterunner API endpoint discovery against a base URL using routes.kite wordlist. " +
        "Detects REST API routes by method, path, status, and response size. " +
        "Target MUST be inside the authorized scope.";

    public FuzzCategory Category => FuzzCategory.WebApi;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _krPath;
    private readonly string? _defaultKitePath;
    private readonly IProcessRunner _runner;

    /// <summary>
    /// Kiterunner wordlist search paths when no explicit kiteFile is supplied.
    /// Checked in order; first found wins. If none found, returns an error.
    /// </summary>
    private static readonly string[] KitePathFallbacks =
    [
        "/opt/kiterunner/routes.kite",
        "/usr/share/kiterunner/routes.kite",
        "~/.kiterunner/routes.kite",
    ];

    /// <summary>
    /// Default fail-status codes to pass to kr's --fail-status-codes flag.
    /// These are common HTTP statuses that indicate a negative result (not found,
    /// unauthorized, etc.) and should be filtered from the output.
    /// </summary>
    private static readonly int[] DefaultFailStatusCodes = [400, 401, 404, 500];

    public ApiEndpointFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string krPath = "kr",
        string? defaultKitePath = null,
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _krPath = krPath;
        _defaultKitePath = defaultKitePath;
        _runner = runner is not null ? runner : new DefaultProcessRunner();
    }

    public async Task<ApiEndpointFuzzResult> ProbeAsync(
        string baseUrl,
        ApiFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        options ??= new ApiFuzzOptions();

        // 1. Validate baseUrl is an absolute URI
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"Invalid base URL: {baseUrl}", nameof(baseUrl));
        }

        // 2. Scope check — first statement
        _scope.Require(uri.Host);

        // 3. Resolve kiteFile
        string? kiteFile = null;
        if (options.KiteFile is not null)
        {
            // Validate: no path traversal
            if (options.KiteFile.Contains(".."))
            {
                throw new ArgumentException(
                    $"KiteFile contains path traversal: {options.KiteFile}", nameof(options));
            }
            if (!File.Exists(options.KiteFile))
            {
                return new ApiEndpointFuzzResult
                {
                    Target = baseUrl,
                    ToolName = Name,
                    StartedAt = startedAt,
                    Duration = DateTimeOffset.UtcNow - startedAt,
                    Error = $"Specified kite file not found: {options.KiteFile}",
                };
            }
            kiteFile = options.KiteFile;
        }
        else if (_defaultKitePath is not null && File.Exists(_defaultKitePath))
        {
            kiteFile = _defaultKitePath;
        }
        else
        {
            // Search fallback paths
            foreach (var path in KitePathFallbacks)
            {
                var expandedPath = path.Replace("~", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
                if (File.Exists(expandedPath))
                {
                    kiteFile = expandedPath;
                    break;
                }
            }
        }

        if (kiteFile is null)
        {
            return new ApiEndpointFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = DateTimeOffset.UtcNow - startedAt,
                Error = "kiterunner wordlist not found",
            };
        }

        // 4. Build argv
        var concurrency = options.Concurrency;
        var failCodes = options.FailStatusCodes ?? DefaultFailStatusCodes;
        var failCodesStr = string.Join(",", failCodes);

        var args = new List<string>
        {
            "scan",
            baseUrl,
            "-w", kiteFile,
            "-x", concurrency.ToString(),
            "-q",
            "-o", "json",
            "--fail-status-codes", failCodesStr,
        };

        // Validate argv elements with strict whitelist
        ValidateArgv(args);

        var argvStr = string.Join(" ", args);
        var argvDigest = ComputeSha256(argvStr);

        // 5. Audit start
        _audit.Record("api-endpoint-fuzz.start", new Dictionary<string, object?>
        {
            ["target"] = baseUrl,
            ["kite_file"] = kiteFile,
            ["argv_digest"] = argvDigest,
        });

        // 6. Spawn kr with timeout
        int exitCode;
        string stdout;
        string stderr;
        try
        {
            (exitCode, stdout, stderr) = await Task.Run(
                () => _runner.Run(_krPath, argvStr, options.TimeoutSec), ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex.Message.Contains("command not found") ||
                                    ex.Message.Contains("No such file or directory"))
        {
            var finishedAt = DateTimeOffset.UtcNow;
            _audit.Record("api-endpoint-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = baseUrl,
                ["exit_code"] = 127,
                ["hit_count"] = 0,
                ["duration_sec"] = (finishedAt - startedAt).TotalSeconds,
            });
            return new ApiEndpointFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = finishedAt - startedAt,
                Error = "kr binary not found",
            };
        }
        catch (Exception ex)
        {
            var finishedAt = DateTimeOffset.UtcNow;
            _audit.Record("api-endpoint-fuzz.error", new Dictionary<string, object?>
            {
                ["target"] = baseUrl,
                ["error"] = ex.Message,
                ["duration_sec"] = (finishedAt - startedAt).TotalSeconds,
            });
            return new ApiEndpointFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = finishedAt - startedAt,
                Error = ex.Message,
            };
        }

        // If kr exited with 127, it's missing
        if (exitCode == 127)
        {
            var finishedAt = DateTimeOffset.UtcNow;
            _audit.Record("api-endpoint-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = baseUrl,
                ["exit_code"] = exitCode,
                ["hit_count"] = 0,
                ["duration_sec"] = (finishedAt - startedAt).TotalSeconds,
            });
            return new ApiEndpointFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = startedAt,
                Duration = finishedAt - startedAt,
                Error = "kr binary not found (exit 127)",
            };
        }

        // 7. Parse kr JSON output
        var hits = new List<ApiHit>();
        if (!string.IsNullOrWhiteSpace(stdout))
        {
            hits.AddRange(ParseKrOutput(stdout, baseUrl));
        }

        var duration = DateTimeOffset.UtcNow - startedAt;

        // 8. Audit finish
        _audit.Record("api-endpoint-fuzz.finish", new Dictionary<string, object?>
        {
            ["target"] = baseUrl,
            ["exit_code"] = exitCode,
            ["hit_count"] = hits.Count,
            ["duration_sec"] = duration.TotalSeconds,
        });

        // 9. Return result
        return new ApiEndpointFuzzResult
        {
            Target = baseUrl,
            ToolName = Name,
            StartedAt = startedAt,
            Duration = duration,
            Hits = hits,
            Error = exitCode != 0 ? $"kr exited with code {exitCode}" : null,
        };
    }

    private static void ValidateArgv(List<string> args)
    {
        // Strict whitelist: only allow safe characters
        // Allow: alphanumerics, dash, underscore, dot, slash, colon, comma, equals
        var allowedPattern = new Regex(@"^[a-zA-Z0-9\-_./:,=]+$");

        foreach (var arg in args)
        {
            if (string.IsNullOrWhiteSpace(arg))
                continue;

            // Check for shell metacharacters
            if (arg.Contains('$') || arg.Contains('`') || arg.Contains(';') ||
                arg.Contains('&') || arg.Contains('|') || arg.Contains('>') ||
                arg.Contains('<') || arg.Contains('(') || arg.Contains(')') ||
                arg.Contains('{') || arg.Contains('}') || arg.Contains('[') ||
                arg.Contains(']') || arg.Contains('*') || arg.Contains('?') ||
                arg.Contains('~') || arg.Contains('!') || arg.Contains('#'))
            {
                throw new ArgumentException($"Unsafe character in argv element: {arg}");
            }

            // Additional safety: ensure no null bytes
            if (arg.Contains('\0'))
            {
                throw new ArgumentException($"Null byte in argv element: {arg}");
            }
        }
    }

    private static List<ApiHit> ParseKrOutput(string stdout, string baseUrl)
    {
        var hits = new List<ApiHit>();

        // kiterunner can emit:
        // - One JSON object per line (JSONL)
        // - A single JSON array
        // Try both modes

        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed))
                continue;

            try
            {
                // Try parsing as array first
                if (trimmed.StartsWith('['))
                {
                    var array = JsonSerializer.Deserialize<List<KrHit>>(trimmed);
                    if (array is not null)
                    {
                        foreach (var krHit in array)
                        {
                            var apiHit = ConvertKrHit(krHit, baseUrl);
                            if (apiHit is not null)
                                hits.Add(apiHit);
                        }
                    }
                }
                else
                {
                    // Try parsing as single object (JSONL mode)
                    var krHit = JsonSerializer.Deserialize<KrHit>(trimmed);
                    if (krHit is not null)
                    {
                        var apiHit = ConvertKrHit(krHit, baseUrl);
                        if (apiHit is not null)
                            hits.Add(apiHit);
                    }
                }
            }
            catch (JsonException)
            {
                // Skip malformed lines
                continue;
            }
        }

        return hits;
    }

    private static ApiHit? ConvertKrHit(KrHit krHit, string baseUrl)
    {
        if (krHit.Request is null || krHit.Response is null)
            return null;

        var method = krHit.Request.Method ?? "GET";
        var url = krHit.Request.Url ?? "";

        // Extract path from URL
        string path;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            path = uri.PathAndQuery;
        }
        else if (url.StartsWith('/'))
        {
            path = url;
        }
        else
        {
            // Try to extract path by removing baseUrl prefix
            path = url.StartsWith(baseUrl)
                ? url[baseUrl.Length..]
                : url;
            if (!path.StartsWith('/'))
                path = "/" + path;
        }

        var status = krHit.Response.StatusCode ?? 0;
        var size = krHit.Response.BodyLength ?? 0;

        return new ApiHit(method, path, status, size);
    }

    private static string ComputeSha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Kiterunner JSON output schema (subset of fields we care about).
    /// </summary>
    private sealed class KrHit
    {
        [JsonPropertyName("request")]
        public KrRequest? Request { get; init; }

        [JsonPropertyName("response")]
        public KrResponse? Response { get; init; }
    }

    private sealed class KrRequest
    {
        [JsonPropertyName("method")]
        public string? Method { get; init; }

        [JsonPropertyName("url")]
        public string? Url { get; init; }
    }

    private sealed class KrResponse
    {
        [JsonPropertyName("statusCode")]
        public int? StatusCode { get; init; }

        [JsonPropertyName("bodyLength")]
        public long? BodyLength { get; init; }
    }
}

/// <summary>
/// Options for <see cref="ApiEndpointFuzzTool.ProbeAsync"/>.
/// </summary>
public sealed class ApiFuzzOptions
{
    /// <summary>Explicit path to routes.kite wordlist (optional).</summary>
    public string? KiteFile { get; init; }

    /// <summary>kr -x concurrency (default 50).</summary>
    public int Concurrency { get; init; } = 50;

    /// <summary>Timeout in seconds (default 600).</summary>
    public int TimeoutSec { get; init; } = 600;

    /// <summary>Fail status codes to pass to kr (default: 400,401,404,500).</summary>
    public IReadOnlyList<int>? FailStatusCodes { get; init; }
}
