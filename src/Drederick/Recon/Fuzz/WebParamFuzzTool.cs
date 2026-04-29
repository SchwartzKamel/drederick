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
/// Wraps <c>arjun</c> (default) or <c>x8</c> (fallback) for hidden HTTP parameter
/// discovery. Sends mutated requests with candidate parameter names and detects
/// which ones produce response deltas (status changes, size deltas, reflection).
/// Each discovered parameter is a potential injection surface for XSS, SQLi,
/// command injection, or IDOR follow-on testing.
/// </summary>
public sealed class WebParamFuzzTool : IFuzzTool
{
    public string Name => "web-param-fuzz";

    public FuzzCategory Category => FuzzCategory.Web;

    public string Description =>
        "Discover hidden HTTP GET/POST parameters via arjun (default) or x8 (fallback) " +
        "against a given URL; returns a list of parameter names that produced response deltas. " +
        "Scope-enforced; only probes targets inside the authorized scope.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _arjunPath;
    private readonly string? _x8Path;
    private readonly IProcessRunner _runner;

    // Strict regex for wordlist path validation: no shell metachar, no path traversal
    private static readonly Regex SafePathRegex = new(@"^[a-zA-Z0-9_.\-/]+$", RegexOptions.Compiled);
    private static readonly char[] ShellMetachars = ['|', '&', ';', '$', '`', '>', '<', '(', ')', '{', '}', '[', ']', '\n', '\r'];

    public WebParamFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string arjunPath = "arjun",
        string? x8Path = "x8",
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _arjunPath = arjunPath;
        _x8Path = x8Path;
        _runner = runner ?? new DefaultProcessRunner();
    }

    public async Task<WebParamFuzzResult> ProbeAsync(
        string baseUrl,
        ParamFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ParamFuzzOptions();
        var started = DateTimeOffset.UtcNow;

        // 1. Validate URL
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"baseUrl '{baseUrl}' is not a valid absolute URI.", nameof(baseUrl));
        }

        // 2. Scope check — FIRST statement after validation
        _scope.Require(uri.Host);

        // 3. Validate custom wordlist if provided
        if (options.CustomWordlist is not null)
        {
            ValidateWordlistPath(options.CustomWordlist);
        }

        // 4. Build argv for arjun
        var argv = BuildArjunArgv(baseUrl, options);
        var argvDigest = ComputeArgvDigest(argv);

        // 5. Audit start
        _audit.Record("web-param-fuzz.start", new Dictionary<string, object?>
        {
            ["tool"] = "arjun",
            ["url"] = baseUrl,
            ["argv_digest"] = argvDigest,
            ["max_requests"] = options.MaxRequests,
            ["method"] = options.Method,
        });

        // 6. Spawn arjun with timeout (default 5 min = 300s)
        var tempJsonPath = Path.Combine(Path.GetTempPath(), $"arjun_{Guid.NewGuid():N}.json");
        string? actualToolUsed = "arjun";
        try
        {
            argv = BuildArjunArgv(baseUrl, options, tempJsonPath);
            var (exitCode, stdout, stderr) = _runner.Run(_arjunPath, string.Join(" ", argv.Select(EscapeArg)), 300);

            // Truncate stdout/stderr if > 64KB
            var (truncStdout, fullStdoutSize, stdoutDigest) = TruncateAndDigest(stdout, 64 * 1024);
            var (truncStderr, fullStderrSize, stderrDigest) = TruncateAndDigest(stderr, 64 * 1024);

            // 7. Parse arjun JSON output or fall back to x8
            List<string> discoveredParams;
            int requestsSent = 0;

            if (exitCode == 0 && File.Exists(tempJsonPath))
            {
                discoveredParams = ParseArjunJson(tempJsonPath);
            }
            else if (ShouldFallbackToX8(exitCode, stderr, options.TryX8Fallback))
            {
                // Fallback to x8
                actualToolUsed = "x8";
                _audit.Record("web-param-fuzz.fallback", new Dictionary<string, object?>
                {
                    ["reason"] = "arjun_unavailable_or_failed",
                    ["arjun_exit_code"] = exitCode,
                });

                var x8Result = await RunX8Async(baseUrl, options, ct);
                discoveredParams = x8Result.DiscoveredParameters.ToList();
                requestsSent = x8Result.RequestsSent;
            }
            else if (exitCode != 0)
            {
                var duration = DateTimeOffset.UtcNow - started;
                _audit.Record("web-param-fuzz.finish", new Dictionary<string, object?>
                {
                    ["discovered_count"] = 0,
                    ["requests_sent"] = 0,
                    ["exit_code"] = exitCode,
                    ["duration_ms"] = (int)duration.TotalMilliseconds,
                });

                return new WebParamFuzzResult
                {
                    Target = baseUrl,
                    ToolName = Name,
                    StartedAt = started,
                    Duration = duration,
                    DiscoveredParameters = Array.Empty<string>(),
                    RequestsSent = 0,
                    ReflectedCount = 0,
                    Error = $"arjun exited {exitCode}: {truncStderr}",
                };
            }
            else
            {
                // Success but no JSON file
                discoveredParams = new List<string>();
            }

            var finalDuration = DateTimeOffset.UtcNow - started;

            // 8. Audit finish
            _audit.Record("web-param-fuzz.finish", new Dictionary<string, object?>
            {
                ["tool"] = actualToolUsed,
                ["discovered_count"] = discoveredParams.Count,
                ["requests_sent"] = requestsSent,
                ["exit_code"] = exitCode,
                ["duration_ms"] = (int)finalDuration.TotalMilliseconds,
            });

            // 9. Return result
            return new WebParamFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = started,
                Duration = finalDuration,
                DiscoveredParameters = discoveredParams,
                RequestsSent = requestsSent,
                ReflectedCount = discoveredParams.Count,
            };
        }
        finally
        {
            // Clean up temp file
            if (File.Exists(tempJsonPath))
            {
                try { File.Delete(tempJsonPath); } catch { }
            }
        }
    }

    private List<string> BuildArjunArgv(string baseUrl, ParamFuzzOptions options, string? tempJsonPath = null)
    {
        var argv = new List<string>
        {
            "-u", baseUrl,
            "-m", options.Method ?? "GET",
            "-t", "10", // threads
            "--stable",
        };

        if (tempJsonPath is not null)
        {
            argv.Add("-oJ");
            argv.Add(tempJsonPath);
        }

        if (options.CustomWordlist is not null)
        {
            argv.Add("-w");
            argv.Add(options.CustomWordlist);
        }

        // Validate every argv element
        foreach (var arg in argv)
        {
            ValidateArgvElement(arg);
        }

        return argv;
    }

    private Task<WebParamFuzzResult> RunX8Async(
        string baseUrl,
        ParamFuzzOptions options,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(_x8Path))
        {
            throw new InvalidOperationException("x8 fallback requested but x8Path is null.");
        }

        var started = DateTimeOffset.UtcNow;
        var argv = new List<string>
        {
            "-u", baseUrl,
            "-X", options.Method ?? "GET",
        };

        if (options.CustomWordlist is not null)
        {
            argv.Add("-w");
            argv.Add(options.CustomWordlist);
        }

        foreach (var arg in argv)
        {
            ValidateArgvElement(arg);
        }

        var argvDigest = ComputeArgvDigest(argv);
        _audit.Record("web-param-fuzz.x8.start", new Dictionary<string, object?>
        {
            ["url"] = baseUrl,
            ["argv_digest"] = argvDigest,
        });

        var (exitCode, stdout, stderr) = _runner.Run(
            _x8Path,
            string.Join(" ", argv.Select(EscapeArg)),
            300);

        var discoveredParams = ParseX8Output(stdout);
        var duration = DateTimeOffset.UtcNow - started;

        _audit.Record("web-param-fuzz.x8.finish", new Dictionary<string, object?>
        {
            ["discovered_count"] = discoveredParams.Count,
            ["exit_code"] = exitCode,
            ["duration_ms"] = (int)duration.TotalMilliseconds,
        });

        return Task.FromResult(new WebParamFuzzResult
        {
            Target = baseUrl,
            ToolName = Name,
            StartedAt = started,
            Duration = duration,
            DiscoveredParameters = discoveredParams,
            RequestsSent = 0, // x8 doesn't report this
            ReflectedCount = discoveredParams.Count,
        });
    }

    private static void ValidateWordlistPath(string wordlistPath)
    {
        // Reject path traversal
        if (wordlistPath.Contains(".."))
        {
            throw new ArgumentException(
                $"Wordlist path '{wordlistPath}' contains path traversal (..)",
                nameof(wordlistPath));
        }

        // Reject shell metachar
        if (wordlistPath.IndexOfAny(ShellMetachars) >= 0)
        {
            throw new ArgumentException(
                $"Wordlist path '{wordlistPath}' contains shell metacharacters",
                nameof(wordlistPath));
        }

        // Must be readable file
        if (!File.Exists(wordlistPath))
        {
            throw new ArgumentException(
                $"Wordlist path '{wordlistPath}' does not exist or is not readable",
                nameof(wordlistPath));
        }
    }

    private static void ValidateArgvElement(string arg)
    {
        // Strict whitelist: reject shell metachar except safe URL/path chars
        // Allow: alphanumeric, :, /, ?, &, =, -, _, ., @, %, +
        if (arg.IndexOfAny(['|', ';', '$', '`', '>', '<', '(', ')', '{', '}', '[', ']', '\n', '\r']) >= 0)
        {
            throw new ArgumentException(
                $"Argv element '{arg}' contains forbidden shell metacharacters");
        }
    }

    private static bool ShouldFallbackToX8(int exitCode, string stderr, bool tryX8Fallback)
    {
        if (!tryX8Fallback) return false;
        if (exitCode == 127) return true; // command not found
        if (stderr.Contains("command not found", StringComparison.OrdinalIgnoreCase)) return true;
        if (stderr.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static List<string> ParseArjunJson(string jsonPath)
    {
        try
        {
            var json = File.ReadAllText(jsonPath);
            var doc = JsonDocument.Parse(json);

            // Arjun outputs an object with a key equal to the URL, containing an array of params
            // Example: {"http://example.com/": ["id", "name"]}
            // OR it can be an array of objects: [{"name": "id", "confirmed": true}, ...]
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Object)
            {
                // Try both formats
                foreach (var prop in root.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        var list = new List<string>();
                        foreach (var elem in prop.Value.EnumerateArray())
                        {
                            if (elem.ValueKind == JsonValueKind.String)
                            {
                                list.Add(elem.GetString()!);
                            }
                            else if (elem.ValueKind == JsonValueKind.Object)
                            {
                                // Format: {"name": "...", "confirmed": true}
                                if (elem.TryGetProperty("name", out var nameVal))
                                {
                                    list.Add(nameVal.GetString()!);
                                }
                            }
                        }
                        return list;
                    }
                }
            }
            else if (root.ValueKind == JsonValueKind.Array)
            {
                var list = new List<string>();
                foreach (var elem in root.EnumerateArray())
                {
                    if (elem.ValueKind == JsonValueKind.String)
                    {
                        list.Add(elem.GetString()!);
                    }
                    else if (elem.ValueKind == JsonValueKind.Object && elem.TryGetProperty("name", out var nameVal))
                    {
                        list.Add(nameVal.GetString()!);
                    }
                }
                return list;
            }

            return new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    private static List<string> ParseX8Output(string stdout)
    {
        // x8 outputs lines like: [+] paramname
        // or: [200] [param: value] /path
        var result = new List<string>();
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var line in lines)
        {
            // Match: [+] param or param: or similar
            if (line.StartsWith("[+]"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    result.Add(parts[1].Trim());
                }
            }
            else if (line.Contains("param:", StringComparison.OrdinalIgnoreCase))
            {
                var idx = line.IndexOf("param:", StringComparison.OrdinalIgnoreCase);
                var afterParam = line.Substring(idx + 6).Trim();
                var paramName = afterParam.Split([' ', ']'], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
                if (paramName is not null)
                {
                    result.Add(paramName);
                }
            }
        }

        return result.Distinct().ToList();
    }

    private static string ComputeArgvDigest(IEnumerable<string> argv)
    {
        var joined = string.Join(" ", argv);
        var bytes = Encoding.UTF8.GetBytes(joined);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static (string Truncated, long FullSize, string Digest) TruncateAndDigest(string input, int maxBytes)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var digest = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

        if (bytes.Length <= maxBytes)
        {
            return (input, bytes.Length, digest);
        }

        var truncatedBytes = bytes.AsSpan(0, maxBytes).ToArray();
        var truncated = Encoding.UTF8.GetString(truncatedBytes);
        return (truncated, bytes.Length, digest);
    }

    private static string EscapeArg(string arg)
    {
        // Simple shell escaping: wrap in single quotes if contains space
        if (arg.Contains(' ') || arg.Contains('\''))
        {
            return $"'{arg.Replace("'", "'\\''")}'";
        }
        return arg;
    }

    /// <summary>Options for parameter fuzzing.</summary>
    public sealed class ParamFuzzOptions
    {
        public int MaxRequests { get; init; } = 1000;
        public int RateLimitRps { get; init; } = 20;
        public string? Method { get; init; } = "GET";
        public string? CustomWordlist { get; init; }
        public bool TryX8Fallback { get; init; } = true;
    }
}
