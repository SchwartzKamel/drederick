using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Virtual host discovery via ffuf. Probes an HTTP target with Host header
/// values from a wordlist to discover hidden vhosts, staging environments,
/// or admin panels served from the same IP. Uses automatic baselining to
/// filter out false positives. Scope-enforced on the target URL host.
/// </summary>
public sealed class VhostFuzzTool : IFuzzTool
{
    public string Name => "vhost-fuzz";
    public FuzzCategory Category => FuzzCategory.Web;

    public string Description =>
        "Discover virtual hosts by fuzzing the Host header with ffuf. " +
        "Automatically baselines response sizes to filter false positives. " +
        "Requires ffuf binary.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _ffufPath;
    private readonly IProcessRunner _runner;

    public VhostFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string ffufPath = "ffuf",
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _ffufPath = ffufPath;
        _runner = runner ?? new DefaultProcessRunner();
    }

    public async Task<VhostFuzzResult> ProbeAsync(
        string baseUrl,
        string apexDomain,
        VhostFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new VhostFuzzOptions();
        var started = DateTimeOffset.UtcNow;

        // Parse and validate baseUrl
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException($"Invalid base URL: {baseUrl}", nameof(baseUrl));
        }

        // Validate apex domain for shell metacharacters
        if (!IsValidApexDomain(apexDomain))
        {
            throw new ArgumentException(
                $"Invalid apex domain '{apexDomain}': must be a valid hostname without shell metacharacters.",
                nameof(apexDomain));
        }

        // Scope check on the target host (first statement after validation)
        _scope.Require(uri.Host);

        var wordlistPath = await ResolveWordlistAsync(opts, ct).ConfigureAwait(false);
        var baselineSize = opts.AutoBaseline
            ? await GetBaselineSizeAsync(baseUrl, apexDomain, ct).ConfigureAwait(false)
            : (long?)null;

        var argv = BuildFfufArgs(baseUrl, apexDomain, wordlistPath, baselineSize, opts);
        var argvDigest = ComputeArgvDigest(argv);

        _audit.Record("vhost-fuzz.start", new Dictionary<string, object?>
        {
            ["target"] = baseUrl,
            ["apex"] = apexDomain,
            ["argv_digest"] = argvDigest,
            ["baseline_size"] = baselineSize,
        });

        try
        {
            var (exitCode, stdout, stderr) = _runner.Run(_ffufPath, string.Join(" ", argv), 600);

            var duration = DateTimeOffset.UtcNow - started;

            if (exitCode != 0)
            {
                _audit.Record("vhost-fuzz.finish", new Dictionary<string, object?>
                {
                    ["target"] = baseUrl,
                    ["exit_code"] = exitCode,
                    ["error"] = stderr,
                });

                return new VhostFuzzResult
                {
                    Target = baseUrl,
                    ToolName = Name,
                    StartedAt = started,
                    Duration = duration,
                    Error = $"ffuf exited {exitCode}: {Tail(stderr, 500)}",
                };
            }

            var hits = ParseFfufJson(stdout);

            _audit.Record("vhost-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = baseUrl,
                ["exit_code"] = exitCode,
                ["hits"] = hits.Count,
            });

            return new VhostFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = started,
                Duration = duration,
                Hits = hits,
            };
        }
        catch (Exception ex)
        {
            var duration = DateTimeOffset.UtcNow - started;
            _audit.Record("vhost-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = baseUrl,
                ["error"] = ex.Message,
            });

            return new VhostFuzzResult
            {
                Target = baseUrl,
                ToolName = Name,
                StartedAt = started,
                Duration = duration,
                Error = ex.Message,
            };
        }
    }

    private static bool IsValidApexDomain(string apex)
    {
        if (string.IsNullOrWhiteSpace(apex)) return false;

        // RFC 1123 hostname: alphanumeric + hyphens + dots, no shell metacharacters
        var regex = new Regex(@"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", RegexOptions.Compiled);
        if (!regex.IsMatch(apex)) return false;

        // Reject shell metacharacters explicitly
        char[] forbidden = ['`', '$', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '\\', '\'', '"', ' ', '\t', '\n', '\r'];
        return !apex.Any(c => forbidden.Contains(c));
    }

    private async Task<string> ResolveWordlistAsync(VhostFuzzOptions opts, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(opts.CustomWordlist))
        {
            // Validate: no path traversal, must exist
            if (opts.CustomWordlist.Contains(".."))
            {
                throw new ArgumentException(
                    "Custom wordlist path contains '..' — path traversal rejected.",
                    nameof(opts.CustomWordlist));
            }

            if (!File.Exists(opts.CustomWordlist))
            {
                throw new FileNotFoundException(
                    $"Custom wordlist not found: {opts.CustomWordlist}");
            }

            return await TruncateWordlistIfNeededAsync(opts.CustomWordlist, opts.MaxWords, ct)
                .ConfigureAwait(false);
        }

        // Try default wordlists
        var candidates = new[]
        {
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dns/subdomains-top1million-5000.txt",
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path))
            {
                return await TruncateWordlistIfNeededAsync(path, opts.MaxWords, ct)
                    .ConfigureAwait(false);
            }
        }

        throw new FileNotFoundException(
            "No default wordlist found. Install SecLists or provide a custom wordlist.");
    }

    private async Task<string> TruncateWordlistIfNeededAsync(
        string sourcePath,
        int maxWords,
        CancellationToken ct)
    {
        var lines = await File.ReadAllLinesAsync(sourcePath, ct).ConfigureAwait(false);
        if (lines.Length <= maxWords)
        {
            return sourcePath;
        }

        // Write truncated copy to a temp file in the current directory (not /tmp)
        var tempFile = Path.Combine(
            Directory.GetCurrentDirectory(),
            $"vhost-wordlist-{Guid.NewGuid():N}.txt");

        await File.WriteAllLinesAsync(tempFile, lines.Take(maxWords), ct).ConfigureAwait(false);
        return tempFile;
    }

    private async Task<long> GetBaselineSizeAsync(
        string baseUrl,
        string apexDomain,
        CancellationToken ct)
    {
        // Send a single request with a random non-existent vhost to get baseline size
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        var randomVhost = $"nonexistent-{Guid.NewGuid():N}.{apexDomain}";

        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, baseUrl);
            request.Headers.Host = randomVhost;

            var response = await client.SendAsync(request, ct).ConfigureAwait(false);
            var content = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            return content.Length;
        }
        catch
        {
            // If baseline fails, just return 0 and let ffuf filter by status code
            return 0;
        }
    }

    private List<string> BuildFfufArgs(
        string baseUrl,
        string apexDomain,
        string wordlistPath,
        long? baselineSize,
        VhostFuzzOptions opts)
    {
        var args = new List<string>
        {
            "-u", QuoteShellArg(baseUrl),
            "-H", QuoteShellArg($"Host: FUZZ.{apexDomain}"),
            "-w", QuoteShellArg(wordlistPath),
            "-mc", "200,204,301,302,307,401,403",
            "-of", "json",
            "-o", "-", // output to stdout
            "-rate", opts.RateLimit.ToString(),
        };

        if (baselineSize.HasValue && baselineSize.Value > 0)
        {
            args.Add("-fs");
            args.Add(baselineSize.Value.ToString());
        }

        return args;
    }

    private static string QuoteShellArg(string arg)
    {
        // Simple shell quoting: wrap in single quotes, escape any internal single quotes
        return $"'{arg.Replace("'", "'\\''")}'";
    }

    private static string ComputeArgvDigest(IEnumerable<string> argv)
    {
        var joined = string.Join(" ", argv);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(joined));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static IReadOnlyList<VhostHit> ParseFfufJson(string stdout)
    {
        try
        {
            var doc = JsonDocument.Parse(stdout);
            var results = doc.RootElement.GetProperty("results");
            var hits = new List<VhostHit>();

            foreach (var result in results.EnumerateArray())
            {
                var vhost = result.GetProperty("input").GetProperty("FUZZ").GetString() ?? "";
                var status = result.GetProperty("status").GetInt32();
                var size = result.GetProperty("length").GetInt64();
                var redirectTo = result.TryGetProperty("redirectlocation", out var redir)
                    ? redir.GetString()
                    : null;

                hits.Add(new VhostHit(vhost, status, size, redirectTo));
            }

            return hits;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to parse ffuf JSON output: {ex.Message}", ex);
        }
    }

    private static string Tail(string text, int maxLen)
    {
        if (text.Length <= maxLen) return text;
        return "…" + text[(text.Length - maxLen)..];
    }
}

/// <summary>Options for vhost fuzzing.</summary>
public sealed class VhostFuzzOptions
{
    /// <summary>Maximum words to try (truncates wordlist if larger).</summary>
    public int MaxWords { get; init; } = 5000;

    /// <summary>Rate limit in requests per second.</summary>
    public int RateLimit { get; init; } = 50;

    /// <summary>Custom wordlist path (validated, no path traversal).</summary>
    public string? CustomWordlist { get; init; }

    /// <summary>
    /// If true, send a baseline request to determine the default response size
    /// and filter it out from results.
    /// </summary>
    public bool AutoBaseline { get; init; } = true;
}
