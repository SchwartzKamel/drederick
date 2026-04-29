using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// Subdomain brute force via gobuster dns (with dnsx fallback). Discovers
/// which subdomains resolve for a given apex domain. Expands the attack
/// surface by finding forgotten or unpatched services. Scope-enforced on
/// the apex domain after DNS resolution.
/// </summary>
public sealed class SubdomainFuzzTool : IFuzzTool
{
    public string Name => "subdomain-fuzz";
    public FuzzCategory Category => FuzzCategory.Dns;

    public string Description =>
        "Discover subdomains via DNS brute force using gobuster (or dnsx fallback). " +
        "Requires gobuster or dnsx binary.";

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _gobusterPath;
    private readonly string? _dnsxPath;
    private readonly IProcessRunner _runner;

    public SubdomainFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string gobusterPath = "gobuster",
        string? dnsxPath = "dnsx",
        IProcessRunner? runner = null)
    {
        _scope = scope;
        _audit = audit;
        _gobusterPath = gobusterPath;
        _dnsxPath = dnsxPath;
        _runner = runner ?? new DefaultProcessRunner();
    }

    public async Task<SubdomainFuzzResult> ProbeAsync(
        string apexDomain,
        SubdomainFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var opts = options ?? new SubdomainFuzzOptions();
        var started = DateTimeOffset.UtcNow;

        // Validate apex domain
        if (!IsValidHostname(apexDomain))
        {
            throw new ArgumentException(
                $"Invalid apex domain '{apexDomain}': must be a valid hostname without shell metacharacters.",
                nameof(apexDomain));
        }

        // Scope check: DNS tools work with hostnames, but scope only knows IPs.
        // Follow the HttpContentDiscoveryTool convention: attempt DNS lookup first,
        // then scope-check at least one resolved IP.
        await ValidateApexInScopeAsync(apexDomain, ct).ConfigureAwait(false);

        var wordlistPath = await ResolveWordlistAsync(opts, ct).ConfigureAwait(false);
        var wordsTried = await CountWordsAsync(wordlistPath, opts.MaxWords, ct).ConfigureAwait(false);

        // Try gobuster first, fall back to dnsx if gobuster fails
        var result = await TryGobusterAsync(apexDomain, wordlistPath, opts, started, wordsTried, ct)
            .ConfigureAwait(false);

        if (result is not null)
        {
            return result;
        }

        // Gobuster failed, try dnsx
        result = await TryDnsxAsync(apexDomain, wordlistPath, opts, started, wordsTried, ct)
            .ConfigureAwait(false);

        if (result is not null)
        {
            return result;
        }

        // Both failed
        var duration = DateTimeOffset.UtcNow - started;
        return new SubdomainFuzzResult
        {
            Target = apexDomain,
            ToolName = Name,
            StartedAt = started,
            Duration = duration,
            Error = "Both gobuster and dnsx binaries are unavailable or failed.",
        };
    }

    private async Task ValidateApexInScopeAsync(string apexDomain, CancellationToken ct)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(apexDomain, ct).ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new ScopeException(
                    $"Apex domain '{apexDomain}' did not resolve to any IP addresses.");
            }

            // Scope-check at least one resolved IP
            var firstIp = addresses[0].ToString();
            _scope.Require(firstIp);
        }
        catch (ScopeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ScopeException(
                $"Failed to resolve apex domain '{apexDomain}' for scope validation: {ex.Message}");
        }
    }

    private static bool IsValidHostname(string hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname)) return false;

        // RFC 1123 hostname: alphanumeric + hyphens + dots, no shell metacharacters
        var regex = new Regex(@"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", RegexOptions.Compiled);
        if (!regex.IsMatch(hostname)) return false;

        // Reject shell metacharacters explicitly
        char[] forbidden = ['`', '$', ';', '&', '|', '<', '>', '(', ')', '{', '}', '[', ']', '\\', '\'', '"', ' ', '\t', '\n', '\r'];
        return !hostname.Any(c => forbidden.Contains(c));
    }

    private async Task<string> ResolveWordlistAsync(SubdomainFuzzOptions opts, CancellationToken ct)
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
            $"subdomain-wordlist-{Guid.NewGuid():N}.txt");

        await File.WriteAllLinesAsync(tempFile, lines.Take(maxWords), ct).ConfigureAwait(false);
        return tempFile;
    }

    private async Task<int> CountWordsAsync(string wordlistPath, int maxWords, CancellationToken ct)
    {
        var lines = await File.ReadAllLinesAsync(wordlistPath, ct).ConfigureAwait(false);
        return Math.Min(lines.Length, maxWords);
    }

    private async Task<SubdomainFuzzResult?> TryGobusterAsync(
        string apexDomain,
        string wordlistPath,
        SubdomainFuzzOptions opts,
        DateTimeOffset started,
        int wordsTried,
        CancellationToken ct)
    {
        try
        {
            var argv = BuildGobusterArgs(apexDomain, wordlistPath, opts);
            var argvDigest = ComputeArgvDigest(argv);

            _audit.Record("subdomain-fuzz.start", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["tool"] = "gobuster",
                ["argv_digest"] = argvDigest,
            });

            var (exitCode, stdout, stderr) = _runner.Run(_gobusterPath, string.Join(" ", argv), 600);
            var duration = DateTimeOffset.UtcNow - started;

            if (exitCode != 0)
            {
                _audit.Record("subdomain-fuzz.gobuster-failed", new Dictionary<string, object?>
                {
                    ["target"] = apexDomain,
                    ["exit_code"] = exitCode,
                    ["error"] = stderr,
                });
                return null; // Fall back to dnsx
            }

            var subdomains = ParseGobusterOutput(stdout, apexDomain);

            _audit.Record("subdomain-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["tool"] = "gobuster",
                ["exit_code"] = exitCode,
                ["subdomains_found"] = subdomains.Count,
            });

            return new SubdomainFuzzResult
            {
                Target = apexDomain,
                ToolName = Name,
                StartedAt = started,
                Duration = duration,
                Subdomains = subdomains,
                WordsTried = wordsTried,
            };
        }
        catch (Exception ex)
        {
            _audit.Record("subdomain-fuzz.gobuster-error", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["error"] = ex.Message,
            });
            return null; // Fall back to dnsx
        }
    }

    private async Task<SubdomainFuzzResult?> TryDnsxAsync(
        string apexDomain,
        string wordlistPath,
        SubdomainFuzzOptions opts,
        DateTimeOffset started,
        int wordsTried,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_dnsxPath))
        {
            return null;
        }

        try
        {
            var argv = BuildDnsxArgs(apexDomain, wordlistPath, opts);
            var argvDigest = ComputeArgvDigest(argv);

            _audit.Record("subdomain-fuzz.start", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["tool"] = "dnsx",
                ["argv_digest"] = argvDigest,
            });

            var (exitCode, stdout, stderr) = _runner.Run(_dnsxPath, string.Join(" ", argv), 600);
            var duration = DateTimeOffset.UtcNow - started;

            if (exitCode != 0)
            {
                _audit.Record("subdomain-fuzz.dnsx-failed", new Dictionary<string, object?>
                {
                    ["target"] = apexDomain,
                    ["exit_code"] = exitCode,
                    ["error"] = stderr,
                });
                return null;
            }

            var subdomains = ParseDnsxOutput(stdout);

            _audit.Record("subdomain-fuzz.finish", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["tool"] = "dnsx",
                ["exit_code"] = exitCode,
                ["subdomains_found"] = subdomains.Count,
            });

            return new SubdomainFuzzResult
            {
                Target = apexDomain,
                ToolName = Name,
                StartedAt = started,
                Duration = duration,
                Subdomains = subdomains,
                WordsTried = wordsTried,
            };
        }
        catch (Exception ex)
        {
            _audit.Record("subdomain-fuzz.dnsx-error", new Dictionary<string, object?>
            {
                ["target"] = apexDomain,
                ["error"] = ex.Message,
            });
            return null;
        }
    }

    private List<string> BuildGobusterArgs(
        string apexDomain,
        string wordlistPath,
        SubdomainFuzzOptions opts)
    {
        var args = new List<string>
        {
            "dns",
            "-d", QuoteShellArg(apexDomain),
            "-w", QuoteShellArg(wordlistPath),
            "-t", "30",
            "-q", // quiet mode
        };

        if (!string.IsNullOrWhiteSpace(opts.Resolver))
        {
            args.Add("-r");
            args.Add(QuoteShellArg(opts.Resolver));
        }

        return args;
    }

    private List<string> BuildDnsxArgs(
        string apexDomain,
        string wordlistPath,
        SubdomainFuzzOptions opts)
    {
        var args = new List<string>
        {
            "-d", QuoteShellArg(apexDomain),
            "-w", QuoteShellArg(wordlistPath),
            "-silent",
        };

        if (!string.IsNullOrWhiteSpace(opts.Resolver))
        {
            args.Add("-r");
            args.Add(QuoteShellArg(opts.Resolver));
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

    private static IReadOnlyList<string> ParseGobusterOutput(string stdout, string apexDomain)
    {
        var subdomains = new List<string>();
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var line in lines)
        {
            // gobuster dns output: "Found: subdomain.apex"
            if (line.StartsWith("Found:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2, StringSplitOptions.TrimEntries);
                if (parts.Length == 2)
                {
                    subdomains.Add(parts[1]);
                }
            }
        }

        return subdomains;
    }

    private static IReadOnlyList<string> ParseDnsxOutput(string stdout)
    {
        var subdomains = new List<string>();
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var line in lines)
        {
            // dnsx output: one subdomain per line
            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith('['))
            {
                subdomains.Add(line);
            }
        }

        return subdomains;
    }
}

/// <summary>Options for subdomain fuzzing.</summary>
public sealed class SubdomainFuzzOptions
{
    /// <summary>Maximum words to try (truncates wordlist if larger).</summary>
    public int MaxWords { get; init; } = 5000;

    /// <summary>Custom wordlist path (validated, no path traversal).</summary>
    public string? CustomWordlist { get; init; }

    /// <summary>Custom DNS resolver (e.g., "8.8.8.8").</summary>
    public string? Resolver { get; init; }
}
