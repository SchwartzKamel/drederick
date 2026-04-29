using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;
using Drederick.Scope;

namespace Drederick.Recon.Fuzz;

/// <summary>
/// JWT token fuzzing via <c>jwt_tool</c> (ticarpi/jwt_tool). Detects algorithm
/// confusion (alg=none, RS256-to-HS256 key confusion), weak HMAC secrets
/// (wordlist-driven brute force), KID header injection (path traversal, SQLi),
/// and JKU/X5U URL injection. Supports two modes:
///
///   1. <b>URL mode</b>: <c>ProbeAsync(token, targetUrl, ...)</c> — sends
///      crafted tokens to <paramref name="targetUrl"/> and observes responses.
///      Re-checks scope via <see cref="Scope.Scope.Require"/> on the URL host.
///   2. <b>Offline mode</b>: <c>AnalyzeAsync(token, ...)</c> — structural
///      analysis and cracking attempts without contacting any target. No
///      scope check (token-only analysis is always allowed since no network
///      egress occurs).
///
/// Every probe is audited to <c>audit.jsonl</c> with token digest (SHA-256)
/// and argv digest; plaintext tokens never appear in the audit log.
/// </summary>
public sealed class JwtFuzzTool : IFuzzTool
{
    public string Name => "jwt-fuzz";

    public string Description =>
        "Fuzz JWT tokens for algorithm confusion, weak HMAC secrets, KID injection, " +
        "and JKU/X5U vulnerabilities using jwt_tool. Supports URL-based probing (scope-checked) " +
        "and offline analysis (token-only, no network egress).";

    public FuzzCategory Category => FuzzCategory.Auth;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly string _jwtToolPath;
    private readonly IProcessRunner _runner;
    private readonly string? _hmacWordlist;

    // JWT regex: 3 base64url segments separated by dots (last segment may be empty for unsigned).
    private static readonly Regex JwtPattern = new(@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$", RegexOptions.Compiled);

    public JwtFuzzTool(
        Scope.Scope scope,
        AuditLog audit,
        string jwtToolPath = "jwt_tool",
        IProcessRunner? runner = null,
        string? hmacWordlist = null)
    {
        _scope = scope;
        _audit = audit;
        _jwtToolPath = jwtToolPath;
        _runner = runner ?? new DefaultProcessRunner();
        _hmacWordlist = hmacWordlist;
    }

    /// <summary>
    /// URL mode: probe <paramref name="targetUrl"/> with crafted tokens.
    /// Scope-checks the URL host before proceeding.
    /// </summary>
    public async Task<JwtFuzzResult> ProbeAsync(
        string token,
        string targetUrl,
        JwtFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var startTime = DateTimeOffset.UtcNow;
        options ??= new JwtFuzzOptions();

        // Validate URL first
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
        {
            throw new ArgumentException($"Invalid target URL '{targetUrl}'. Must be absolute http(s).");
        }

        // Validate token format
        ValidateToken(token);

        // FIRST statement after validation: scope check
        _scope.Require(uri.Host);

        return await RunJwtToolAsync(token, targetUrl, options, startTime, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Offline mode: analyze token structure and attempt cracking without
    /// contacting any URL. No scope check (token-only analysis is always
    /// allowed since no network egress occurs).
    /// </summary>
    public async Task<JwtFuzzResult> AnalyzeAsync(
        string token,
        JwtFuzzOptions? options = null,
        CancellationToken ct = default)
    {
        var startTime = DateTimeOffset.UtcNow;
        options ??= new JwtFuzzOptions();

        // Validate token format
        ValidateToken(token);

        // No scope check — offline analysis only
        return await RunJwtToolAsync(token, null, options, startTime, ct).ConfigureAwait(false);
    }

    private static void ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException(
                "Malformed JWT (token is null or whitespace; expected 3 base64url segments separated by dots).",
                nameof(token));
        }

        if (!JwtPattern.IsMatch(token))
        {
            throw new ArgumentException(
                $"Malformed JWT (must be 3 base64url segments separated by dots). " +
                $"Got: {token[..Math.Min(token.Length, 50)]}...",
                nameof(token));
        }
    }

    private async Task<JwtFuzzResult> RunJwtToolAsync(
        string token,
        string? targetUrl,
        JwtFuzzOptions options,
        DateTimeOffset startTime,
        CancellationToken ct)
    {
        var mode = targetUrl != null ? "url" : "offline";
        var tokenDigest = ComputeSha256(token);

        // Build argv
        var args = new List<string> { token };

        if (targetUrl != null)
        {
            args.Add("-t");
            args.Add(targetUrl);
        }

        // All-tests mode
        args.Add("-M");
        args.Add("at");

        // Disable auto-update check
        args.Add("--no-update");

        // HMAC secret wordlist
        var wordlist = options.HmacWordlist ?? _hmacWordlist;
        if (!string.IsNullOrWhiteSpace(wordlist))
        {
            ValidateWordlistPath(wordlist!);
            args.Add("-d");
            args.Add(wordlist);
        }

        // Signature algorithm for cracking attempts
        args.Add("-S");
        args.Add("hs256");

        var argvDigest = ComputeSha256(string.Join(" ", args));

        _audit.Record("jwt-fuzz.start", new Dictionary<string, object?>
        {
            ["mode"] = mode,
            ["url"] = targetUrl,
            ["token_digest"] = tokenDigest,
            ["argv_digest"] = argvDigest,
            ["options"] = new
            {
                options.HmacWordlist,
                options.TryKeyConfusion,
                options.TryKidInjection,
                options.TimeoutSec,
            },
        });

        int exitCode;
        string stdout;
        string stderr;

        try
        {
            (exitCode, stdout, stderr) = _runner.Run(_jwtToolPath, string.Join(" ", args), options.TimeoutSec);
        }
        catch (Exception ex) when (ex is not ScopeException)
        {
            _audit.Record("jwt-fuzz.error", new Dictionary<string, object?>
            {
                ["mode"] = mode,
                ["url"] = targetUrl,
                ["token_digest"] = tokenDigest,
                ["error"] = ex.Message,
            });

            // Binary missing or other failure
            return new JwtFuzzResult
            {
                Target = targetUrl ?? "(offline)",
                ToolName = Name,
                StartedAt = startTime,
                Duration = DateTimeOffset.UtcNow - startTime,
                Vulnerabilities = Array.Empty<JwtVulnerability>(),
                Error = ex is TimeoutException
                    ? $"Timeout after {options.TimeoutSec}s"
                    : ex.Message,
            };
        }

        var duration = DateTimeOffset.UtcNow - startTime;

        _audit.Record("jwt-fuzz.finish", new Dictionary<string, object?>
        {
            ["mode"] = mode,
            ["url"] = targetUrl,
            ["token_digest"] = tokenDigest,
            ["exit_code"] = exitCode,
            ["duration_ms"] = (int)duration.TotalMilliseconds,
        });

        // Check if tool is missing (exit 127 is typical "command not found")
        if (exitCode == 127 || stderr.Contains("command not found") || stderr.Contains("No such file"))
        {
            return new JwtFuzzResult
            {
                Target = targetUrl ?? "(offline)",
                ToolName = Name,
                StartedAt = startTime,
                Duration = duration,
                Vulnerabilities = Array.Empty<JwtVulnerability>(),
                Error = "jwt_tool not found",
            };
        }

        // Parse vulnerabilities from stdout
        var vulns = ParseVulnerabilities(stdout);

        return new JwtFuzzResult
        {
            Target = targetUrl ?? "(offline)",
            ToolName = Name,
            StartedAt = startTime,
            Duration = duration,
            Vulnerabilities = vulns,
            Error = exitCode != 0 && vulns.Count == 0 ? $"Exit {exitCode}: {Tail(stderr, 500)}" : null,
        };
    }

    private static List<JwtVulnerability> ParseVulnerabilities(string output)
    {
        var vulns = new HashSet<JwtVulnerability>();

        // Only consider lines that report a positive finding. jwt_tool output
        // uses `[!] VULNERABILITY FOUND: …` and `[+] … accepted/cracked/…`
        // for confirmed vulns, while `[*] … Test` is a section header and
        // `[-] …` is a negative finding. Section headers can mention every
        // category by name, so naive substring matching on the full output
        // produces false positives.
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimStart();
            if (line.Length == 0) continue;

            var isFinding =
                line.StartsWith("[!]", StringComparison.Ordinal) ||
                (line.StartsWith("[+]", StringComparison.Ordinal) &&
                 (line.Contains("accepted", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("cracked", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("successful", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("vulnerability", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("found", StringComparison.OrdinalIgnoreCase) ||
                  line.Contains("HMAC:", StringComparison.OrdinalIgnoreCase)));

            if (!isFinding) continue;

            var l = line.ToLowerInvariant();

            if (l.Contains("alg=none") || l.Contains("algorithm none") ||
                l.Contains("none alg") || l.Contains("alg:none"))
            {
                vulns.Add(JwtVulnerability.AlgNone);
            }
            if (l.Contains("hmac") &&
                (l.Contains("weak") || l.Contains("cracked") || l.Contains("secret")))
            {
                vulns.Add(JwtVulnerability.WeakHmacSecret);
            }
            if (l.Contains("kid") && (l.Contains("path traversal") || l.Contains("traversal") || l.Contains("../")))
            {
                vulns.Add(JwtVulnerability.KidPathTraversal);
            }
            if (l.Contains("kid") && (l.Contains("sql") || l.Contains("' or") || l.Contains("sqli")))
            {
                vulns.Add(JwtVulnerability.KidSqlInjection);
            }
            if (l.Contains("rs256 to hs256") || l.Contains("rsa to hmac") ||
                l.Contains("key confusion") || l.Contains("algorithm confusion") ||
                l.Contains("public key as secret"))
            {
                vulns.Add(JwtVulnerability.RsaToHsKeyConfusion);
            }
            if (l.Contains("jku") && (l.Contains("inject") || l.Contains("url")))
            {
                vulns.Add(JwtVulnerability.JkuInjection);
            }
            if (l.Contains("x5u") && (l.Contains("inject") || l.Contains("url")))
            {
                vulns.Add(JwtVulnerability.X5uInjection);
            }
        }

        return vulns.ToList();
    }

    private static void ValidateWordlistPath(string path)
    {
        if (path.Contains(".."))
        {
            throw new ArgumentException($"Wordlist path contains path traversal: {path}");
        }

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Wordlist not found: {path}");
        }

        var info = new FileInfo(path);
        if (!info.Attributes.HasFlag(FileAttributes.Normal) &&
            !info.Attributes.HasFlag(FileAttributes.Archive) &&
            info.Attributes.HasFlag(FileAttributes.Directory))
        {
            throw new ArgumentException($"Wordlist must be a regular file: {path}");
        }
    }

    private static string ComputeSha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Tail(string s, int maxLen)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= maxLen ? s : s[^maxLen..];
    }
}

/// <summary>Options for JWT fuzzing campaigns.</summary>
public sealed class JwtFuzzOptions
{
    /// <summary>Path to HMAC secret wordlist for brute force attacks.</summary>
    public string? HmacWordlist { get; init; }

    /// <summary>Attempt RS256-to-HS256 key confusion attacks.</summary>
    public bool TryKeyConfusion { get; init; } = true;

    /// <summary>Attempt KID header injection (path traversal, SQLi).</summary>
    public bool TryKidInjection { get; init; } = true;

    /// <summary>Timeout in seconds for jwt_tool execution.</summary>
    public int TimeoutSec { get; init; } = 300;
}
