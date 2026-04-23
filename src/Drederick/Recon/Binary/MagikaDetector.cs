using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Drederick.Audit;

namespace Drederick.Recon.Binary;

/// <summary>
/// Abstraction for launching the <c>magika</c> subprocess so tests can stub
/// without shelling out. Returns <c>ExitCode == -1</c> when the binary could
/// not be located on <c>PATH</c>.
/// </summary>
public interface IMagikaProcessRunner
{
    /// <summary>
    /// Runs <c>magika</c> with <paramref name="arguments"/> and returns
    /// (ExitCode, StdOut, StdErr). Must return <c>(-1, "", "not-found")</c>
    /// when magika is not installed.
    /// </summary>
    Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(
        string arguments,
        CancellationToken ct);
}

/// <summary>
/// Default <see cref="IMagikaProcessRunner"/> — shells out to <c>magika</c>
/// on <c>PATH</c> via <c>which</c>/direct <c>Process.Start</c>.
/// </summary>
internal sealed class DefaultMagikaProcessRunner : IMagikaProcessRunner
{
    private readonly string? _magikaPath;

    public DefaultMagikaProcessRunner()
    {
        _magikaPath = ResolveOnPath("magika");
    }

    public async Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(string arguments, CancellationToken ct)
    {
        if (_magikaPath is null)
        {
            return (-1, string.Empty, "not-found");
        }

        var psi = new ProcessStartInfo
        {
            FileName = _magikaPath,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi);
        if (p is null) return (-1, string.Empty, "spawn-failed");
        var outTask = p.StandardOutput.ReadToEndAsync(ct);
        var errTask = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct).ConfigureAwait(false);
        return (p.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false));
    }

    private static string? ResolveOnPath(string tool)
    {
        try
        {
            var psi = new ProcessStartInfo("which", tool)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var o = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit();
            return string.IsNullOrEmpty(o) ? null : o;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Structured verdict returned by <see cref="MagikaDetector"/>. Fields map to
/// the union of older (<c>ct_label</c>) and newer (<c>label</c>) magika JSON
/// output shapes; absent fields are null / empty.
/// </summary>
public sealed class MagikaVerdict
{
    /// <summary>Primary content-type label, e.g. <c>elf</c>, <c>zip</c>, <c>pe</c>, <c>python</c>.</summary>
    [JsonPropertyName("label")]
    public string Label { get; init; } = string.Empty;

    /// <summary>Human-readable description, e.g. "ELF executable".</summary>
    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    /// <summary>Content-type group bucket, e.g. <c>executable</c>, <c>archive</c>, <c>code</c>.</summary>
    [JsonPropertyName("group")]
    public string Group { get; init; } = string.Empty;

    /// <summary>MIME type, e.g. <c>application/x-executable</c>.</summary>
    [JsonPropertyName("mime_type")]
    public string MimeType { get; init; } = string.Empty;

    /// <summary>Primary file extension magika associates with this label.</summary>
    [JsonPropertyName("extension")]
    public string Extension { get; init; } = string.Empty;

    /// <summary>Model confidence score in [0, 1]. Zero when missing.</summary>
    [JsonPropertyName("confidence")]
    public double Confidence { get; init; }

    /// <summary>True if magika classified the file as a text type.</summary>
    [JsonPropertyName("is_text")]
    public bool IsText { get; init; }

    /// <summary>Verbatim JSON line magika emitted, for debugging / auditing downstream.</summary>
    [JsonPropertyName("raw_json")]
    public string RawJson { get; init; } = string.Empty;
}

/// <summary>
/// Thin wrapper around the <c>magika</c> CLI (Google's ML-based file-type
/// detector). Used as a fast pre-pass inside <see cref="BinaryAnalyzer"/> and
/// as an optional category hint for the CTF challenge solver.
///
/// Contract:
/// <list type="bullet">
///   <item>Path must be an absolute path under the current working directory
///     — parent escapes and relative paths are rejected before spawning
///     magika.</item>
///   <item>Returns <c>null</c> when magika is unavailable, exits non-zero, or
///     emits unparseable JSON. Never throws except for the path validation
///     <see cref="ArgumentException"/>.</item>
///   <item>Records <c>magika.detect.start</c> / <c>.finish</c> audit events
///     with the file path + SHA-256 of the path string. File contents are
///     never recorded.</item>
///   <item>Emits <c>magika.detect.unavailable</c> at most once per
///     <see cref="MagikaDetector"/> instance so CI logs don't spam.</item>
/// </list>
/// </summary>
public sealed class MagikaDetector
{
    private readonly AuditLog _audit;
    private readonly IMagikaProcessRunner _runner;
    private readonly Func<string> _cwdProvider;
    private int _unavailableLogged;

    public MagikaDetector(AuditLog audit, IMagikaProcessRunner? runner = null, Func<string>? cwdProvider = null)
    {
        _audit = audit;
        _runner = runner ?? new DefaultMagikaProcessRunner();
        _cwdProvider = cwdProvider ?? Directory.GetCurrentDirectory;
    }

    /// <summary>
    /// Classify <paramref name="filePath"/>. Returns null on any failure
    /// mode (magika missing, non-zero exit, garbage JSON, cancellation).
    /// </summary>
    public async Task<MagikaVerdict?> DetectAsync(string filePath, CancellationToken ct = default)
    {
        var validated = ValidatePath(filePath, _cwdProvider());

        var pathDigest = Sha256Hex(validated);
        _audit.Record("magika.detect.start", new Dictionary<string, object?>
        {
            ["file_path"] = validated,
            ["file_path_sha256"] = pathDigest,
        });

        (int exit, string so, string se) result;
        try
        {
            // --jsonl gives one JSON object per line; works on both the
            // Python and Rust CLIs. Quote the path to survive spaces.
            result = await _runner.RunAsync($"--jsonl \"{validated}\"", ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            RecordUnavailableOnce("spawn-failed", ex.Message);
            RecordFinish(validated, pathDigest, "spawn-failed", null);
            return null;
        }

        if (result.exit == -1)
        {
            RecordUnavailableOnce("not-found", result.se);
            RecordFinish(validated, pathDigest, "unavailable", null);
            return null;
        }

        if (result.exit != 0)
        {
            RecordUnavailableOnce($"exit-{result.exit}", Truncate(result.se, 200));
            RecordFinish(validated, pathDigest, $"exit-{result.exit}", null);
            return null;
        }

        var verdict = TryParseVerdict(result.so);
        if (verdict is null)
        {
            RecordUnavailableOnce("unparseable", Truncate(result.so, 200));
            RecordFinish(validated, pathDigest, "unparseable", null);
            return null;
        }

        RecordFinish(validated, pathDigest, "ok", verdict);
        return verdict;
    }

    /// <summary>Validates that <paramref name="filePath"/> is absolute and
    /// lives under <paramref name="cwd"/> (defaults to the process cwd).
    /// Rejects relative paths, parent-escapes, and symlink-style traversal
    /// segments. Returns the normalized full path on success.</summary>
    internal static string ValidatePath(string filePath, string? cwd = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("file path must be non-empty", nameof(filePath));
        if (!Path.IsPathRooted(filePath))
            throw new ArgumentException("file path must be absolute", nameof(filePath));
        // Reject any literal parent-segment in the raw input — even if the
        // final resolved path stays under cwd, `..` in argv is a red flag.
        var segments = filePath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var s in segments)
        {
            if (s == "..")
                throw new ArgumentException("parent-directory segments are not allowed", nameof(filePath));
        }

        var full = Path.GetFullPath(filePath);
        var cwdResolved = Path.GetFullPath(cwd ?? Directory.GetCurrentDirectory());
        // Ensure the resolved path is under cwd. Use trailing separator so
        // "/homework" doesn't match "/home".
        var cwdWithSep = cwdResolved.EndsWith(Path.DirectorySeparatorChar)
            ? cwdResolved
            : cwdResolved + Path.DirectorySeparatorChar;
        if (!string.Equals(full, cwdResolved, StringComparison.Ordinal) &&
            !full.StartsWith(cwdWithSep, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"file path must be under the current working directory ({cwdResolved})",
                nameof(filePath));
        }
        return full;
    }

    private static MagikaVerdict? TryParseVerdict(string stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        // magika may emit multiple objects (directory walk); take the first.
        string firstLine = stdout;
        var nl = stdout.IndexOf('\n');
        if (nl >= 0) firstLine = stdout.Substring(0, nl);
        firstLine = firstLine.Trim();
        if (firstLine.Length == 0) return null;

        try
        {
            using var doc = JsonDocument.Parse(firstLine);
            var root = doc.RootElement;
            // Navigate to the verdict object. Known shapes:
            //   { "path": "...", "result": { "status": "ok",
            //     "value": { "dl": {...}, "output": {...}, "score": 0.99 } } }
            //   { "path": "...", "output": { "ct_label": "...", ... }, "score": 0.99 }  (older)
            JsonElement verdictNode = default;
            double? score = null;
            if (TryGet(root, "result", out var r) &&
                TryGet(r, "value", out var v))
            {
                if (TryGet(v, "output", out var o)) verdictNode = o;
                if (TryGet(v, "score", out var s) && s.ValueKind == JsonValueKind.Number)
                    score = s.GetDouble();
            }
            else if (TryGet(root, "output", out var o2))
            {
                verdictNode = o2;
                if (TryGet(root, "score", out var s2) && s2.ValueKind == JsonValueKind.Number)
                    score = s2.GetDouble();
            }
            else
            {
                verdictNode = root;
            }

            string label = FirstString(verdictNode, "label", "ct_label");
            string description = FirstString(verdictNode, "description");
            string group = FirstString(verdictNode, "group");
            string mime = FirstString(verdictNode, "mime_type");
            string ext = string.Empty;
            if (TryGet(verdictNode, "extensions", out var exts) && exts.ValueKind == JsonValueKind.Array && exts.GetArrayLength() > 0)
            {
                ext = exts[0].GetString() ?? string.Empty;
            }
            else
            {
                ext = FirstString(verdictNode, "extension");
            }
            bool isText = false;
            if (TryGet(verdictNode, "is_text", out var it) && (it.ValueKind == JsonValueKind.True || it.ValueKind == JsonValueKind.False))
                isText = it.GetBoolean();

            if (score is null && TryGet(verdictNode, "score", out var innerScore) && innerScore.ValueKind == JsonValueKind.Number)
                score = innerScore.GetDouble();

            if (string.IsNullOrEmpty(label))
                return null; // unparseable for our purposes

            return new MagikaVerdict
            {
                Label = label,
                Description = description,
                Group = group,
                MimeType = mime,
                Extension = ext,
                Confidence = score ?? 0.0,
                IsText = isText,
                RawJson = firstLine,
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool TryGet(JsonElement el, string name, out JsonElement value)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out value))
            return true;
        value = default;
        return false;
    }

    private static string FirstString(JsonElement el, params string[] names)
    {
        foreach (var n in names)
        {
            if (TryGet(el, n, out var v) && v.ValueKind == JsonValueKind.String)
            {
                var s = v.GetString();
                if (!string.IsNullOrEmpty(s)) return s;
            }
        }
        return string.Empty;
    }

    private void RecordUnavailableOnce(string reason, string detail)
    {
        if (Interlocked.Exchange(ref _unavailableLogged, 1) == 0)
        {
            _audit.Record("magika.detect.unavailable", new Dictionary<string, object?>
            {
                ["reason"] = reason,
                ["detail"] = Truncate(detail ?? string.Empty, 200),
            });
        }
    }

    private void RecordFinish(string path, string pathDigest, string status, MagikaVerdict? v)
    {
        _audit.Record("magika.detect.finish", new Dictionary<string, object?>
        {
            ["file_path"] = path,
            ["file_path_sha256"] = pathDigest,
            ["status"] = status,
            ["label"] = v?.Label,
            ["group"] = v?.Group,
            ["confidence"] = v?.Confidence,
        });
    }

    private static string Sha256Hex(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Truncate(string s, int max)
        => string.IsNullOrEmpty(s) || s.Length <= max ? s : s.Substring(0, max) + "…";
}
