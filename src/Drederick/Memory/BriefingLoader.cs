using System.Security.Cryptography;
using System.Text;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Memory;

/// <summary>
/// Loads an operator-supplied briefing markdown file and produces a
/// redacted <see cref="BriefingSeed"/> that <see cref="KnowledgeBase"/>
/// merges before recon starts (GAP-049 supplement).
///
/// <para><b>Invariants.</b></para>
/// <list type="bullet">
///   <item>Briefing input does NOT grant scope. Any target string in
///   the briefing is checked with <see cref="Scope.Contains"/>; targets
///   outside the operator's scope file are recorded as
///   <c>briefing.target.out_of_scope</c> audit events and excluded
///   from the seed. Every downstream tool still re-checks scope.</item>
///   <item>Plaintext passwords are never stored anywhere. The SHA-256
///   hex digest of the password is recorded on
///   <see cref="BriefingCredential.SecretSha256"/>. Pre-existing hashes
///   (NTLM / AES / SHA-*) are stored verbatim as the operator supplied
///   them — those are hashes already.</item>
///   <item>Path traversal / argv injection on <c>--briefing</c> is
///   rejected before the file is opened (null bytes, newlines).</item>
///   <item>Best-effort parse on malformed input: bad sections are
///   skipped, the seed is flagged <see cref="BriefingSeed.Malformed"/>,
///   and <c>briefing.malformed</c> is recorded.</item>
/// </list>
/// </summary>
public static class BriefingLoader
{
    /// <summary>
    /// Resolve, read, parse, and audit a briefing file. Returns an
    /// empty seed when the file cannot be opened — the caller should
    /// still merge it (the seed records the source path and SHA so the
    /// run reproduces the operator's intent).
    /// </summary>
    public static BriefingSeed Load(string path, Scope.Scope scope, AuditLog audit)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);

        var safePath = ValidatePath(path);
        if (safePath is null)
        {
            audit.Record("briefing.error", new Dictionary<string, object?>
            {
                ["path"] = path,
                ["reason"] = "path_rejected",
            });
            return BriefingSeed.Empty(path ?? "", "");
        }

        if (!File.Exists(safePath))
        {
            audit.Record("briefing.error", new Dictionary<string, object?>
            {
                ["path"] = safePath,
                ["reason"] = "not_found",
            });
            return BriefingSeed.Empty(safePath, "");
        }

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(safePath);
        }
        catch (Exception ex)
        {
            audit.Record("briefing.error", new Dictionary<string, object?>
            {
                ["path"] = safePath,
                ["reason"] = "read_failed",
                ["error"] = ex.GetType().Name,
            });
            return BriefingSeed.Empty(safePath, "");
        }

        var sha = Sha256Hex(bytes);
        audit.Record("briefing.loaded", new Dictionary<string, object?>
        {
            ["path"] = safePath,
            ["sha256"] = sha,
            ["bytes"] = bytes.Length,
        });

        var text = Encoding.UTF8.GetString(bytes);
        return Parse(text, safePath, sha, scope, audit);
    }

    /// <summary>
    /// Parse a briefing markdown buffer without touching the filesystem.
    /// Exposed for unit tests; the file-based <see cref="Load"/> path
    /// hashes contents and delegates here.
    /// </summary>
    public static BriefingSeed Parse(
        string markdown,
        string sourcePath,
        string sha256,
        Scope.Scope scope,
        AuditLog audit)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(audit);

        bool malformed = false;
        IReadOnlyList<string> rawTargets = Array.Empty<string>();
        IReadOnlyList<string> users = Array.Empty<string>();
        IReadOnlyList<BriefingMarkdownExtractors.RawCredential> rawCreds =
            Array.Empty<BriefingMarkdownExtractors.RawCredential>();
        IReadOnlyList<string> constraints = Array.Empty<string>();
        string? notes = null;

        IReadOnlyDictionary<string, IReadOnlyList<string>> sections;
        try
        {
            sections = BriefingMarkdownExtractors.SplitSections(markdown);
        }
        catch
        {
            malformed = true;
            sections = new Dictionary<string, IReadOnlyList<string>>();
        }

        rawTargets = TrySection(sections, "Targets",
            BriefingMarkdownExtractors.ExtractTargets, ref malformed);
        users = TrySection(sections, "Users",
            BriefingMarkdownExtractors.ExtractUsers, ref malformed);
        rawCreds = TrySection(sections, "Credentials",
            BriefingMarkdownExtractors.ExtractCredentials, ref malformed);
        constraints = TrySection(sections, "Constraints",
            BriefingMarkdownExtractors.ExtractConstraints, ref malformed);
        notes = TrySection<string?>(sections, "Notes",
            BriefingMarkdownExtractors.ExtractNotes, ref malformed);

        // Scope check on every target hint. Out-of-scope targets are
        // recorded but never authorized.
        var keptTargets = new List<string>();
        foreach (var t in rawTargets)
        {
            if (scope.Contains(t))
            {
                keptTargets.Add(t);
            }
            else
            {
                audit.Record("briefing.target.out_of_scope", new Dictionary<string, object?>
                {
                    ["path"] = sourcePath,
                    ["target"] = t,
                    ["scope_source"] = scope.Source,
                });
            }
        }

        // Hash plaintext passwords; leave pre-existing hashes verbatim.
        var creds = new List<BriefingCredential>(rawCreds.Count);
        foreach (var rc in rawCreds)
        {
            string stored;
            if (rc.Kind == "password")
            {
                stored = Sha256Hex(Encoding.UTF8.GetBytes(rc.Secret));
            }
            else
            {
                stored = rc.Secret;
            }
            creds.Add(new BriefingCredential(rc.Username, rc.Kind, stored));
        }

        var seed = new BriefingSeed(
            sourcePath,
            sha256,
            keptTargets,
            users,
            creds,
            constraints,
            notes,
            malformed);

        audit.Record("briefing.parsed", new Dictionary<string, object?>
        {
            ["path"] = sourcePath,
            ["sha256"] = sha256,
            ["target_count"] = keptTargets.Count,
            ["target_skipped"] = rawTargets.Count - keptTargets.Count,
            ["user_count"] = users.Count,
            ["cred_count"] = creds.Count,
            ["constraint_count"] = constraints.Count,
            ["has_notes"] = notes is not null,
            ["malformed"] = malformed,
            ["redacted"] = "plaintext_passwords_sha256",
        });

        if (malformed)
        {
            audit.Record("briefing.malformed", new Dictionary<string, object?>
            {
                ["path"] = sourcePath,
                ["sha256"] = sha256,
            });
        }

        return seed;
    }

    private static T TrySection<T>(
        IReadOnlyDictionary<string, IReadOnlyList<string>> sections,
        string name,
        Func<IReadOnlyList<string>, T> extractor,
        ref bool malformed)
    {
        if (!sections.TryGetValue(name, out var lines))
        {
            return extractor(Array.Empty<string>());
        }
        try
        {
            return extractor(lines);
        }
        catch
        {
            malformed = true;
            return extractor(Array.Empty<string>());
        }
    }

    /// <summary>
    /// Reject paths with null bytes, embedded newlines, or empty/whitespace
    /// content. Returns the canonical full path on success, <c>null</c>
    /// on rejection.
    /// </summary>
    private static string? ValidatePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        if (path.IndexOf('\0') >= 0) return null;
        if (path.IndexOf('\n') >= 0 || path.IndexOf('\r') >= 0) return null;
        try
        {
            return Path.GetFullPath(path);
        }
        catch
        {
            return null;
        }
    }

    private static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
