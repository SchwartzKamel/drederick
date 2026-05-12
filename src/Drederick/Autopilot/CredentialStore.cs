using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Drederick.Audit;

namespace Drederick.Autopilot;

/// <summary>
/// Thread-safe store of captured / operator-supplied credentials and a
/// matrix of attempted (host, service, user, password_sha256) tuples. The
/// black book of sparring partners in the Tatum corner: every newly
/// discovered service re-queries this store to decide which creds are worth
/// trying, and every spray outcome updates the matrix so lockouts and retry
/// storms are avoided.
///
/// Invariants:
///   • Plaintext never leaves the locker room (not logged, not written to
///     disk).
///   • Only <see cref="CredentialRef"/> (with SHA-256) crosses public APIs.
///   • Callers who need to actually throw the punch go through
///     <see cref="TryGetSecret"/> which returns the secret in-memory and
///     records the retrieval to <see cref="AuditLog"/>.
/// </summary>
public sealed class CredentialStore
{
    private readonly AuditLog _audit;

    // (realm|user) → plaintext. Lowercased realm/user to dedup case variants.
    private readonly ConcurrentDictionary<string, string> _secrets = new();

    // (host, service, realm|user, pwdSha) → attempt record. Presence = attempted.
    private readonly ConcurrentDictionary<string, AttemptRecord> _attempts = new();

    public CredentialStore(AuditLog audit) { _audit = audit; }

    /// <summary>Number of distinct credentials currently known.</summary>
    public int Count => _secrets.Count;

    /// <summary>
    /// Register a credential. Idempotent — re-adding the same tuple with the
    /// same password is a no-op. Returns true if this is a genuinely new
    /// (realm, user, password) combination.
    /// </summary>
    public bool Add(string user, string password, string? realm = null, string source = "operator")
    {
        if (string.IsNullOrWhiteSpace(user) || password is null)
            throw new ArgumentException("user+password required");
        var key = Key(realm, user);
        var added = _secrets.TryAdd(key, password);
        if (added)
        {
            _audit.Record("autopilot.cred.added", new Dictionary<string, object?>
            {
                ["user"] = user,
                ["realm"] = realm,
                ["password_sha256"] = Sha256Hex(password),
                ["source"] = source,
                ["total"] = _secrets.Count,
            });
        }
        return added;
    }

    /// <summary>Iterate over all known credentials as non-secret refs.</summary>
    public IReadOnlyList<CredentialRef> List()
    {
        var list = new List<CredentialRef>(_secrets.Count);
        foreach (var kv in _secrets)
        {
            var (realm, user) = SplitKey(kv.Key);
            list.Add(new CredentialRef
            {
                User = user,
                Realm = realm,
                PasswordSha256 = Sha256Hex(kv.Value),
            });
        }
        return list;
    }

    /// <summary>
    /// Check whether <c>(host, service, user, password_sha)</c> has already
    /// been attempted this run. Used by the planner to avoid duplicate spray
    /// actions against the same tuple.
    /// </summary>
    public bool HasAttempted(string host, string service, CredentialRef cred)
    {
        return _attempts.ContainsKey(AttemptKey(host, service, cred));
    }

    /// <summary>Record the outcome of a credential attempt. Idempotent on key.</summary>
    public void RecordAttempt(string host, string service, CredentialRef cred, bool succeeded)
    {
        var key = AttemptKey(host, service, cred);
        _attempts[key] = new AttemptRecord(host, service, cred, succeeded, DateTimeOffset.UtcNow);
        _audit.Record("autopilot.cred.attempt", new Dictionary<string, object?>
        {
            ["host"] = host,
            ["service"] = service,
            ["user"] = cred.User,
            ["realm"] = cred.Realm,
            ["password_sha256"] = cred.PasswordSha256,
            ["succeeded"] = succeeded,
        });
    }

    /// <summary>
    /// Look up the plaintext for a <see cref="CredentialRef"/>. Returns null
    /// if the ref points at a secret we do not hold. Records a retrieval event
    /// to the audit log (without the plaintext) so the operator can correlate.
    /// </summary>
    public string? TryGetSecret(CredentialRef cred)
    {
        if (cred is null) return null;
        if (!_secrets.TryGetValue(Key(cred.Realm, cred.User), out var pwd))
            return null;
        // Defence in depth: verify the stored secret still hashes to what the
        // caller referenced. Guards against a store mutation mid-run.
        if (!string.Equals(Sha256Hex(pwd), cred.PasswordSha256, StringComparison.OrdinalIgnoreCase))
            return null;
        _audit.Record("autopilot.cred.retrieve", new Dictionary<string, object?>
        {
            ["user"] = cred.User,
            ["realm"] = cred.Realm,
            ["password_sha256"] = cred.PasswordSha256,
        });
        return pwd;
    }

    /// <summary>Seed the store with a built-in, conservative default list.
    /// Used by autopilot when <c>--autopilot-default-creds</c> is set and the
    /// operator has not provided their own wordlist. Kept very small on purpose
    /// — the goal is a credible lab-grade spray, not an offline crack.</summary>
    public int SeedDefaultLab()
    {
        var pairs = new (string user, string pwd, string? realm)[]
        {
            ("administrator", "P@ssw0rd!", null),
            ("administrator", "Password1", null),
            ("admin", "admin", null),
            ("admin", "password", null),
            ("root", "root", null),
            ("root", "toor", null),
            ("guest", "guest", null),
            ("user", "user", null),
        };
        int added = 0;
        foreach (var (u, p, r) in pairs) if (Add(u, p, r, source: "lab-default")) added++;
        return added;
    }

    internal static string Key(string? realm, string user)
        => ((realm ?? "").ToLowerInvariant()) + "|" + user.ToLowerInvariant();

    internal static (string? realm, string user) SplitKey(string key)
    {
        var idx = key.IndexOf('|');
        var r = idx <= 0 ? null : key[..idx];
        var u = idx < 0 ? key : key[(idx + 1)..];
        return (string.IsNullOrEmpty(r) ? null : r, u);
    }

    internal static string AttemptKey(string host, string service, CredentialRef cred)
        => $"{host}|{service.ToLowerInvariant()}|{Key(cred.Realm, cred.User)}|{cred.PasswordSha256}";

    public static string Sha256Hex(string s)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(s ?? ""));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // --- htb-ssh-key-passphrase-crack ---
    /// <summary>
    /// GAP-038 — record an SSH private-key passphrase recovered by
    /// <see cref="Drederick.Exploit.Cred.SshKeyCracker"/>. Stored in the
    /// same secrets map as every other captured credential; the "user"
    /// slot is the key id (typically the looted filename, e.g.
    /// <c>id_rsa</c>) and the "realm" is the fixed sentinel
    /// <c>ssh-key</c> so the autopilot chooser can distinguish
    /// key-passphrases from interactive account passwords. NEVER logs
    /// the plaintext — only its SHA-256.
    /// </summary>
    public bool AddSshKeyPassphrase(string keyId, string passphrase, string source = "ssh-key-crack")
    {
        if (string.IsNullOrWhiteSpace(keyId))
            throw new ArgumentException("keyId required", nameof(keyId));
        if (passphrase is null)
            throw new ArgumentException("passphrase required", nameof(passphrase));
        const string realm = "ssh-key";
        var key = Key(realm, keyId);
        var added = _secrets.TryAdd(key, passphrase);
        if (added)
        {
            _audit.Record("autopilot.cred.sshkey_passphrase", new Dictionary<string, object?>
            {
                ["key_id"] = keyId,
                ["realm"] = realm,
                ["passphrase_sha256"] = Sha256Hex(passphrase),
                ["source"] = source,
                ["total"] = _secrets.Count,
            });
        }
        return added;
    }
    // --- end htb-ssh-key-passphrase-crack ---
}

internal sealed record AttemptRecord(
    string Host, string Service, CredentialRef Cred, bool Succeeded, DateTimeOffset At);
