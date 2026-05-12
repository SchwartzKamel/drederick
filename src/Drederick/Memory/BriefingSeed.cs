using System.Text.Json.Serialization;

namespace Drederick.Memory;

/// <summary>
/// A single credential parsed from a briefing markdown file. Plaintext
/// passwords are NEVER stored — only the SHA-256 hex digest of the
/// secret is retained. Hashes parsed verbatim from the briefing
/// (NTLM, AES, SHA-*) keep their original byte string under
/// <see cref="SecretSha256"/> (which in that case stores the hash
/// the operator supplied, not a hash-of-hash) and the kind in
/// <see cref="Kind"/>.
/// </summary>
public sealed record BriefingCredential(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("secret_sha256")] string SecretSha256);

/// <summary>
/// Typed, redacted projection of a briefing markdown file consumed by
/// <see cref="BriefingLoader"/> and merged into <see cref="KnowledgeBase"/>
/// via <see cref="KnowledgeBase.MergeFromBriefing"/> before recon starts.
///
/// Targets in the briefing are <b>hints</b>. They do NOT grant scope. Any
/// target that fails <see cref="Drederick.Scope.Scope.Contains"/> is
/// recorded via the <c>briefing.target.out_of_scope</c> audit event by
/// the loader and excluded from this seed; every tool still calls
/// <c>_scope.Require</c> at entry.
/// </summary>
public sealed record BriefingSeed(
    [property: JsonPropertyName("source_path")] string SourcePath,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("targets")] IReadOnlyList<string> Targets,
    [property: JsonPropertyName("users")] IReadOnlyList<string> Users,
    [property: JsonPropertyName("credentials")] IReadOnlyList<BriefingCredential> Credentials,
    [property: JsonPropertyName("constraints")] IReadOnlyList<string> Constraints,
    [property: JsonPropertyName("notes")] string? Notes,
    [property: JsonPropertyName("malformed")] bool Malformed)
{
    public static BriefingSeed Empty(string sourcePath, string sha256) =>
        new(sourcePath, sha256,
            Array.Empty<string>(),
            Array.Empty<string>(),
            Array.Empty<BriefingCredential>(),
            Array.Empty<string>(),
            Notes: null,
            Malformed: false);
}
