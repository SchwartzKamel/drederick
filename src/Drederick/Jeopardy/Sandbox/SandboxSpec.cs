using System.Collections.Generic;

namespace Drederick.Jeopardy.Sandbox;

/// <summary>
/// Declarative configuration for a single CTF challenge sandbox. The harness
/// owns the image build; the spec is what the solver runtime passes per
/// challenge. <see cref="ConnectionInfo"/> is the only field that interacts
/// with <see cref="Drederick.Scope.Scope"/>: when set, the remote host it
/// references must be in scope before network access is granted.
/// </summary>
public sealed record SandboxSpec(
    string ImageName,
    int ChallengeId,
    string ChallengeName,
    string Category,
    IReadOnlyDictionary<string, byte[]>? AttachmentsByFilename,
    TimeSpan Timeout,
    long MemoryBytesCap,
    int CpuShares,
    bool Privileged,
    string? ConnectionInfo)
{
    public const string DefaultImage = "drederick-jeopardy-sandbox:latest";
    public static TimeSpan DefaultTimeout { get; } = TimeSpan.FromMinutes(20);
    public const long DefaultMemoryBytesCap = 4L * 1024L * 1024L * 1024L;
    public const int DefaultCpuShares = 1024;

    /// <summary>Convenience factory for the common case.</summary>
    public static SandboxSpec ForChallenge(
        int challengeId,
        string challengeName,
        string category,
        IReadOnlyDictionary<string, byte[]>? attachments = null,
        string? connectionInfo = null,
        TimeSpan? timeout = null)
        => new(
            ImageName: DefaultImage,
            ChallengeId: challengeId,
            ChallengeName: challengeName,
            Category: category,
            AttachmentsByFilename: attachments,
            Timeout: timeout ?? DefaultTimeout,
            MemoryBytesCap: DefaultMemoryBytesCap,
            CpuShares: DefaultCpuShares,
            Privileged: false,
            ConnectionInfo: connectionInfo);
}

/// <summary>
/// Bounded result from <see cref="ISandboxSession.ExecAsync"/>. Stdout/stderr
/// are truncated to 256 KiB to avoid unbounded memory growth on chatty
/// commands. Full-size SHA-256 is recorded in the audit log.
/// </summary>
public sealed record SandboxExecResult(
    int ExitCode,
    string Stdout,
    string Stderr,
    TimeSpan Elapsed,
    bool TimedOut);
