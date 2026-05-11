namespace Drederick.Reporting;

/// <summary>
/// Provenance of a candidate flag string, ordered by descending trust.
/// Highest-trust sources accept ambiguous (bare-hex) candidates at high
/// confidence; lowest-trust sources mostly only accept explicit markers.
///
/// Used by <see cref="FlagDetector"/> to score detections and gate
/// false-positives (GAP-008/GAP-009).
/// </summary>
public enum FlagSource
{
    /// <summary>String already wears a CTF marker prefix (HTB{, flag{, ...).</summary>
    ExplicitFlagMarker = 0,
    /// <summary>Read from a canonical flag file under a user home (/root/root.txt, /home/*/user.txt).</summary>
    UserHomeFile = 1,
    /// <summary>Captured stdout/stderr of a spawned shell command.</summary>
    ShellCommandOutput = 2,
    /// <summary>Generic file content (not a known flag file).</summary>
    FileSystemContent = 3,
    /// <summary>HTTP body, SMB share content, or other network-service payload.</summary>
    NetworkServiceResponse = 4,
    /// <summary>Scanner banner / NSE output / version string — almost always noise.</summary>
    ScanMetadata = 5,
}
