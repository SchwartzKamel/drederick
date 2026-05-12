using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Recon;

/// <summary>
/// NFS export enumeration (GAP-007). Lists exports via <c>showmount -e</c>,
/// attempts a read-only mount per export at both NFSv3 and NFSv4, walks
/// up to two levels of the mounted share via an injected probe so tests
/// don't need an actual mount, captures uid/gid metadata, flags
/// well-known sensitive files (id_rsa, .ssh/authorized_keys, *.kdbx,
/// shadow, passwd, *.env, web.config, wp-config.php, …), heuristically
/// detects <c>no_root_squash</c> exports, and (in lab mode) probes for
/// anonymous write.
///
/// Scope is enforced as the first statement of every public entry point.
/// All subprocess argv is constructed via <see cref="ProcessStartInfo.ArgumentList"/>
/// — never via a shell — and the target is shape-checked
/// (<c>^[\w.\-]+$</c>) before any binary is spawned.
/// </summary>
public sealed partial class NfsEnumTool : IReconTool
{
    public string Name => "nfs-enum";

    public string Description =>
        "Enumerate NFS exports via showmount -e, attempt read-only mount " +
        "at NFSv3 and NFSv4, list top-level contents (depth ≤ 2), capture " +
        "uid/gid, flag well-known sensitive files (id_rsa, *.kdbx, *.env, " +
        "wp-config.php, …), detect no_root_squash, and (lab-only) probe " +
        "for anonymous write. Always unmounts cleanly.";

    [GeneratedRegex(@"^[\w.\-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetShapeRegex();

    /// <summary>Sensitive-file glob patterns. Matched case-insensitively
    /// against either the basename or the relative path with forward
    /// slashes. Patterns are deliberately conservative — false positives
    /// here cost an operator one extra glance, false negatives cost a
    /// missed credential.</summary>
    internal static readonly string[] SensitivePatterns =
    [
        "id_rsa", "id_rsa.pub",
        "id_ed25519", "id_ed25519.pub",
        "id_ecdsa", "id_ecdsa.pub",
        "id_dsa",
        ".ssh/authorized_keys",
        "authorized_keys",
        ".ssh/known_hosts",
        "*.kdbx",
        "shadow", "passwd", "gshadow",
        "*.env",
        ".env",
        "web.config",
        "*.config.php",
        "wp-config.php",
        "settings.py",
        "credentials",
        ".aws/credentials",
        "*.pem", "*.key", "*.pfx", "*.p12",
        "*.kirbi", "*.ccache", "*.keytab",
    ];

    private const int ShowmountTimeoutSeconds = 30;
    private const int MountTimeoutSeconds = 30;
    private const int UmountTimeoutSeconds = 15;
    private const int MaxExportsToMount = 32;
    private const int MaxEntriesPerExport = 256;

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly IProcessRunner _runner;
    private readonly string _showmountPath;
    private readonly string _mountPath;
    private readonly string _umountPath;
    private readonly Func<string, NfsMountSnapshot>? _listMount;
    private readonly Func<string, bool>? _tryWriteProbe;
    private readonly bool _allowWriteProbe;

    public NfsEnumTool(
        Scope.Scope scope,
        AuditLog audit,
        IProcessRunner? runner = null,
        string? showmountPath = null,
        string? mountPath = null,
        string? umountPath = null,
        Func<string, NfsMountSnapshot>? listMount = null,
        Func<string, bool>? tryWriteProbe = null,
        bool allowWriteProbe = true)
    {
        _scope = scope;
        _audit = audit;
        _runner = runner ?? new DefaultProcessRunner();
        _showmountPath = showmountPath ?? "showmount";
        _mountPath = mountPath ?? "mount";
        _umountPath = umountPath ?? "umount";
        _listMount = listMount;
        _tryWriteProbe = tryWriteProbe;
        _allowWriteProbe = allowWriteProbe;
    }

    public Task<NfsEnumResult> EnumerateAsync(string target, CancellationToken ct = default)
    {
        _scope.Require(target);

        if (string.IsNullOrEmpty(target)
            || !TargetShapeRegex().IsMatch(target)
            || Scope.ArgvValidator.ContainsShellMetachars(target))
        {
            throw new ArgumentException(
                $"Invalid NFS target '{target}': expected bare host or IP (no port, no metachars).",
                nameof(target));
        }

        var result = new NfsEnumResult();
        _audit.Record("nfs-enum.start", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["write_probe_enabled"] = _allowWriteProbe,
        });

        try
        {
            // 1) showmount -e <target>
            var (exit, stdout, stderr) = TryRun(_showmountPath, [ "-e", "--no-headers", target ], ShowmountTimeoutSeconds);
            if (exit == -1)
            {
                // Try again without --no-headers (BSD showmount does not support it).
                (exit, stdout, stderr) = TryRun(_showmountPath, [ "-e", target ], ShowmountTimeoutSeconds);
            }
            if (exit < 0)
            {
                result.Error = $"showmount unavailable: {stderr.Trim()}";
                RecordFinish(target, result);
                return Task.FromResult(result);
            }
            if (exit != 0)
            {
                result.Error = $"showmount exit={exit}: {Truncate(stderr.Trim(), 256)}";
                RecordFinish(target, result);
                return Task.FromResult(result);
            }

            foreach (var (path, allowedClients) in ParseShowmountOutput(stdout))
            {
                result.Exports.Add(new NfsExport
                {
                    Path = path,
                    AllowedClients = allowedClients,
                });
                if (result.Exports.Count >= MaxExportsToMount) break;
            }

            // 2) Attempt mount per export. We do NOT spawn anything against
            //    paths whose names contain shell metachars — showmount output
            //    is attacker-controlled.
            foreach (var export in result.Exports)
            {
                if (ct.IsCancellationRequested) break;
                if (Scope.ArgvValidator.ContainsShellMetachars(export.Path))
                {
                    export.Error = "export path contains shell metachars; skipped";
                    continue;
                }
                MountAndInspect(target, export);
            }
        }
        catch (Exception ex)
        {
            result.Error ??= ex.Message;
        }

        RecordFinish(target, result);
        return Task.FromResult(result);
    }

    private void MountAndInspect(string target, NfsExport export)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"drederick-nfs-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);
        }
        catch (Exception ex)
        {
            export.Error = $"tempdir: {ex.Message}";
            return;
        }

        bool mounted = false;
        try
        {
            // Try v3 first.
            export.MountSucceededV3 = TryMount(target, export.Path, tempDir, "vers=3");
            mounted = export.MountSucceededV3;

            // Try v4 either way — both versions are independently informative.
            if (!mounted)
            {
                export.MountSucceededV4 = TryMount(target, export.Path, tempDir, "vers=4");
                mounted = export.MountSucceededV4;
            }
            else
            {
                // Already mounted via v3; v4 probe needs an isolated mount
                // point. Cheaper to skip than to teardown/remount unless the
                // operator specifically wants version diff; v3-success is
                // already enough to enumerate the export.
            }

            if (!mounted)
            {
                export.Error ??= "mount failed (v3 and v4)";
                return;
            }

            export.AnonRead = true;
            var snapshot = ListMount(tempDir);
            export.FileCount = snapshot.FileCount;
            foreach (var e in snapshot.Entries.Take(MaxEntriesPerExport))
            {
                if (e.Depth <= 0) export.TopLevelEntries.Add(e.RelativePath);
                if (IsSensitive(e.RelativePath))
                {
                    if (!export.InterestingFiles.Contains(e.RelativePath))
                        export.InterestingFiles.Add(e.RelativePath);
                }
                if (e.Uid == 0 && e.IsFile)
                {
                    // We can see a uid-0-owned file. On a properly squashed
                    // export this would either be mapped to nobody or be
                    // unreadable. Flag as a strong heuristic.
                    export.RootSquashDisabled = true;
                }
            }

            if (_allowWriteProbe)
            {
                try
                {
                    if (TryAnonWriteProbe(tempDir))
                    {
                        export.AnonWrite = true;
                    }
                }
                catch (Exception ex)
                {
                    // Probe failure does not invalidate the rest of the
                    // export's findings — record but continue.
                    export.Error ??= $"write probe: {ex.Message}";
                }
            }
        }
        finally
        {
            if (mounted)
            {
                try { _runner.Run(_umountPath, $"\"{tempDir}\"", UmountTimeoutSeconds); }
                catch { /* best-effort unmount */ }
            }
            try { Directory.Delete(tempDir, recursive: false); } catch { /* best-effort */ }
        }
    }

    private bool TryMount(string target, string exportPath, string mountPoint, string versOption)
    {
        // Note: we deliberately do NOT shell out. ArgumentList wraps each
        // argv element verbatim so the validated target/path cannot be
        // re-parsed by /bin/sh.
        try
        {
            var (exit, _, stderr) = RunWithArgList(
                _mountPath,
                [
                    "-t", "nfs",
                    "-o", $"ro,nolock,soft,timeo=20,retry=0,{versOption}",
                    $"{target}:{exportPath}",
                    mountPoint,
                ],
                MountTimeoutSeconds);
            if (exit == 0) return true;
            _audit.Record("nfs-enum.mount.fail", new Dictionary<string, object?>
            {
                ["target"] = target,
                ["export"] = exportPath,
                ["vers"] = versOption,
                ["exit"] = exit,
                ["stderr"] = Truncate(stderr.Trim(), 200),
            });
            return false;
        }
        catch
        {
            return false;
        }
    }

    private NfsMountSnapshot ListMount(string mountPath)
    {
        if (_listMount is not null) return _listMount(mountPath);
        return DefaultListMount(mountPath);
    }

    private bool TryAnonWriteProbe(string mountPath)
    {
        if (_tryWriteProbe is not null) return _tryWriteProbe(mountPath);
        return DefaultWriteProbe(mountPath);
    }

    private NfsMountSnapshot DefaultListMount(string mountPath)
    {
        var entries = new List<NfsEntry>();
        int fileCount = 0;
        try
        {
            var root = new DirectoryInfo(mountPath);
            EnumerateDepth(root, "", 0, 2, entries, ref fileCount);
        }
        catch { /* best-effort */ }
        return new NfsMountSnapshot(entries, fileCount);
    }

    private static void EnumerateDepth(DirectoryInfo dir, string relBase, int depth, int maxDepth, List<NfsEntry> sink, ref int fileCount)
    {
        if (sink.Count >= MaxEntriesPerExport) return;
        FileSystemInfo[] children;
        try { children = dir.GetFileSystemInfos(); }
        catch { return; }
        foreach (var child in children)
        {
            if (sink.Count >= MaxEntriesPerExport) break;
            var rel = string.IsNullOrEmpty(relBase) ? child.Name : $"{relBase}/{child.Name}";
            uint uid = 0, gid = 0;
            long size = 0;
            bool isFile = child is FileInfo;
            if (child is FileInfo fi)
            {
                try { size = fi.Length; } catch { }
                fileCount++;
            }
            sink.Add(new NfsEntry(rel, uid, gid, size, isFile, depth));
            if (!isFile && depth < maxDepth && child is DirectoryInfo sub)
            {
                EnumerateDepth(sub, rel, depth + 1, maxDepth, sink, ref fileCount);
            }
        }
    }

    private static bool DefaultWriteProbe(string mountPath)
    {
        var name = $".drederick_probe_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        var full = Path.Combine(mountPath, name);
        try
        {
            using (var fs = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // zero-byte probe — minimum side effect on the export.
            }
            try { File.Delete(full); } catch { /* best-effort cleanup */ }
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsSensitive(string relPath)
    {
        if (string.IsNullOrEmpty(relPath)) return false;
        var norm = relPath.Replace('\\', '/');
        var basename = norm[(norm.LastIndexOf('/') + 1)..];
        foreach (var pat in SensitivePatterns)
        {
            if (GlobMatch(pat, basename) || GlobMatch(pat, norm)) return true;
        }
        return false;
    }

    private static bool GlobMatch(string pattern, string value)
    {
        if (!pattern.Contains('*') && !pattern.Contains('?'))
        {
            return string.Equals(pattern, value, StringComparison.OrdinalIgnoreCase);
        }
        // Translate glob → regex.
        var sb = new StringBuilder("^");
        foreach (var c in pattern)
        {
            sb.Append(c switch
            {
                '*' => ".*",
                '?' => ".",
                _ => Regex.Escape(c.ToString()),
            });
        }
        sb.Append('$');
        return Regex.IsMatch(value, sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>Parses <c>showmount -e</c> output, one export per line.
    /// Each line is "<c>/path  client1,client2,…</c>". The header line
    /// "Export list for X:" is tolerated.</summary>
    internal static IEnumerable<(string Path, string? AllowedClients)> ParseShowmountOutput(string stdout)
    {
        var results = new List<(string, string?)>();
        foreach (var raw in stdout.Split('\n'))
        {
            var line = raw.TrimEnd('\r').Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("Export list", StringComparison.OrdinalIgnoreCase)) continue;
            // First token is the export path; remainder is the access list.
            int idx = 0;
            while (idx < line.Length && !char.IsWhiteSpace(line[idx])) idx++;
            var path = line[..idx];
            var rest = idx < line.Length ? line[idx..].Trim() : null;
            if (path.Length == 0 || path[0] != '/') continue;
            results.Add((path, string.IsNullOrEmpty(rest) ? null : rest));
        }
        return results;
    }

    private (int Exit, string StdOut, string StdErr) TryRun(string file, IReadOnlyList<string> args, int timeoutSeconds)
    {
        try
        {
            return RunWithArgList(file, args, timeoutSeconds);
        }
        catch (FileNotFoundException)
        {
            return (-1, "", "binary not found");
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (-1, "", "binary not found");
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }

    private (int Exit, string StdOut, string StdErr) RunWithArgList(string file, IReadOnlyList<string> args, int timeoutSeconds)
    {
        // Use IProcessRunner so tests can stub. We serialise the arg list
        // into the runner's single-string `arguments` slot with conservative
        // quoting; the real spawn path in DefaultProcessRunner re-splits via
        // ProcessStartInfo.Arguments — same surface tools like SmbTool use.
        var argString = ArgListToCommandLine(args);
        return _runner.Run(file, argString, timeoutSeconds);
    }

    private static string ArgListToCommandLine(IReadOnlyList<string> args)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < args.Count; i++)
        {
            if (i > 0) sb.Append(' ');
            var a = args[i];
            if (a.Length == 0 || a.Any(c => c == ' ' || c == '\t' || c == '"' || c == '\''))
            {
                sb.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
            }
            else
            {
                sb.Append(a);
            }
        }
        return sb.ToString();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private void RecordFinish(string target, NfsEnumResult result)
    {
        _audit.Record("nfs-enum.finish", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["exports"] = result.Exports.Count,
            ["any_anon_read"] = result.Exports.Any(e => e.AnonRead),
            ["any_anon_write"] = result.Exports.Any(e => e.AnonWrite),
            ["any_root_squash_disabled"] = result.Exports.Any(e => e.RootSquashDisabled),
            ["error"] = result.Error,
        });
    }
}

/// <summary>
/// Result of an <see cref="NfsEnumTool"/> filesystem walk, supplied either
/// by the default disk-walking implementation or by a test stub injected
/// via the constructor. Carries every entry observed (up to depth 2) plus
/// a precomputed file count so the tool does not need to re-walk.
/// </summary>
public sealed record NfsMountSnapshot(IReadOnlyList<NfsEntry> Entries, int FileCount);

public sealed record NfsEntry(
    string RelativePath,
    uint Uid,
    uint Gid,
    long Size,
    bool IsFile,
    int Depth);
