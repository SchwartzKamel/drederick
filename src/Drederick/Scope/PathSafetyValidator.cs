namespace Drederick.Scope;

/// <summary>
/// Path-safety validator that closes the symlink-escape gap left by a
/// naive <see cref="Path.GetFullPath(string)"/>+<c>StartsWith</c> check.
///
/// The check <c>fullPath.StartsWith(workdir)</c> only matches the literal
/// path string; it does not resolve symlinks. An operator-controlled
/// symlink at <c>&lt;workdir&gt;/safe.iL</c> pointing at <c>/etc/passwd</c>
/// passes the prefix check but reads outside the workdir at use time. The
/// validator here resolves the symlink chain to its final target via
/// <see cref="FileInfo.ResolveLinkTarget(bool)"/> with
/// <c>returnFinalTarget: true</c> and re-checks the resolved path.
///
/// Same pattern as <c>DbPillageTool.ResolveSafePath</c> (29e48ed); shared
/// here so every -i*-style flag in <see cref="LlmExecShellTool"/> can use
/// it.
///
/// Note (residual TOCTOU). <see cref="File.ResolveLinkTarget(string,bool)"/>
/// does not return an open file descriptor, so a concurrent rename of the
/// symlink between resolve and read remains theoretically observable. The
/// primary defense for the LLM exec-shell -iL path is the sanitized-copy
/// rewrite (Fix 1) which routes nmap through a single-writer file in the
/// per-spawn workdir; this validator is the belt-and-suspenders layer.
/// </summary>
public static class PathSafetyValidator
{
    public enum Status
    {
        Ok,
        OutsideWorkdir,
        SymlinkLoop,
        IsDirectory,
        PathResolutionFailed,
    }

    public sealed record Result(
        Status Status,
        string? ResolvedPath,
        string? OriginalFullPath,
        bool WasSymlink,
        string? Reason);

    /// <summary>
    /// Validate <paramref name="path"/> and confirm both the original
    /// resolved path and (if it is a symlink) the final symlink target are
    /// inside <paramref name="workdirRoot"/>.
    /// </summary>
    public static Result Validate(string path, string workdirRoot)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new Result(Status.PathResolutionFailed, null, null, false, "empty path");
        if (string.IsNullOrWhiteSpace(workdirRoot))
            return new Result(Status.PathResolutionFailed, null, null, false, "empty workdir");

        string fullPath;
        string rootFull;
        try
        {
            fullPath = Path.GetFullPath(path);
            rootFull = Path.GetFullPath(workdirRoot);
        }
        catch (Exception ex)
        {
            return new Result(Status.PathResolutionFailed, null, null, false,
                $"GetFullPath: {ex.GetType().Name}");
        }

        if (!IsInside(fullPath, rootFull))
        {
            return new Result(Status.OutsideWorkdir, fullPath, fullPath, false,
                "path outside workdir");
        }

        // Probe the link without requiring the target to exist (broken
        // symlinks are forwarded to the caller; only loops fail here).
        bool wasSymlink = false;
        string resolved = fullPath;

        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            FileSystemInfo fsi;
            try
            {
                fsi = File.Exists(fullPath)
                    ? (FileSystemInfo)new FileInfo(fullPath)
                    : new DirectoryInfo(fullPath);
            }
            catch (Exception ex)
            {
                return new Result(Status.PathResolutionFailed, fullPath, fullPath, false,
                    $"FileSystemInfo: {ex.GetType().Name}");
            }

            if (fsi.LinkTarget is not null)
            {
                wasSymlink = true;
                FileSystemInfo? target;
                try
                {
                    target = fsi.ResolveLinkTarget(returnFinalTarget: true);
                }
                catch (IOException ex)
                {
                    // .NET surfaces symlink loops as IOException.
                    return new Result(Status.SymlinkLoop, fullPath, fullPath, true,
                        $"symlink loop: {ex.Message}");
                }
                catch (Exception ex)
                {
                    return new Result(Status.PathResolutionFailed, fullPath, fullPath, true,
                        $"ResolveLinkTarget: {ex.GetType().Name}");
                }

                if (target is not null)
                {
                    string targetFull;
                    try { targetFull = Path.GetFullPath(target.FullName); }
                    catch (Exception ex)
                    {
                        return new Result(Status.PathResolutionFailed, fullPath, fullPath, true,
                            $"target GetFullPath: {ex.GetType().Name}");
                    }

                    if (!IsInside(targetFull, rootFull))
                    {
                        return new Result(Status.OutsideWorkdir, targetFull, fullPath, true,
                            "symlink target outside workdir");
                    }
                    resolved = targetFull;
                }
            }
        }

        // Reject directory targets (caller wants a regular file).
        if (Directory.Exists(resolved) && !File.Exists(resolved))
        {
            return new Result(Status.IsDirectory, resolved, fullPath, wasSymlink,
                "resolved path is a directory");
        }

        return new Result(Status.Ok, resolved, fullPath, wasSymlink, null);
    }

    private static bool IsInside(string fullPath, string rootFull)
    {
        var sep = Path.DirectorySeparatorChar;
        var rootWithSep = rootFull.EndsWith(sep) ? rootFull : rootFull + sep;
        return fullPath.StartsWith(rootWithSep, StringComparison.Ordinal) ||
               string.Equals(fullPath, rootFull, StringComparison.Ordinal);
    }
}
