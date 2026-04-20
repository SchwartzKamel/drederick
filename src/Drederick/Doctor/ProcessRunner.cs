using System.Diagnostics;

namespace Drederick.Doctor;

/// <summary>
/// Abstraction for launching subprocesses. Tests substitute a recording stub
/// so they never actually fork /usr/bin/apt-get.
/// </summary>
public interface IProcessRunner
{
    (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds);
    (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds);
}

public sealed class DefaultProcessRunner : IProcessRunner
{
    public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = file,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"failed to start {file}");
        if (!p.WaitForExit(timeoutSeconds * 1000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"{file} timed out after {timeoutSeconds}s");
        }
        return (p.ExitCode, p.StandardOutput.ReadToEnd(), p.StandardError.ReadToEnd());
    }

    public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
    {
        // /bin/sh -c … keeps the recipe strings readable (they use && and redirects).
        var psi = new ProcessStartInfo
        {
            FileName = "/bin/sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(commandLine);
        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException("failed to start /bin/sh");
        if (!p.WaitForExit(timeoutSeconds * 1000))
        {
            try { p.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"command timed out after {timeoutSeconds}s");
        }
        return (p.ExitCode, p.StandardOutput.ReadToEnd(), p.StandardError.ReadToEnd());
    }
}
