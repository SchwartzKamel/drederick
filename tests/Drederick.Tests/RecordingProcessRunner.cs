using Drederick.Doctor;

namespace Drederick.Tests;

/// <summary>
/// Recording stub for IProcessRunner used across PoC source tests. Scripts
/// responses per (filename, arguments contains substring) and records every
/// invocation so tests can assert behaviour without forking any subprocess.
/// </summary>
internal sealed class RecordingProcessRunner : IProcessRunner
{
    public sealed record Call(string Kind, string FileOrCmd, string Arguments);

    public List<Call> Calls { get; } = new();
    public List<(Func<string, string, bool> Match, Func<(int, string, string)> Respond)> RunHandlers { get; } = new();
    public List<(Func<string, bool> Match, Func<(int, string, string)> Respond)> ShellHandlers { get; } = new();

    public RecordingProcessRunner OnRun(Func<string, string, bool> match, int exit, string stdout = "", string stderr = "")
    {
        RunHandlers.Add((match, () => (exit, stdout, stderr)));
        return this;
    }

    public RecordingProcessRunner OnShell(Func<string, bool> match, int exit, string stdout = "", string stderr = "")
    {
        ShellHandlers.Add((match, () => (exit, stdout, stderr)));
        return this;
    }

    public RecordingProcessRunner OnRun(
        Func<string, string, bool> match,
        Func<(int exit, string stdout, string stderr)> respond)
    {
        RunHandlers.Add((match, respond));
        return this;
    }

    public RecordingProcessRunner OnRunThrow(Func<string, string, bool> match, Exception ex)
    {
        RunHandlers.Add((match, () => throw ex));
        return this;
    }

    public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
    {
        Calls.Add(new Call("run", file, arguments));
        foreach (var (match, respond) in RunHandlers)
        {
            if (match(file, arguments)) return respond();
        }
        return (127, "", "no handler");
    }

    public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
    {
        Calls.Add(new Call("shell", "/bin/sh", commandLine));
        foreach (var (match, respond) in ShellHandlers)
        {
            if (match(commandLine)) return respond();
        }
        return (127, "", "no handler");
    }
}
