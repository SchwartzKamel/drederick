using System.Collections.Concurrent;
using System.Text;
using Drederick.Doctor;

namespace Drederick.Tests.Jeopardy.Sandbox;

/// <summary>
/// Canned <see cref="IProcessRunner"/> for sandbox tests. Matches docker CLI
/// invocations by substring against a list of scripted handlers and records
/// every call for assertion. Does NOT spawn any subprocess. Thread-safe so
/// parallelism tests can hit it from multiple tasks.
/// </summary>
internal sealed class CannedDockerRunner : IProcessRunner
{
    public sealed record Call(string File, string Arguments);

    private readonly object _gate = new();
    public List<Call> Calls { get; } = new();

    private readonly List<Handler> _handlers = new();

    private sealed record Handler(
        Func<string, string, bool> Match,
        Func<string, (int exit, string stdout, string stderr)> Respond,
        int? DelayMs);

    /// <summary>Track concurrent calls peak — for parallelism tests.</summary>
    public int CurrentInFlight;
    public int PeakInFlight;

    public CannedDockerRunner OnArgs(string substring, int exit, string stdout = "", string stderr = "", int? delayMs = null)
    {
        _handlers.Add(new Handler(
            (file, args) => args.Contains(substring, StringComparison.Ordinal),
            _ => (exit, stdout, stderr),
            delayMs));
        return this;
    }

    public CannedDockerRunner OnArgs(Func<string, bool> match, int exit, string stdout = "", string stderr = "", int? delayMs = null)
    {
        _handlers.Add(new Handler(
            (_, args) => match(args),
            _ => (exit, stdout, stderr),
            delayMs));
        return this;
    }

    public CannedDockerRunner OnArgsFn(Func<string, bool> match, Func<string, (int, string, string)> respond, int? delayMs = null)
    {
        _handlers.Add(new Handler((_, args) => match(args), respond, delayMs));
        return this;
    }

    public CannedDockerRunner OnArgsThrow(Func<string, bool> match, Exception ex)
    {
        _handlers.Add(new Handler((_, args) => match(args), _ => throw ex, null));
        return this;
    }

    public (int ExitCode, string StdOut, string StdErr) Run(string file, string arguments, int timeoutSeconds)
    {
        var inflight = Interlocked.Increment(ref CurrentInFlight);
        var peakBefore = Volatile.Read(ref PeakInFlight);
        while (inflight > peakBefore)
        {
            Interlocked.CompareExchange(ref PeakInFlight, inflight, peakBefore);
            peakBefore = Volatile.Read(ref PeakInFlight);
        }
        try
        {
            lock (_gate) { Calls.Add(new Call(file, arguments)); }
            Handler? chosen = null;
            lock (_gate)
            {
                foreach (var h in _handlers)
                {
                    if (h.Match(file, arguments)) { chosen = h; break; }
                }
            }
            if (chosen is null) return (127, "", $"no handler: {arguments}");
            if (chosen.DelayMs is int d) Thread.Sleep(d);
            return chosen.Respond(arguments);
        }
        finally
        {
            Interlocked.Decrement(ref CurrentInFlight);
        }
    }

    public (int ExitCode, string StdOut, string StdErr) RunShell(string commandLine, int timeoutSeconds)
        => throw new NotSupportedException("sandbox uses Run(file, args) only");

    public IReadOnlyList<string> ArgvTrace
    {
        get { lock (_gate) { return Calls.Select(c => c.Arguments).ToArray(); } }
    }
}
