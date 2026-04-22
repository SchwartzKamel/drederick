namespace Drederick.Jeopardy.Ops;

/// <summary>
/// A single operator directive pushed into a running Jeopardy coordinator via
/// the JSONL inbox. All fields are local-only; the file path is not a network
/// resource and therefore not scope-gated.
/// </summary>
/// <param name="At">Wall-clock timestamp the operator sent the message.</param>
/// <param name="ChallengeId">Null = broadcast to all challenges in the run.</param>
/// <param name="SolverId">Null = all solvers on <paramref name="ChallengeId"/>.</param>
/// <param name="Kind">One of: <c>hint</c>, <c>stop</c>, <c>focus</c>, <c>skip</c>, <c>shutdown</c>.</param>
/// <param name="Body">Free-form payload. Never logged verbatim — audit records SHA-256 only.</param>
public sealed record OperatorMessage(
    DateTimeOffset At,
    string? ChallengeId,
    string? SolverId,
    string Kind,
    string Body);
