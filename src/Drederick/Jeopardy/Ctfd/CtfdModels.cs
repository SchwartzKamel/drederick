namespace Drederick.Jeopardy.Ctfd;

public sealed record CtfdAttachment(
    string Name,
    string Url,
    long? SizeBytes
);

public sealed record CtfdChallenge(
    int Id,
    string Name,
    string Category,
    int Value,
    string Description,
    IReadOnlyList<CtfdAttachment> Files,
    IReadOnlyList<string> Tags,
    string? ConnectionInfo,
    bool Solved
);

public sealed record CtfdSubmissionResult(
    bool Correct,
    bool AlreadySolved,
    string? Message,
    DateTimeOffset SubmittedAt
);

public sealed record CtfdScoreboardEntry(int Rank, int TeamId, string Name, int Score);

public sealed class CtfdException : Exception
{
    public CtfdException(string message) : base(message) { }
    public CtfdException(string message, Exception inner) : base(message, inner) { }
}
