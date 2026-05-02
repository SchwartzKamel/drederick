using System.ComponentModel;
using Drederick.Learning;
using Microsoft.Extensions.AI;

namespace Drederick.Agent;

/// <summary>
/// LLM-facing wrapper around <see cref="FightNotebook"/>. Exposes a
/// single <c>take_note</c> tool the model can call any time during a
/// fight to commit a structured observation, tactic, gap, mistake,
/// winning move, or lesson to the long-term notebook.
///
/// <para>Notes are <i>operator-readable</i>: the LLM should write what
/// would be useful to a human reviewer between fights, not raw model
/// chatter. Plaintext credentials are auto-redacted by the notebook
/// before disk; the model should still avoid pasting them in the first
/// place.</para>
///
/// <para>This wrapper is intentionally small. It does NOT consult
/// <see cref="RunPermissions"/> or <see cref="Drederick.Scope.Scope"/>:
/// note-taking is a pure local-disk recording action against operator
/// machine paths Drederick already owns, not a network action against
/// any target. Scope governs <i>what we touch on the wire</i>;
/// note-taking is bookkeeping.</para>
/// </summary>
public sealed class LlmNotebookTool
{
    private readonly FightNotebook _notebook;
    private readonly string? _fightId;
    private readonly string? _targetArchetype;

    public LlmNotebookTool(
        FightNotebook notebook,
        string? fightId = null,
        string? targetArchetype = null)
    {
        _notebook = notebook ?? throw new ArgumentNullException(nameof(notebook));
        _fightId = fightId;
        _targetArchetype = targetArchetype;
    }

    /// <summary>
    /// Build the <c>take_note</c> AIFunction list for inclusion in the
    /// agent's tool catalog.
    /// </summary>
    public IReadOnlyList<AIFunction> BuildAiFunctions()
    {
        return new List<AIFunction>
        {
            AIFunctionFactory.Create(TakeNoteAsync, name: "take_note"),
        };
    }

    [Description(
        "Append a structured note to the long-term fight notebook so it can be reviewed later " +
        "and replayed into future fights. Use during or after a fight to record what worked, " +
        "what didn't, what was novel, or what the operator should look at next time. " +
        "Body should be a short paragraph (1-5 sentences) of operator-readable English. " +
        "Plaintext credentials are auto-redacted but should not be included.")]
    public async Task<object> TakeNoteAsync(
        [Description("One of: observation, tactic, gap, mistake, winning_move, lesson, general.")]
        string category,
        [Description(
            "1-5 sentence body describing the observation. " +
            "Plain English. No credentials. Reference services / techniques / GAP-IDs explicitly.")]
        string body,
        [Description(
            "Optional tags (service names, GAP-IDs, archetype hints, e.g. 'smb', 'GAP-046', 'ad'). " +
            "Pass empty array if none.")]
        string[]? tags = null,
        [Description(
            "Optional target host or hostname this note is about. " +
            "Will be redacted to /24 (v4) or /48 (v6) for private addresses.")]
        string? target_host = null)
    {
        if (string.IsNullOrWhiteSpace(category))
            return new { ok = false, error = "category is required" };
        if (string.IsNullOrWhiteSpace(body))
            return new { ok = false, error = "body is required" };

        var cat = category.Trim().ToLowerInvariant();
        if (!FightNoteCategory.IsKnown(cat))
            cat = FightNoteCategory.General;

        var note = await _notebook.TakeNoteAsync(
            category: cat,
            body: body,
            tags: tags,
            fightId: _fightId,
            targetHost: target_host,
            targetArchetype: _targetArchetype,
            source: "llm").ConfigureAwait(false);

        return new
        {
            ok = true,
            category = note.Category,
            body_sha256 = note.BodySha256,
            redacted = note.Body != body,
            tag_count = note.Tags.Count,
            timestamp = note.Timestamp,
        };
    }
}
