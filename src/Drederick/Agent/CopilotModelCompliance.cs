using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using GitHub.Copilot.SDK;

namespace Drederick.Agent;

internal static class CopilotModelCompliance
{
    internal static readonly IReadOnlyList<string> PreferredToolCapableModelIds =
    [
        "claude-sonnet-4.6",
        "claude-haiku-4.5",
        "claude-sonnet-4.5",
        "claude-sonnet-4",
        "gpt-5.4-mini",
        "gpt-5-mini",
        "gpt-5.4",
        "gpt-5.3-codex",
        "gpt-5.2-codex",
        "gpt-5.2",
        "gpt-4.1",
        "gpt-4o",
        "gpt-4o-mini",
        "o4-mini",
        "o3",
        "o3-mini",
    ];

    private static readonly HashSet<string> KnownToolCapableModelIds = new(
        PreferredToolCapableModelIds,
        StringComparer.OrdinalIgnoreCase)
    {
        "claude-opus-4.7",
        "claude-opus-4.7-high",
        "claude-opus-4.7-xhigh",
        "claude-opus-4.7-1m-internal",
        "claude-opus-4.6",
        "claude-opus-4.6-1m",
        "claude-opus-4.5",
        "gpt-5.5",
    };

    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);
    private static readonly SemaphoreSlim CacheGate = new(1, 1);
    private static readonly Dictionary<string, CachedModelList> ModelCache = new(StringComparer.Ordinal);

    internal static async Task<CopilotModelListSnapshot> GetModelsAsync(
        string githubToken,
        Func<CancellationToken, Task<IList<ModelInfo>>> fetchModelsAsync,
        CancellationToken ct)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(githubToken);
        ArgumentNullException.ThrowIfNull(fetchModelsAsync);

        var key = CacheKey(githubToken);
        var now = DateTimeOffset.UtcNow;
        await CacheGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (ModelCache.TryGetValue(key, out var cached) && now - cached.FetchedAt <= CacheTtl)
            {
                return new CopilotModelListSnapshot(cached.Models, FromCache: true);
            }
        }
        finally
        {
            CacheGate.Release();
        }

        var models = await fetchModelsAsync(ct).ConfigureAwait(false);
        var materialized = models.ToArray();

        await CacheGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            ModelCache[key] = new CachedModelList(materialized, DateTimeOffset.UtcNow);
        }
        finally
        {
            CacheGate.Release();
        }

        return new CopilotModelListSnapshot(materialized, FromCache: false);
    }

    internal static CopilotModelDecision SelectModel(
        IReadOnlyList<ModelInfo> models,
        string? requestedModelId,
        bool explicitModel)
    {
        ArgumentNullException.ThrowIfNull(models);

        var requested = string.IsNullOrWhiteSpace(requestedModelId) ? null : requestedModelId.Trim();
        var byId = models
            .Where(m => !string.IsNullOrWhiteSpace(m.Id))
            .GroupBy(m => m.Id, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var compliant = models
            .Where(m => IsCompliant(m).Compliant)
            .Select(m => m.Id)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (explicitModel)
        {
            if (string.IsNullOrWhiteSpace(requested))
            {
                return Failure(null, explicitModel, "explicit_model_empty", compliant);
            }

            if (!byId.TryGetValue(requested, out var model))
            {
                return Failure(requested, explicitModel, "model_unavailable", compliant);
            }

            var evaluation = IsCompliant(model);
            return evaluation.Compliant
                ? Success(model.Id, requested, explicitModel, evaluation.Reason, compliant)
                : Failure(requested, explicitModel, evaluation.Reason, compliant);
        }

        foreach (var preferred in PreferredToolCapableModelIds)
        {
            if (!byId.TryGetValue(preferred, out var model)) continue;

            var evaluation = IsCompliant(model);
            if (evaluation.Compliant)
            {
                return Success(model.Id, requested, explicitModel, $"preferred:{preferred}", compliant);
            }
        }

        var fallback = models.FirstOrDefault(m => IsCompliant(m).Compliant);
        if (fallback is not null)
        {
            var evaluation = IsCompliant(fallback);
            return Success(fallback.Id, requested, explicitModel, $"fallback:{evaluation.Reason}", compliant);
        }

        return Failure(requested, explicitModel, "no_tool_capable_model_available", compliant);
    }

    internal static ModelComplianceEvaluation IsCompliant(ModelInfo model)
    {
        ArgumentNullException.ThrowIfNull(model);

        var id = model.Id?.Trim();
        if (string.IsNullOrWhiteSpace(id))
        {
            return new ModelComplianceEvaluation(false, "model_id_empty");
        }

        if (!IsPolicyEnabled(model.Policy?.State))
        {
            return new ModelComplianceEvaluation(false, "model_policy_not_enabled");
        }

        if (HasExplicitToolSupportFlag(model.Capabilities?.Supports))
        {
            return new ModelComplianceEvaluation(true, "metadata_tool_support");
        }

        if (KnownToolCapableModelIds.Contains(id))
        {
            return new ModelComplianceEvaluation(true, "known_tool_capable");
        }

        return new ModelComplianceEvaluation(false, "missing_tool_support_metadata");
    }

    internal static string BuildFailureMessage(CopilotModelDecision decision)
    {
        var requested = string.IsNullOrWhiteSpace(decision.RequestedModelId)
            ? "<auto>"
            : decision.RequestedModelId;
        var compliant = decision.CompliantModelIds.Count == 0
            ? "none"
            : string.Join(", ", decision.CompliantModelIds);

        return decision.Reason switch
        {
            "model_unavailable" =>
                $"Copilot model '{requested}' is not available to this GitHub account. " +
                $"Available Drederick tool-capable models: {compliant}.",
            "model_policy_not_enabled" =>
                $"Copilot model '{requested}' is not enabled by policy for this GitHub account. " +
                $"Select a compliant tool-capable model via DREDERICK_MODEL. Available compliant models: {compliant}.",
            "missing_tool_support_metadata" =>
                $"Copilot model '{requested}' is not marked as tool/function-call capable for Drederick. " +
                $"Select one of: {compliant}.",
            _ =>
                $"No GitHub Copilot model suitable for Drederick tool/function calling was found. " +
                $"Selection reason: {decision.Reason}; available compliant models: {compliant}.",
        };
    }

    internal static void ClearCacheForTests()
    {
        CacheGate.Wait();
        try
        {
            ModelCache.Clear();
        }
        finally
        {
            CacheGate.Release();
        }
    }

    private static CopilotModelDecision Success(
        string selectedModelId,
        string? requestedModelId,
        bool explicitModel,
        string reason,
        IReadOnlyList<string> compliantModelIds) =>
        new(
            SelectedModelId: selectedModelId,
            RequestedModelId: requestedModelId,
            ExplicitModel: explicitModel,
            Compliant: true,
            Reason: reason,
            CompliantModelIds: compliantModelIds);

    private static CopilotModelDecision Failure(
        string? requestedModelId,
        bool explicitModel,
        string reason,
        IReadOnlyList<string> compliantModelIds) =>
        new(
            SelectedModelId: null,
            RequestedModelId: requestedModelId,
            ExplicitModel: explicitModel,
            Compliant: false,
            Reason: reason,
            CompliantModelIds: compliantModelIds);

    private static bool IsPolicyEnabled(string? state)
    {
        if (string.IsNullOrWhiteSpace(state)) return true;
        return string.Equals(state.Trim(), "enabled", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasExplicitToolSupportFlag(object? supports)
    {
        if (supports is null) return false;

        foreach (var property in supports.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.PropertyType != typeof(bool)) continue;
            if (!LooksLikeToolSupportFlag(property.Name)) continue;
            if (property.GetValue(supports) is true) return true;
        }

        return false;
    }

    private static bool LooksLikeToolSupportFlag(string name) =>
        name.Contains("Tool", StringComparison.OrdinalIgnoreCase)
        || name.Contains("Function", StringComparison.OrdinalIgnoreCase);

    private static string CacheKey(string githubToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(githubToken));
        return Convert.ToHexString(bytes);
    }

    private sealed record CachedModelList(IReadOnlyList<ModelInfo> Models, DateTimeOffset FetchedAt);
}

internal sealed record CopilotModelListSnapshot(IReadOnlyList<ModelInfo> Models, bool FromCache);

internal sealed record ModelComplianceEvaluation(bool Compliant, string Reason);

internal sealed record CopilotModelDecision(
    string? SelectedModelId,
    string? RequestedModelId,
    bool ExplicitModel,
    bool Compliant,
    string Reason,
    IReadOnlyList<string> CompliantModelIds);

internal sealed class CopilotModelComplianceException : InvalidOperationException
{
    public CopilotModelComplianceException(string message)
        : base(message)
    {
    }
}
