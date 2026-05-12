using System.Globalization;
using System.Text.Json;
using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using ToolBudget = Drederick.Agent.Budgets.ToolBudget;

namespace Drederick.Agent;

// --- htb-structured-plan-prior --- (GAP-054)
/// <summary>
/// Assembles a <see cref="PlanPrior"/> from the live <see cref="KnowledgeBase"/>,
/// an optional <see cref="AuditLog"/> (read back from disk for past-attempt
/// dedup), and an optional <see cref="ToolBudget"/>. The builder is pure and
/// allocates no I/O when the audit log is null or unreadable — making it safe
/// to call from inside a hot planning loop.
///
/// No plaintext credentials, wordlists, or captured secrets are emitted.
/// Captured-credential state is exposed as a non-negative count derived from
/// KB metadata keys; if those keys are absent, the count is zero.
/// </summary>
public static class PlanPriorBuilder
{
    private static readonly string[] CredKeyPrefixes = { "cred.", "creds.", "credential.", "credentials." };
    private static readonly string[] SessionKeyPrefixes = { "session.", "sessions." };

    /// <summary>
    /// Build a structured plan prior. Any argument may be null; nulls yield
    /// empty collections / zero counters so the caller can opt into partial
    /// context without conditional branches.
    /// </summary>
    public static PlanPrior Build(
        KnowledgeBase? kb,
        AuditLog? audit,
        ToolBudget? budget,
        IReadOnlyList<string>? targets = null,
        string? summary = null)
    {
        var hosts = kb?.Hosts ?? new Dictionary<string, HostFinding>();
        var targetList = (targets is { Count: > 0 })
            ? targets.ToArray()
            : hosts.Keys.OrderBy(k => k, StringComparer.Ordinal).ToArray();

        var openServices = new List<PlanPriorService>();
        int credCount = 0;
        int sessionCount = 0;

        foreach (var kv in hosts)
        {
            var host = kv.Key;
            var finding = kv.Value;
            if (finding is null) continue;

            credCount += CountByPrefix(finding.Findings, CredKeyPrefixes);
            sessionCount += CountByPrefix(finding.Findings, SessionKeyPrefixes);

            if (finding.Nmap?.OpenPorts is { Count: > 0 } ports)
            {
                foreach (var p in ports)
                {
                    if (p is null) continue;
                    var cves = ExtractCvesForPort(finding.Findings, p.Port);
                    openServices.Add(new PlanPriorService(
                        Host: host,
                        Port: p.Port,
                        Protocol: string.IsNullOrEmpty(p.Protocol) ? "tcp" : p.Protocol,
                        Product: p.Product,
                        Version: p.Version,
                        Cves: cves));
                }
            }
        }

        openServices.Sort((a, b) =>
        {
            var byHost = string.CompareOrdinal(a.Host, b.Host);
            return byHost != 0 ? byHost : a.Port.CompareTo(b.Port);
        });

        var attempts = ReadPreviousAttempts(audit);

        int used = budget?.TotalCalls ?? 0;
        int remaining = budget is null ? 0 : Math.Max(0, budget.GlobalBudget - budget.TotalCalls);
        var planBudget = new PlanPriorBudget(used, remaining);

        return new PlanPrior(
            Targets: targetList,
            OpenServices: openServices,
            CapturedCreds: new PlanPriorCredentials(credCount),
            ActiveSessions: new PlanPriorSessions(sessionCount),
            PreviouslyAttempted: attempts,
            Budget: planBudget,
            Summary: summary);
    }

    /// <summary>
    /// Flatten the prior to a dictionary suitable for
    /// <see cref="AuditLog.Record(string, IReadOnlyDictionary{string, object?})"/>.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> ToAuditFields(this PlanPrior prior)
    {
        ArgumentNullException.ThrowIfNull(prior);
        var fields = new Dictionary<string, object?>
        {
            ["targets"] = prior.Targets,
            ["open_services"] = prior.OpenServices,
            ["captured_creds"] = prior.CapturedCreds,
            ["active_sessions"] = prior.ActiveSessions,
            ["previously_attempted"] = prior.PreviouslyAttempted,
            ["budget"] = prior.Budget,
        };
        if (!string.IsNullOrEmpty(prior.Summary))
        {
            fields["summary"] = prior.Summary;
        }
        return fields;
    }

    private static int CountByPrefix(IReadOnlyDictionary<string, string>? findings, string[] prefixes)
    {
        if (findings is null || findings.Count == 0) return 0;
        int n = 0;
        foreach (var key in findings.Keys)
        {
            foreach (var prefix in prefixes)
            {
                if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    n++;
                    break;
                }
            }
        }
        return n;
    }

    private static IReadOnlyList<string> ExtractCvesForPort(IReadOnlyDictionary<string, string>? findings, int port)
    {
        if (findings is null || findings.Count == 0) return Array.Empty<string>();
        var portKey = port.ToString(CultureInfo.InvariantCulture);
        var prefixes = new[]
        {
            $"services.{portKey}.cves",
            $"services.{portKey}.cve",
        };
        var cves = new List<string>();
        foreach (var prefix in prefixes)
        {
            if (findings.TryGetValue(prefix, out var raw) && !string.IsNullOrWhiteSpace(raw))
            {
                foreach (var piece in raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (piece.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) && !cves.Contains(piece, StringComparer.OrdinalIgnoreCase))
                    {
                        cves.Add(piece);
                    }
                }
            }
        }
        return cves;
    }

    private static IReadOnlyList<PlanPriorAttempt> ReadPreviousAttempts(AuditLog? audit)
    {
        if (audit is null || string.IsNullOrEmpty(audit.Path) || !File.Exists(audit.Path))
            return Array.Empty<PlanPriorAttempt>();

        // Read a snapshot copy so concurrent writes to the live log do not
        // block (StreamWriter holds an exclusive write handle but allows
        // shared reads, see AuditLog ctor).
        string[] lines;
        try
        {
            using var fs = new FileStream(audit.Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var rdr = new StreamReader(fs);
            var collected = new List<string>();
            string? line;
            while ((line = rdr.ReadLine()) is not null)
            {
                if (line.Length > 0) collected.Add(line);
            }
            lines = collected.ToArray();
        }
        catch (IOException)
        {
            return Array.Empty<PlanPriorAttempt>();
        }

        // Dedup by (tool, target) — last write wins so the most recent
        // attempt's result_kind is what the planner sees.
        var seen = new Dictionary<(string Tool, string Target), PlanPriorAttempt>(
            new ToolTargetComparer());

        foreach (var line in lines)
        {
            JsonElement root;
            try
            {
                using var doc = JsonDocument.Parse(line);
                root = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                continue;
            }
            if (root.ValueKind != JsonValueKind.Object) continue;

            if (!root.TryGetProperty("tool", out var toolEl) || toolEl.ValueKind != JsonValueKind.String) continue;
            if (!root.TryGetProperty("target", out var targetEl) || targetEl.ValueKind != JsonValueKind.String) continue;

            var tool = toolEl.GetString();
            var target = targetEl.GetString();
            if (string.IsNullOrEmpty(tool) || string.IsNullOrEmpty(target)) continue;

            string resultKind = "unknown";
            if (root.TryGetProperty("result_kind", out var rk) && rk.ValueKind == JsonValueKind.String)
            {
                resultKind = rk.GetString() ?? "unknown";
            }
            else if (root.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.String)
            {
                resultKind = st.GetString() ?? "unknown";
            }
            else if (root.TryGetProperty("event", out var ev) && ev.ValueKind == JsonValueKind.String)
            {
                var evName = ev.GetString() ?? "";
                if (evName.EndsWith(".finish", StringComparison.OrdinalIgnoreCase)) resultKind = "finish";
                else if (evName.EndsWith(".start", StringComparison.OrdinalIgnoreCase)) resultKind = "start";
                else if (evName.EndsWith(".error", StringComparison.OrdinalIgnoreCase)) resultKind = "error";
            }

            seen[(tool!, target!)] = new PlanPriorAttempt(tool!, target!, resultKind);
        }

        return seen.Values
            .OrderBy(a => a.Tool, StringComparer.Ordinal)
            .ThenBy(a => a.Target, StringComparer.Ordinal)
            .ToArray();
    }

    private sealed class ToolTargetComparer : IEqualityComparer<(string Tool, string Target)>
    {
        public bool Equals((string Tool, string Target) x, (string Tool, string Target) y)
            => string.Equals(x.Tool, y.Tool, StringComparison.OrdinalIgnoreCase)
            && string.Equals(x.Target, y.Target, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Tool, string Target) obj)
            => HashCode.Combine(
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Tool),
                StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Target));
    }
}
// --- end htb-structured-plan-prior ---
