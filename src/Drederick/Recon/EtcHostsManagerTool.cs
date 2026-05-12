using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Drederick.Audit;

namespace Drederick.Recon;

// --- htb-hosts-mutation --- (GAP-006 pair with batch 2: cross-cutting /etc/hosts analyzer)
/// <summary>
/// Cross-cutting analyzer that compares discovered virtual hostnames
/// (from <see cref="EtcHostsProposal"/> records emitted by other recon
/// tools — TLS cert SANs, HTTP vhost responses, SMB CN, Kerberos realm)
/// against the operator's local <c>/etc/hosts</c> file and emits
/// structured <c>briefing.delta.proposed</c> events suggesting additions
/// or flagging conflicts.
///
/// Drederick NEVER writes to <c>/etc/hosts</c>. Host-file mutation is
/// strictly the operator's prerogative; this tool only produces a diff
/// + a copy-paste-ready snippet.
/// </summary>
public sealed partial class EtcHostsManagerTool : IReconTool
{
    public string Name => "etc-hosts";

    public string Description =>
        "Compare discovered virtual hostnames against the operator's local " +
        "/etc/hosts and emit add/conflict/info_only/skip proposals. " +
        "Read-only: never mutates /etc/hosts.";

    [GeneratedRegex(@"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9_\-]{1,63}(?<!-)\.?)+$",
        RegexOptions.CultureInvariant)]
    private static partial Regex HostnameShapeRegex();

    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;
    private readonly Func<string, CancellationToken, Task<string[]>> _resolver;

    public EtcHostsManagerTool(
        Scope.Scope scope,
        AuditLog audit,
        Func<string, CancellationToken, Task<string[]>>? resolver = null)
    {
        _scope = scope;
        _audit = audit;
        _resolver = resolver ?? DefaultResolveAsync;
    }

    private static async Task<string[]> DefaultResolveAsync(string host, CancellationToken ct)
    {
        try
        {
            var addrs = await System.Net.Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return addrs.Select(a => a.ToString()).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    [Description("Read the operator's /etc/hosts, compare against discovered virtual hostnames, " +
                 "and emit structured add/conflict/info_only proposals. Read-only — never writes /etc/hosts.")]
    public async Task<EtcHostsAnalysisResult> AnalyzeAsync(
        string target,
        IEnumerable<EtcHostsProposal> incomingProposals,
        string etcHostsPath = "/etc/hosts",
        CancellationToken ct = default)
    {
        _scope.Require(target);

        ArgumentNullException.ThrowIfNull(incomingProposals);

        if (!IsHostsPathAllowed(etcHostsPath))
        {
            throw new ArgumentException(
                $"Refusing arbitrary hosts-path read '{etcHostsPath}': must be /etc/hosts, " +
                "under the operator's home directory, or under the current working / out directory.",
                nameof(etcHostsPath));
        }

        var result = new EtcHostsAnalysisResult();

        // Snapshot file metadata BEFORE analysis for tamper-evidence assertions.
        long sizeBefore = -1;
        DateTime mtimeBefore = default;
        try
        {
            var fi = new FileInfo(etcHostsPath);
            if (fi.Exists)
            {
                sizeBefore = fi.Length;
                mtimeBefore = fi.LastWriteTimeUtc;
            }
        }
        catch { /* metadata read failure shouldn't break analysis */ }

        try
        {
            result.CurrentEntries = await ReadHostsAsync(etcHostsPath, ct).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            // Treat missing file as empty map — operator may not have one yet.
            result.CurrentEntries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            return result;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var proposal in incomingProposals)
        {
            if (proposal is null) continue;

            var hostname = (proposal.Hostname ?? "").Trim();
            var proposedIp = (proposal.TargetIp ?? "").Trim();
            var source = string.IsNullOrWhiteSpace(proposal.Source) ? "unknown" : proposal.Source;

            // Argv-injection guard: hostnames must look like hostnames.
            // Reject anything with shell metachars or path-traversal shape.
            if (string.IsNullOrEmpty(hostname)
                || Scope.ArgvValidator.ContainsShellMetachars(hostname)
                || !HostnameShapeRegex().IsMatch(hostname))
            {
                continue;
            }
            if (!System.Net.IPAddress.TryParse(proposedIp, out _))
            {
                continue;
            }
            if (!seen.Add(hostname))
            {
                continue;
            }

            string action;
            string? currentIp = null;
            int priority;

            if (result.CurrentEntries.TryGetValue(hostname, out var existingIp))
            {
                currentIp = existingIp;
                if (string.Equals(existingIp, proposedIp, StringComparison.OrdinalIgnoreCase))
                {
                    action = "skip";
                    priority = 0;
                }
                else
                {
                    action = "conflict";
                    priority = 50;
                }
            }
            else
            {
                string[] resolved;
                try { resolved = await _resolver(hostname, ct).ConfigureAwait(false); }
                catch { resolved = Array.Empty<string>(); }

                if (resolved.Contains(proposedIp, StringComparer.OrdinalIgnoreCase))
                {
                    action = "info_only";
                    priority = 25;
                }
                else
                {
                    action = "add";
                    // Highest priority when the hostname does not resolve at all —
                    // operator will be blocked without the entry.
                    priority = resolved.Length == 0 ? 100 : 75;
                }
            }

            var decision = new EtcHostsProposalDecision
            {
                Hostname = hostname,
                ProposedIp = proposedIp,
                Action = action,
                CurrentIp = currentIp,
                Source = source,
                Priority = priority,
            };
            result.Proposals.Add(decision);

            if (action == "add")
            {
                _audit.Record("briefing.delta.proposed", new Dictionary<string, object?>
                {
                    ["section"] = "etc_hosts",
                    ["hostname"] = hostname,
                    ["target_ip"] = proposedIp,
                    ["source"] = source,
                    ["priority"] = priority,
                });
            }
        }

        result.SuggestedSnippet = BuildSnippet(target, result.Proposals);

        // Tamper-evidence: assert file is unchanged (defensive — we never open
        // for write, but verify size+mtime are intact).
        try
        {
            var fi = new FileInfo(etcHostsPath);
            if (fi.Exists && sizeBefore >= 0)
            {
                if (fi.Length != sizeBefore || fi.LastWriteTimeUtc != mtimeBefore)
                {
                    throw new InvalidOperationException(
                        $"/etc/hosts changed during analysis (size/mtime mismatch). " +
                        "EtcHostsManagerTool MUST NOT write to the hosts file; aborting.");
                }
            }
        }
        catch (InvalidOperationException) { throw; }
        catch { /* metadata recheck failure shouldn't poison results */ }

        var counts = result.Proposals
            .GroupBy(p => p.Action)
            .ToDictionary(g => g.Key, g => (object?)g.Count());

        _audit.Record("etc-hosts.analyze", new Dictionary<string, object?>
        {
            ["target"] = target,
            ["hosts_path"] = etcHostsPath,
            ["current_entries_count"] = result.CurrentEntries.Count,
            ["proposals_total"] = result.Proposals.Count,
            ["counts_by_action"] = counts,
            ["error"] = result.Error,
        });

        return result;
    }

    private static bool IsHostsPathAllowed(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return false; }

        if (string.Equals(full, "/etc/hosts", StringComparison.Ordinal)) return true;

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(home))
        {
            var homeFull = Path.GetFullPath(home);
            if (IsUnder(full, homeFull)) return true;
        }

        var cwdOut = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), "out"));
        if (IsUnder(full, cwdOut)) return true;

        // Also allow anything under the current working directory itself
        // (test fixtures under e.g. bin/Debug/.../).
        var cwd = Path.GetFullPath(Directory.GetCurrentDirectory());
        if (IsUnder(full, cwd)) return true;

        // Allow tmp-like locations only if the OS temp folder is the parent
        // — needed for test rigs that pin temp paths via DREDERICK_TMPDIR.
        var tmp = Path.GetFullPath(Path.GetTempPath());
        if (IsUnder(full, tmp)) return true;

        return false;
    }

    private static bool IsUnder(string candidate, string root)
    {
        var c = candidate.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var r = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return c.Equals(r, StringComparison.Ordinal)
            || c.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            || c.StartsWith(r + Path.AltDirectorySeparatorChar, StringComparison.Ordinal);
    }

    private static async Task<Dictionary<string, string>> ReadHostsAsync(string path, CancellationToken ct)
    {
        var entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var lines = await File.ReadAllLinesAsync(path, ct).ConfigureAwait(false);

        foreach (var raw in lines)
        {
            var line = raw;
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;

            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var ip = parts[0];
            if (!System.Net.IPAddress.TryParse(ip, out _)) continue;

            for (var i = 1; i < parts.Length; i++)
            {
                var name = parts[i];
                if (string.IsNullOrEmpty(name)
                    || Scope.ArgvValidator.ContainsShellMetachars(name)
                    || !HostnameShapeRegex().IsMatch(name))
                {
                    continue;
                }
                // First occurrence wins (matches resolver behaviour).
                entries.TryAdd(name, ip);
            }
        }

        return entries;
    }

    private static string BuildSnippet(string target, List<EtcHostsProposalDecision> decisions)
    {
        var adds = decisions
            .Where(d => d.Action == "add")
            .GroupBy(d => d.ProposedIp, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (adds.Count == 0) return "";

        var sb = new StringBuilder();
        sb.Append("# drederick-proposed: target=").Append(target).Append('\n');
        foreach (var group in adds)
        {
            sb.Append(group.Key);
            foreach (var d in group.OrderByDescending(x => x.Priority).ThenBy(x => x.Hostname, StringComparer.Ordinal))
            {
                sb.Append(' ').Append(d.Hostname);
            }
            sb.Append('\n');
        }
        return sb.ToString();
    }
}
// --- end htb-hosts-mutation ---
