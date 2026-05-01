using System.IO.Compression;
using System.Text.Json;

namespace Drederick.Memory;

/// <summary>
/// Offline reader for SharpHound JSON output. Converts SharpHound's
/// graph-format JSON into a flattened <see cref="BloodhoundFindings"/>
/// suitable for cross-run consumption by the planner.
///
/// Not a recon tool — there is no network, no subprocess, and no
/// scope check, because SharpHound was already run by the operator
/// against authorized targets and produced the JSON. The ingest
/// reads only the high-signal fields a planner uses to prioritize
/// follow-ups (kerberoastable / asreproastable / unconstrained
/// delegation / computer DNSHostName for KB host joins). The full
/// ACE / session / LocalAdmin graph is left on disk for direct
/// BloodHound queries.
///
/// Defense-in-depth:
/// <list type="bullet">
///   <item>Per-entry JSON-element bound on file size (default 256 MB) —
///   refuses runaway zips and disclaims responsibility for
///   pathological inputs.</item>
///   <item>Streaming <see cref="JsonDocument"/> parse rather than
///   POCO deserialization — schema-tolerant against SharpHound v1
///   ("Computers"/"Users"/"Groups" arrays) and v2 ("data"/"meta")
///   formats and any future field churn.</item>
///   <item>Returns <see cref="BloodhoundIngestResult"/> with
///   per-stream error messages rather than throwing on partial
///   corruption — so a bad file in the zip never poisons the whole
///   run.</item>
/// </list>
/// </summary>
public static class SharpHoundIngest
{
    /// <summary>
    /// Per-entry size cap. SharpHound zips for medium domains land
    /// in the 50–200 MB range; oversized inputs are usually either
    /// pathological or generated against an out-of-scope domain
    /// the operator didn't mean to ingest.
    /// </summary>
    public const long DefaultPerEntryByteCap = 256L * 1024L * 1024L;

    /// <summary>
    /// Ingest a SharpHound zip (the file produced by
    /// <c>sharphound -c All --zipfilename out.zip</c>). Each inner
    /// <c>*.json</c> is dispatched to the type-specific parser based
    /// on the <c>meta.type</c> field. Findings are appended to the
    /// supplied <paramref name="findings"/> bucket.
    /// </summary>
    public static BloodhoundIngestResult IngestZip(
        string zipPath,
        BloodhoundFindings findings,
        long perEntryByteCap = DefaultPerEntryByteCap)
    {
        ArgumentNullException.ThrowIfNull(findings);
        if (!File.Exists(zipPath))
            return new BloodhoundIngestResult
            {
                SourceZip = zipPath,
                Errors = { $"file not found: {zipPath}" },
            };

        findings.SourceZip = zipPath;
        findings.IngestedAt = DateTimeOffset.UtcNow.ToString("o");

        int filesIngested = 0;
        int kerberoastable = 0, asreproastable = 0, unconstrainedComputers = 0, unconstrainedUsers = 0;
        var errors = new List<string>();
        int domains = 0;

        try
        {
            using var fs = File.OpenRead(zipPath);
            using var zip = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: false);
            foreach (var entry in zip.Entries)
            {
                if (!entry.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) continue;
                if (entry.Length > perEntryByteCap)
                {
                    errors.Add($"{entry.FullName}: {entry.Length} bytes exceeds cap {perEntryByteCap}");
                    continue;
                }
                bool oversize = false;
                MemoryStream? ms = null;
                try
                {
                    using var es = entry.Open();
                    ms = new MemoryStream();
                    // Bounded copy: even if the central-directory `Length` lied,
                    // never read more than the cap. This is the zip-bomb gate.
                    var buf = new byte[81920];
                    long total = 0;
                    int n;
                    while ((n = es.Read(buf, 0, buf.Length)) > 0)
                    {
                        total += n;
                        if (total > perEntryByteCap)
                        {
                            errors.Add($"{entry.FullName}: exceeded cap {perEntryByteCap} during decompression");
                            oversize = true;
                            break;
                        }
                        ms.Write(buf, 0, n);
                    }
                    if (oversize)
                    {
                        ms.Dispose();
                        continue;
                    }
                    ms.Position = 0;
                    var counts = IngestStream(ms, findings);
                    kerberoastable += counts.kerberoastable;
                    asreproastable += counts.asreproastable;
                    unconstrainedComputers += counts.unconstrainedComputers;
                    unconstrainedUsers += counts.unconstrainedUsers;
                    domains += counts.domains;
                    filesIngested++;
                }
                catch (Exception ex)
                {
                    errors.Add($"{entry.FullName}: {ex.Message}");
                }
                finally
                {
                    ms?.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"zip open failed: {ex.Message}");
        }

        findings.DomainCount = domains;
        findings.HighValueGroups = findings.Groups
            .Where(g => g.HighValue)
            .Select(g => g.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new BloodhoundIngestResult
        {
            SourceZip = zipPath,
            FilesIngested = filesIngested,
            Computers = findings.Computers.Count,
            Users = findings.Users.Count,
            Groups = findings.Groups.Count,
            Domains = domains,
            KerberoastableUsers = kerberoastable,
            AsRepRoastableUsers = asreproastable,
            UnconstrainedDelegationComputers = unconstrainedComputers,
            UnconstrainedDelegationUsers = unconstrainedUsers,
            HighValueGroups = findings.HighValueGroups.Count,
            Errors = errors,
        };
    }

    /// <summary>
    /// Ingest a single SharpHound JSON file (e.g. <c>20240501130000_computers.json</c>).
    /// Useful for tests and for users who pre-extract their zip.
    /// </summary>
    public static BloodhoundIngestResult IngestJsonFile(
        string jsonPath,
        BloodhoundFindings findings,
        long perEntryByteCap = DefaultPerEntryByteCap)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var errors = new List<string>();
        if (!File.Exists(jsonPath))
            return new BloodhoundIngestResult { Errors = { $"file not found: {jsonPath}" } };
        var info = new FileInfo(jsonPath);
        if (info.Length > perEntryByteCap)
            return new BloodhoundIngestResult
            {
                Errors = { $"{jsonPath}: {info.Length} bytes exceeds cap {perEntryByteCap}" },
            };

        try
        {
            using var fs = File.OpenRead(jsonPath);
            var counts = IngestStream(fs, findings);
            findings.IngestedAt = DateTimeOffset.UtcNow.ToString("o");
            findings.DomainCount += counts.domains;
            findings.HighValueGroups = findings.Groups
                .Where(g => g.HighValue)
                .Select(g => g.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return new BloodhoundIngestResult
            {
                FilesIngested = 1,
                Computers = findings.Computers.Count,
                Users = findings.Users.Count,
                Groups = findings.Groups.Count,
                Domains = counts.domains,
                KerberoastableUsers = counts.kerberoastable,
                AsRepRoastableUsers = counts.asreproastable,
                UnconstrainedDelegationComputers = counts.unconstrainedComputers,
                UnconstrainedDelegationUsers = counts.unconstrainedUsers,
                HighValueGroups = findings.HighValueGroups.Count,
                Errors = errors,
            };
        }
        catch (Exception ex)
        {
            errors.Add($"{jsonPath}: {ex.Message}");
            return new BloodhoundIngestResult { Errors = errors };
        }
    }

    private static (int kerberoastable, int asreproastable,
        int unconstrainedComputers, int unconstrainedUsers, int domains)
        IngestStream(Stream s, BloodhoundFindings findings)
    {
        using var doc = JsonDocument.Parse(s);
        var root = doc.RootElement;

        // Detect format: SharpHound v2 emits {data: [...], meta: {type, count}};
        // SharpHound v1 emits {Computers: [...]}, {Users: [...]}, etc.
        string? type = null;
        JsonElement dataArr = default;
        bool haveData = false;

        if (root.TryGetProperty("meta", out var meta) &&
            meta.ValueKind == JsonValueKind.Object &&
            meta.TryGetProperty("type", out var typeEl) &&
            typeEl.ValueKind == JsonValueKind.String)
        {
            type = typeEl.GetString();
            if (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Array)
            {
                dataArr = d;
                haveData = true;
            }
        }
        else
        {
            foreach (var prop in root.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.Array) continue;
                var name = prop.Name.ToLowerInvariant();
                if (name is "computers" or "users" or "groups" or "domains" or "gpos" or "ous")
                {
                    type = name;
                    dataArr = prop.Value;
                    haveData = true;
                    break;
                }
            }
        }

        if (!haveData || type is null) return (0, 0, 0, 0, 0);

        int kerb = 0, asrep = 0, unCompS = 0, unUsersS = 0, doms = 0;
        switch (type.ToLowerInvariant())
        {
            case "computers":
                foreach (var el in dataArr.EnumerateArray())
                {
                    var c = ParseComputer(el);
                    findings.Computers.Add(c);
                    if (c.UnconstrainedDelegation) unCompS++;
                }
                break;
            case "users":
                foreach (var el in dataArr.EnumerateArray())
                {
                    var u = ParseUser(el);
                    findings.Users.Add(u);
                    if (u.HasSpn) kerb++;
                    if (u.DontReqPreauth) asrep++;
                    if (u.UnconstrainedDelegation) unUsersS++;
                }
                break;
            case "groups":
                foreach (var el in dataArr.EnumerateArray())
                    findings.Groups.Add(ParseGroup(el));
                break;
            case "domains":
                foreach (var _ in dataArr.EnumerateArray()) doms++;
                break;
                // gpos and ous: counted in the future if a planner needs them; ignored for now.
        }

        return (kerb, asrep, unCompS, unUsersS, doms);
    }

    internal static BloodhoundComputer ParseComputer(JsonElement el)
    {
        var c = new BloodhoundComputer
        {
            ObjectId = GetString(el, "ObjectIdentifier") ?? "",
        };
        var p = el.TryGetProperty("Properties", out var pp) && pp.ValueKind == JsonValueKind.Object ? pp : default;
        if (p.ValueKind == JsonValueKind.Object)
        {
            c.Name = GetString(p, "name") ?? "";
            c.DnsHostName = GetString(p, "dnshostname") ?? GetString(p, "DNSHostName");
            c.Domain = GetString(p, "domain");
            c.OperatingSystem = GetString(p, "operatingsystem") ?? GetString(p, "OperatingSystem");
            c.Enabled = GetBool(p, "enabled");
            c.HighValue = GetBool(p, "highvalue") ?? false;
            c.UnconstrainedDelegation = GetBool(p, "unconstraineddelegation") ?? false;
            c.HasLaps = GetBool(p, "haslaps");
            c.Owned = GetBool(p, "owned") ?? false;
        }
        return c;
    }

    internal static BloodhoundUser ParseUser(JsonElement el)
    {
        var u = new BloodhoundUser
        {
            ObjectId = GetString(el, "ObjectIdentifier") ?? "",
        };
        var p = el.TryGetProperty("Properties", out var pp) && pp.ValueKind == JsonValueKind.Object ? pp : default;
        if (p.ValueKind == JsonValueKind.Object)
        {
            u.Name = GetString(p, "name") ?? "";
            u.Domain = GetString(p, "domain");
            u.Enabled = GetBool(p, "enabled");
            u.HighValue = GetBool(p, "highvalue") ?? false;
            u.Sensitive = GetBool(p, "sensitive") ?? false;
            u.AdminCount = GetBool(p, "admincount") ?? false;
            u.DontReqPreauth = GetBool(p, "dontreqpreauth") ?? false;
            u.HasSpn = GetBool(p, "hasspn") ?? false;
            u.UnconstrainedDelegation = GetBool(p, "unconstraineddelegation") ?? false;
            u.PasswordNotRequired = GetBool(p, "passwordnotreqd") ?? false;
            u.Owned = GetBool(p, "owned") ?? false;
        }
        return u;
    }

    internal static BloodhoundGroup ParseGroup(JsonElement el)
    {
        var g = new BloodhoundGroup
        {
            ObjectId = GetString(el, "ObjectIdentifier") ?? "",
        };
        var p = el.TryGetProperty("Properties", out var pp) && pp.ValueKind == JsonValueKind.Object ? pp : default;
        if (p.ValueKind == JsonValueKind.Object)
        {
            g.Name = GetString(p, "name") ?? "";
            g.Domain = GetString(p, "domain");
            g.HighValue = GetBool(p, "highvalue") ?? false;
        }
        if (el.TryGetProperty("Members", out var m) && m.ValueKind == JsonValueKind.Array)
            g.MemberCount = m.GetArrayLength();
        return g;
    }

    /// <summary>Case-insensitive property fetch for SharpHound's mixed casing.</summary>
    private static string? GetString(JsonElement el, string name)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        if (el.TryGetProperty(name, out var v))
            return v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        foreach (var prop in el.EnumerateObject())
        {
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase) &&
                prop.Value.ValueKind == JsonValueKind.String)
                return prop.Value.GetString();
        }
        return null;
    }

    private static bool? GetBool(JsonElement el, string name)
    {
        if (el.ValueKind != JsonValueKind.Object) return null;
        JsonElement v = default;
        bool found = el.TryGetProperty(name, out v);
        if (!found)
        {
            foreach (var prop in el.EnumerateObject())
            {
                if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    v = prop.Value; found = true; break;
                }
            }
        }
        if (!found) return null;
        return v.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String =>
                bool.TryParse(v.GetString(), out var b) ? b : null,
            JsonValueKind.Number when v.TryGetInt32(out var n) => n != 0,
            _ => null,
        };
    }
}
