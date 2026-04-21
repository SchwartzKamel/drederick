using System.Collections.ObjectModel;
using System.Diagnostics;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Drederick.Audit;
using Microsoft.Data.Sqlite;

namespace Drederick.UI.ViewModels;

/// <summary>
/// Backs the Findings tab. Read-only summary of <c>findings.db</c>
/// (host / port / service / CVE count). Intentionally thin: triage belongs
/// to Datasette, which this tab can launch via the "Open in Datasette"
/// button (shells out to our own CLI's <c>drederick serve</c> subcommand —
/// narrowly allowed because it is the harness itself, not a scanner binary;
/// see <c>@invariant-id:aggregate-not-execute</c>).
/// </summary>
public sealed partial class FindingsViewModel : ObservableObject
{
    [ObservableProperty]
    private string _outputDir = "out";

    [ObservableProperty]
    private string _status = "No findings loaded.";

    [ObservableProperty]
    private int _hostCount;

    [ObservableProperty]
    private int _serviceCount;

    [ObservableProperty]
    private int _cveCount;

    [ObservableProperty]
    private int _pocRefCount;

    [ObservableProperty]
    private bool _canOpenDatasette;

    public ObservableCollection<FindingRow> Rows { get; } = new();

    [RelayCommand]
    public void Reload()
    {
        Rows.Clear();
        HostCount = 0;
        ServiceCount = 0;
        CveCount = 0;
        PocRefCount = 0;
        CanOpenDatasette = false;

        var dbPath = Path.Combine(OutputDir, "findings.db");
        if (!File.Exists(dbPath))
        {
            Status = $"No database at {dbPath}. Run a scan first.";
            return;
        }

        try
        {
            using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
            conn.Open();

            HostCount = (int)ScalarLong(conn, "SELECT COUNT(*) FROM hosts");
            ServiceCount = (int)ScalarLong(conn, "SELECT COUNT(*) FROM services");
            CveCount = TryScalar(conn, "SELECT COUNT(*) FROM cves");
            PocRefCount = TryScalar(conn, "SELECT COUNT(*) FROM poc_refs");

            // Per-host summary: host address, open port count, service sample.
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT h.address,
                       COUNT(s.id) AS svc_count,
                       GROUP_CONCAT(DISTINCT (CAST(s.port AS TEXT) || '/' || COALESCE(s.service,'?'))) AS sample
                FROM hosts h
                LEFT JOIN services s ON s.host_id = h.id
                GROUP BY h.id
                ORDER BY h.address";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                Rows.Add(new FindingRow(
                    Address: r.IsDBNull(0) ? string.Empty : r.GetString(0),
                    ServiceCount: r.IsDBNull(1) ? 0 : (int)r.GetInt64(1),
                    Services: r.IsDBNull(2) ? string.Empty : r.GetString(2)));
            }

            Status = $"{HostCount} host(s), {ServiceCount} service(s), {CveCount} CVE(s), {PocRefCount} PoC ref(s).";
            CanOpenDatasette = true;

            Directory.CreateDirectory(OutputDir);
            var auditPath = Path.Combine(OutputDir, "audit.jsonl");
            using var audit = new AuditLog(auditPath);
            audit.Record("ui.findings.reload", new Dictionary<string, object?>
            {
                ["hosts"] = HostCount,
                ["services"] = ServiceCount,
                ["cves"] = CveCount,
                ["poc_refs"] = PocRefCount,
            });
        }
        catch (SqliteException ex)
        {
            Status = $"Could not read findings.db: {ex.Message}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanOpenDatasette))]
    public void OpenDatasette()
    {
        // Launch our own CLI's `drederick serve` subcommand. This is the
        // harness itself, not a scanner binary — narrowly allowed.
        // @invariant-id:aggregate-not-execute is preserved because Datasette
        // only *reads* findings.db; it never runs a PoC.
        Directory.CreateDirectory(OutputDir);
        var auditPath = Path.Combine(OutputDir, "audit.jsonl");
        using var audit = new AuditLog(auditPath);
        audit.Record("ui.findings.open_datasette", new Dictionary<string, object?>
        {
            ["output_dir"] = OutputDir,
        });

        var exe = DrederickExecutablePath();
        try
        {
            var psi = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
            };
            psi.ArgumentList.Add("serve");
            psi.ArgumentList.Add("--out");
            psi.ArgumentList.Add(OutputDir);
            Process.Start(psi);
            Status = $"Launched `{Path.GetFileName(exe)} serve --out {OutputDir}` — check your browser for Datasette.";
        }
        catch (Exception ex)
        {
            Status = $"Failed to launch `drederick serve`: {ex.Message}";
        }
    }

    /// <summary>
    /// Best-effort path resolution: prefer <c>drederick</c> on PATH, fall
    /// back to <c>dotnet run --project src/Drederick</c> when we're running
    /// under a dev checkout.
    /// </summary>
    private static string DrederickExecutablePath()
    {
        // Environment override first, then PATH probe.
        var explicitPath = Environment.GetEnvironmentVariable("DREDERICK_CLI");
        if (!string.IsNullOrWhiteSpace(explicitPath) && File.Exists(explicitPath))
            return explicitPath;

        foreach (var name in new[] { "drederick", "drederick.exe" })
        {
            var onPath = WhichOnPath(name);
            if (onPath is not null) return onPath;
        }
        // Dev fallback: same directory as drederick-ui (ProjectReference
        // publishes drederick.dll alongside it).
        var here = AppContext.BaseDirectory;
        foreach (var candidate in new[] { "drederick", "drederick.exe" })
        {
            var p = Path.Combine(here, candidate);
            if (File.Exists(p)) return p;
        }
        return "drederick"; // last resort — Process.Start will error.
    }

    private static string? WhichOnPath(string name)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path)) return null;
        foreach (var dir in path.Split(Path.PathSeparator))
        {
            try
            {
                var candidate = Path.Combine(dir, name);
                if (File.Exists(candidate)) return candidate;
            }
            catch { /* ignore */ }
        }
        return null;
    }

    private static long ScalarLong(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var r = cmd.ExecuteScalar();
        return r is null or DBNull ? 0 : Convert.ToInt64(r);
    }

    private static int TryScalar(SqliteConnection conn, string sql)
    {
        try { return (int)ScalarLong(conn, sql); }
        catch (SqliteException) { return 0; }
    }
}

/// <summary>Presentation-layer row for a findings.db host.</summary>
public sealed record FindingRow(string Address, int ServiceCount, string Services);
