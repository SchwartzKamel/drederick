using System.Text.Json;
using Drederick.Recon;
using Drederick.Reporting;
using Microsoft.Data.Sqlite;
using Xunit;

namespace Drederick.Tests;

public class DatasetteMetadataTests : IDisposable
{
    private readonly string _dir;

    public DatasetteMetadataTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "drederick-datasette-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static string FindMetadataPath()
    {
        // Walk upward from the test assembly location until we find datasette/metadata.json.
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "datasette", "metadata.json");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException("datasette/metadata.json not found walking up from test binary.");
    }

    private static JsonElement LoadMetadata() =>
        JsonDocument.Parse(File.ReadAllText(FindMetadataPath())).RootElement;

    private SqliteConnection OpenFreshSchema()
    {
        // Instantiating SqliteReport + issuing a trivial write materialises the full schema.
        var report = new SqliteReport(_dir);
        report.UpsertCve("CVE-0000-0000", cvss: 0.0, summary: "schema-prime", published: "1970-01-01T00:00:00Z");
        var conn = new SqliteConnection($"Data Source={report.DatabasePath}");
        conn.Open();
        return conn;
    }

    [Fact]
    public void MetadataFile_ParsesAsJson()
    {
        var root = LoadMetadata();
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.True(root.TryGetProperty("databases", out var dbs));
        Assert.True(dbs.TryGetProperty("findings", out _));
    }

    [Fact]
    public void AllReferencedTablesExistInSchema()
    {
        var root = LoadMetadata();
        var findings = root.GetProperty("databases").GetProperty("findings");

        using var conn = OpenFreshSchema();
        var existingTables = new HashSet<string>(StringComparer.Ordinal);
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
            using var r = cmd.ExecuteReader();
            while (r.Read()) existingTables.Add(r.GetString(0));
        }

        var tables = findings.GetProperty("tables");
        foreach (var t in tables.EnumerateObject())
        {
            Assert.True(existingTables.Contains(t.Name), $"metadata references missing table '{t.Name}'");
        }
    }

    [Fact]
    public void EveryCannedQuery_PreparesAgainstSchema()
    {
        var root = LoadMetadata();
        var findings = root.GetProperty("databases").GetProperty("findings");
        Assert.True(findings.TryGetProperty("queries", out var queries));

        using var conn = OpenFreshSchema();
        foreach (var q in queries.EnumerateObject())
        {
            var sql = q.Value.GetProperty("sql").GetString();
            Assert.False(string.IsNullOrWhiteSpace(sql), $"query '{q.Name}' has empty sql");

            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql!;
            // Prepare() parses + binds without executing; a syntactic or schema error throws.
            cmd.Prepare();
        }
    }

    [Fact]
    public void ExpectedFacetsAreDeclared()
    {
        var root = LoadMetadata();
        var tables = root.GetProperty("databases").GetProperty("findings").GetProperty("tables");

        static string[] Facets(JsonElement table) =>
            table.TryGetProperty("facets", out var f)
                ? f.EnumerateArray().Select(e => e.GetString() ?? "").ToArray()
                : Array.Empty<string>();

        Assert.Superset(new HashSet<string> { "proto", "service", "product" }, new HashSet<string>(Facets(tables.GetProperty("services"))));
        Assert.Superset(new HashSet<string> { "kind", "host_id" }, new HashSet<string>(Facets(tables.GetProperty("findings"))));
        Assert.Superset(new HashSet<string> { "cvss", "published" }, new HashSet<string>(Facets(tables.GetProperty("cves"))));
        Assert.Contains("source", Facets(tables.GetProperty("poc_refs")));
        Assert.Contains("source", Facets(tables.GetProperty("tooling")));
    }

    [Fact]
    public void ExpectedLabelColumnsAreDeclared()
    {
        var root = LoadMetadata();
        var tables = root.GetProperty("databases").GetProperty("findings").GetProperty("tables");

        Assert.Equal("address", tables.GetProperty("hosts").GetProperty("label_column").GetString());
        Assert.Equal("cve_id", tables.GetProperty("cves").GetProperty("label_column").GetString());
    }

    [Fact]
    public void ExpectedCannedQueriesArePresent()
    {
        var root = LoadMetadata();
        var queries = root.GetProperty("databases").GetProperty("findings").GetProperty("queries");
        var names = queries.EnumerateObject().Select(p => p.Name).ToHashSet();
        Assert.Contains("cves_by_host", names);
        Assert.Contains("services_with_pocs", names);
        Assert.Contains("pocs_by_source", names);
        Assert.Contains("tooling_detected", names);
        Assert.Contains("top_cves_by_cvss", names);
    }
}
