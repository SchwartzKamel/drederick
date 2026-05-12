using System.Text.Json;
using Xunit;

namespace Drederick.Tests.Datasette;

/// <summary>
/// Wave D: assert that the Empire canned queries and per-table metadata
/// are wired up in <c>datasette/metadata.json</c>. The schema is checked
/// by the generic <c>DatasetteMetadataTests</c>; here we only verify
/// the Empire-specific surface.
/// </summary>
public class EmpireMetadataTests
{
    private static string FindMetadataPath()
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "datasette", "metadata.json");
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException("datasette/metadata.json not found walking up from test binary.");
    }

    private static JsonElement Findings() =>
        JsonDocument.Parse(File.ReadAllText(FindMetadataPath()))
            .RootElement.GetProperty("databases").GetProperty("findings");

    [Theory]
    [InlineData("empire_active_agents")]
    [InlineData("empire_agents_per_host")]
    [InlineData("empire_modules_recent")]
    [InlineData("empire_creds_harvested")]
    [InlineData("empire_listener_summary")]
    [InlineData("empire_lifecycle_audit")]
    [InlineData("empire_host_compromise_chain")]
    public void EmpireCannedQuery_IsDeclared(string name)
    {
        var queries = Findings().GetProperty("queries");
        Assert.True(queries.TryGetProperty(name, out var q),
            $"missing canned query '{name}'");
        var sql = q.GetProperty("sql").GetString();
        Assert.False(string.IsNullOrWhiteSpace(sql), $"query '{name}' has empty sql");
    }

    [Fact]
    public void PreExistingCannedQueries_ArePreserved()
    {
        var names = Findings().GetProperty("queries").EnumerateObject()
            .Select(p => p.Name).ToHashSet();
        Assert.Contains("cves_by_host", names);
        Assert.Contains("services_with_pocs", names);
        Assert.Contains("pocs_by_source", names);
        Assert.Contains("tooling_detected", names);
        Assert.Contains("top_cves_by_cvss", names);
    }

    [Theory]
    [InlineData("empire_servers", "host", new[] { "status" })]
    [InlineData("empire_listeners", "name", new[] { "type" })]
    [InlineData("empire_agents", "external_id", new[] { "status", "os", "language" })]
    public void EmpireTable_HasLabelAndFacets(string table, string label, string[] expectedFacets)
    {
        var tables = Findings().GetProperty("tables");
        Assert.True(tables.TryGetProperty(table, out var t), $"missing table metadata for '{table}'");
        Assert.Equal(label, t.GetProperty("label_column").GetString());

        var facets = t.GetProperty("facets").EnumerateArray()
            .Select(e => e.GetString() ?? "").ToHashSet();
        foreach (var f in expectedFacets)
            Assert.Contains(f, facets);
    }

    [Fact]
    public void EmpireModulesExecuted_HasSearchableModuleName()
    {
        var tables = Findings().GetProperty("tables");
        Assert.True(tables.TryGetProperty("empire_modules_executed", out var t));
        var searchable = t.GetProperty("searchable").EnumerateArray()
            .Select(e => e.GetString() ?? "").ToHashSet();
        Assert.Contains("module_name", searchable);
    }

    [Theory]
    [InlineData("empire_listeners", "server_id")]
    [InlineData("empire_agents", "server_id")]
    [InlineData("empire_agents", "listener_id")]
    [InlineData("empire_agents", "host_id")]
    [InlineData("empire_modules_executed", "agent_id")]
    public void EmpireTable_DeclaresForeignKeyColumn(string table, string column)
    {
        var tables = Findings().GetProperty("tables");
        Assert.True(tables.TryGetProperty(table, out var t));
        Assert.True(t.TryGetProperty("columns", out var cols),
            $"{table} has no 'columns' block");
        Assert.True(cols.TryGetProperty(column, out var c),
            $"{table}.columns missing entry for '{column}'");
        Assert.True(c.TryGetProperty("foreign_key", out _),
            $"{table}.columns.{column} missing 'foreign_key' declaration");
    }
}
