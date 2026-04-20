using Drederick.Audit;
using Drederick.Memory;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests;

public class KnowledgeBaseTests
{
    [Fact]
    public void Load_Missing_File_Returns_Empty()
    {
        var kb = KnowledgeBase.Load(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"));
        Assert.Empty(kb.Hosts);
    }

    [Fact]
    public void Save_Then_Load_Round_Trips()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            var kb = new KnowledgeBase();
            kb.Hosts["10.10.10.5"] = new HostFinding
            {
                Target = "10.10.10.5",
                Started = "2026-04-20T00:00:00Z",
                Finished = "2026-04-20T00:01:00Z",
                Nmap = new NmapResult
                {
                    ReturnCode = 0,
                    OpenPorts = { new NmapPort { Port = 22, Service = "ssh" } }
                },
            };
            kb.Save(path);

            var loaded = KnowledgeBase.Load(path);
            Assert.Single(loaded.Hosts);
            Assert.Equal(22, loaded.Hosts["10.10.10.5"].Nmap!.OpenPorts[0].Port);
            Assert.Contains("ssh", loaded.Digest("10.10.10.5"));
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Corrupt_File_Falls_Back_To_Empty()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json");
        try
        {
            File.WriteAllText(path, "{not-json");
            var kb = KnowledgeBase.Load(path);
            Assert.Empty(kb.Hosts);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public void Digest_For_Unknown_Target_Is_Informational()
    {
        var kb = new KnowledgeBase();
        Assert.Equal("(no prior findings)", kb.Digest("10.10.10.99"));
    }
}

public class AuditLogTests
{
    [Fact]
    public void Writes_JsonL_With_Required_Fields()
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".jsonl");
        try
        {
            using (var log = new AuditLog(path))
            {
                log.Record("test.event", new Dictionary<string, object?>
                {
                    ["target"] = "10.10.10.5",
                    ["n"] = 42,
                });
            }
            var lines = File.ReadAllLines(path);
            Assert.Single(lines);
            Assert.Contains("\"event\":\"test.event\"", lines[0]);
            Assert.Contains("\"target\":\"10.10.10.5\"", lines[0]);
            Assert.Contains("\"ts\":", lines[0]);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
