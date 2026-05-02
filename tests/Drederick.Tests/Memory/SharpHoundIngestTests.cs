using System.IO.Compression;
using System.Text;
using Drederick.Memory;
using Xunit;

namespace Drederick.Tests.Memory;

public class SharpHoundIngestTests
{
    private static string TempDir()
    {
        var d = Path.Combine(Path.GetTempPath(), $"drederick-bh-{Guid.NewGuid():N}");
        Directory.CreateDirectory(d);
        return d;
    }

    private static string ComputersV2Json =>
        """
        {
          "data": [
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-1001",
              "Properties": {
                "name": "DC01.CORP.LAB",
                "dnshostname": "dc01.corp.lab",
                "domain": "CORP.LAB",
                "operatingsystem": "Windows Server 2019",
                "enabled": true,
                "highvalue": true,
                "unconstraineddelegation": true,
                "haslaps": false,
                "owned": false
              }
            },
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-1002",
              "Properties": {
                "name": "WS01.CORP.LAB",
                "dnshostname": "ws01.corp.lab",
                "domain": "CORP.LAB",
                "operatingsystem": "Windows 10",
                "enabled": true,
                "highvalue": false,
                "unconstraineddelegation": false,
                "haslaps": true,
                "owned": false
              }
            }
          ],
          "meta": { "type": "computers", "count": 2, "version": 5 }
        }
        """;

    private static string UsersV2Json =>
        """
        {
          "data": [
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-1100",
              "Properties": {
                "name": "alice@CORP.LAB",
                "domain": "CORP.LAB",
                "enabled": true,
                "admincount": true,
                "dontreqpreauth": false,
                "hasspn": false,
                "highvalue": false,
                "sensitive": false
              }
            },
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-1101",
              "Properties": {
                "name": "svc-mssql@CORP.LAB",
                "domain": "CORP.LAB",
                "enabled": true,
                "admincount": false,
                "dontreqpreauth": false,
                "hasspn": true,
                "highvalue": false,
                "unconstraineddelegation": false
              }
            },
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-1102",
              "Properties": {
                "name": "legacy-svc@CORP.LAB",
                "domain": "CORP.LAB",
                "enabled": true,
                "admincount": false,
                "dontreqpreauth": true,
                "hasspn": false,
                "highvalue": false
              }
            }
          ],
          "meta": { "type": "users", "count": 3, "version": 5 }
        }
        """;

    private static string GroupsV2Json =>
        """
        {
          "data": [
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-512",
              "Properties": {
                "name": "DOMAIN ADMINS@CORP.LAB",
                "domain": "CORP.LAB",
                "highvalue": true
              },
              "Members": [
                { "ObjectIdentifier": "S-1-5-21-1-2-3-1100", "ObjectType": "User" }
              ]
            },
            {
              "ObjectIdentifier": "S-1-5-21-1-2-3-513",
              "Properties": {
                "name": "DOMAIN USERS@CORP.LAB",
                "domain": "CORP.LAB",
                "highvalue": false
              }
            }
          ],
          "meta": { "type": "groups", "count": 2, "version": 5 }
        }
        """;

    private static string DomainsV2Json =>
        """
        {
          "data": [
            { "ObjectIdentifier": "S-1-5-21-1-2-3", "Properties": { "name": "CORP.LAB" } }
          ],
          "meta": { "type": "domains", "count": 1, "version": 5 }
        }
        """;

    [Fact]
    public void IngestJsonFile_Computers_Populates_Findings()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "computers.json");
            File.WriteAllText(path, ComputersV2Json);
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Empty(r.Errors);
            Assert.Equal(1, r.FilesIngested);
            Assert.Equal(2, f.Computers.Count);
            var dc = f.Computers.First(c => c.Name == "DC01.CORP.LAB");
            Assert.True(dc.UnconstrainedDelegation);
            Assert.True(dc.HighValue);
            Assert.Equal("dc01.corp.lab", dc.DnsHostName);
            Assert.Equal(1, r.UnconstrainedDelegationComputers);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_Users_Flags_Kerberoastable_And_AsReproastable()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "users.json");
            File.WriteAllText(path, UsersV2Json);
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Empty(r.Errors);
            Assert.Equal(3, f.Users.Count);
            Assert.Equal(1, r.KerberoastableUsers);
            Assert.Equal(1, r.AsRepRoastableUsers);
            var sql = f.Users.First(u => u.Name.StartsWith("svc-mssql"));
            Assert.True(sql.HasSpn);
            var legacy = f.Users.First(u => u.Name.StartsWith("legacy-svc"));
            Assert.True(legacy.DontReqPreauth);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_Groups_Captures_HighValue_And_MemberCount()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "groups.json");
            File.WriteAllText(path, GroupsV2Json);
            var f = new BloodhoundFindings();
            SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Equal(2, f.Groups.Count);
            var da = f.Groups.First(g => g.Name.StartsWith("DOMAIN ADMINS"));
            Assert.True(da.HighValue);
            Assert.Equal(1, da.MemberCount);
            Assert.Contains("DOMAIN ADMINS@CORP.LAB", f.HighValueGroups);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestZip_Dispatches_All_Streams()
    {
        var dir = TempDir();
        var zipPath = Path.Combine(dir, "sharphound.zip");
        try
        {
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                AddText(zip, "20240501130000_computers.json", ComputersV2Json);
                AddText(zip, "20240501130000_users.json", UsersV2Json);
                AddText(zip, "20240501130000_groups.json", GroupsV2Json);
                AddText(zip, "20240501130000_domains.json", DomainsV2Json);
                AddText(zip, "readme.txt", "this is not json");
            }
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestZip(zipPath, f);
            Assert.Empty(r.Errors);
            Assert.Equal(4, r.FilesIngested);
            Assert.Equal(2, r.Computers);
            Assert.Equal(3, r.Users);
            Assert.Equal(2, r.Groups);
            Assert.Equal(1, r.Domains);
            Assert.Equal(1, r.UnconstrainedDelegationComputers);
            Assert.Equal(1, r.KerberoastableUsers);
            Assert.Equal(1, r.AsRepRoastableUsers);
            Assert.Equal(1, r.HighValueGroups);
            Assert.Equal(zipPath, f.SourceZip);
            Assert.NotNull(f.IngestedAt);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestZip_Skips_Oversize_Entries()
    {
        var dir = TempDir();
        var zipPath = Path.Combine(dir, "huge.zip");
        try
        {
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                AddText(zip, "computers.json", new string('x', 5 * 1024));
            }
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestZip(zipPath, f, perEntryByteCap: 1024);
            Assert.Single(r.Errors);
            Assert.Contains("exceeds cap", r.Errors[0]);
            Assert.Equal(0, r.FilesIngested);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_Missing_File_Returns_Error_Not_Throw()
    {
        var f = new BloodhoundFindings();
        var r = SharpHoundIngest.IngestJsonFile("/nonexistent/path.json", f);
        Assert.Single(r.Errors);
        Assert.Contains("file not found", r.Errors[0]);
    }

    [Fact]
    public void IngestZip_Missing_File_Returns_Error_Not_Throw()
    {
        var f = new BloodhoundFindings();
        var r = SharpHoundIngest.IngestZip("/nonexistent/sharphound.zip", f);
        Assert.Single(r.Errors);
        Assert.Contains("file not found", r.Errors[0]);
    }

    [Fact]
    public void IngestJsonFile_Tolerates_Bad_Json_Per_File()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "bad.json");
            File.WriteAllText(path, "{ this is not json");
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Single(r.Errors);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_Tolerates_Missing_Properties_Block()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "computers.json");
            File.WriteAllText(path, """
                { "data": [{"ObjectIdentifier":"S-1-5-21-1-2-3-9999"}],
                  "meta": {"type":"computers","count":1} }
                """);
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Empty(r.Errors);
            Assert.Single(f.Computers);
            Assert.Equal("S-1-5-21-1-2-3-9999", f.Computers[0].ObjectId);
            Assert.Equal("", f.Computers[0].Name);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_Handles_Boolean_As_String_Or_Number()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "users.json");
            File.WriteAllText(path, """
                { "data": [
                    {"ObjectIdentifier":"a","Properties":{"name":"a","hasspn":"true","dontreqpreauth":1}},
                    {"ObjectIdentifier":"b","Properties":{"name":"b","hasspn":"false","dontreqpreauth":0}}
                  ],
                  "meta": {"type":"users"} }
                """);
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Empty(r.Errors);
            Assert.Equal(1, r.KerberoastableUsers);
            Assert.Equal(1, r.AsRepRoastableUsers);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestJsonFile_V1_Format_Computers_Array_Recognized()
    {
        var dir = TempDir();
        try
        {
            var path = Path.Combine(dir, "computers_v1.json");
            File.WriteAllText(path, """
                { "Computers": [
                    {"ObjectIdentifier":"x","Properties":{"name":"X","unconstraineddelegation":true}}
                  ] }
                """);
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestJsonFile(path, f);
            Assert.Empty(r.Errors);
            Assert.Single(f.Computers);
            Assert.True(f.Computers[0].UnconstrainedDelegation);
            Assert.Equal(1, r.UnconstrainedDelegationComputers);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void KnowledgeBase_IngestSharpHoundZip_Persists_And_Round_Trips()
    {
        var dir = TempDir();
        var zipPath = Path.Combine(dir, "bh.zip");
        var kbPath = Path.Combine(dir, "memory.json");
        try
        {
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                AddText(zip, "users.json", UsersV2Json);
                AddText(zip, "computers.json", ComputersV2Json);
            }

            var kb = new KnowledgeBase();
            var r = kb.IngestSharpHoundZip(zipPath);
            Assert.Empty(r.Errors);
            Assert.NotNull(kb.Bloodhound);
            Assert.Equal(2, kb.Bloodhound!.Computers.Count);
            Assert.Equal(3, kb.Bloodhound.Users.Count);

            kb.Save(kbPath);
            var loaded = KnowledgeBase.Load(kbPath);
            Assert.NotNull(loaded.Bloodhound);
            Assert.Equal(2, loaded.Bloodhound!.Computers.Count);
            Assert.Equal(3, loaded.Bloodhound.Users.Count);
            Assert.Equal(zipPath, loaded.Bloodhound.SourceZip);
            Assert.Contains(loaded.Bloodhound.Users, u => u.HasSpn);
            Assert.Contains(loaded.Bloodhound.Users, u => u.DontReqPreauth);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void KnowledgeBase_IngestSharpHoundJsonFile_Appends()
    {
        var dir = TempDir();
        try
        {
            var p1 = Path.Combine(dir, "users.json");
            var p2 = Path.Combine(dir, "computers.json");
            File.WriteAllText(p1, UsersV2Json);
            File.WriteAllText(p2, ComputersV2Json);
            var kb = new KnowledgeBase();
            kb.IngestSharpHoundJsonFile(p1);
            kb.IngestSharpHoundJsonFile(p2);
            Assert.NotNull(kb.Bloodhound);
            Assert.Equal(3, kb.Bloodhound!.Users.Count);
            Assert.Equal(2, kb.Bloodhound.Computers.Count);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void IngestZip_Bounded_Read_Stops_If_Decompressed_Size_Exceeds_Cap()
    {
        // Defense-in-depth: even if `entry.Length` is small or lies,
        // the read loop must abort once decompressed bytes exceed the cap.
        // We force this by setting the cap below the actual content size.
        var dir = TempDir();
        var zipPath = Path.Combine(dir, "decompbomb.zip");
        try
        {
            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                AddText(zip, "computers.json", new string('A', 200_000));
            }
            var f = new BloodhoundFindings();
            var r = SharpHoundIngest.IngestZip(zipPath, f, perEntryByteCap: 50_000);
            // Length-precheck or read-loop precheck both lead to a skip + error.
            Assert.NotEmpty(r.Errors);
            Assert.Equal(0, r.FilesIngested);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    private static void AddText(ZipArchive zip, string name, string contents)
    {
        var e = zip.CreateEntry(name);
        using var s = e.Open();
        var bytes = Encoding.UTF8.GetBytes(contents);
        s.Write(bytes, 0, bytes.Length);
    }
}
