using System.Text;
using System.Text.Json;
using Drederick.Cli;
using Drederick.Exploit;
using Xunit;

namespace Drederick.Tests.Cli;

/// <summary>
/// Smoke tests for the `drederick windows-vulns` subcommand. The command
/// is read-only — no scope, no subprocess, no network — so tests run
/// fully offline against the bundled corpus + a fabricated PostEx JSON.
/// </summary>
public class WindowsVulnsCommandTests
{
    [Fact]
    public async Task List_Without_Json_Prints_Header_And_Rows()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new WindowsVulnsCommand(stdout, stderr);
        var opts = new CommandLineOptions
        {
            WindowsVulnsSubcommand = true,
            WindowsVulnsList = true,
        };

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        var text = stdout.ToString();
        Assert.Contains("Drederick Windows MSRC corpus", text);
        Assert.Contains("CVE-2017-0144", text);
        Assert.Contains("CVE-2020-1472", text);
    }

    [Fact]
    public async Task List_Json_Emits_Valid_Json_Array()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new WindowsVulnsCommand(stdout, stderr);
        var opts = new CommandLineOptions
        {
            WindowsVulnsSubcommand = true,
            WindowsVulnsList = true,
            WindowsVulnsJson = true,
        };

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(0, rc);
        var text = stdout.ToString();
        using var doc = JsonDocument.Parse(text);
        Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
        Assert.True(doc.RootElement.GetArrayLength() >= 30);
    }

    [Fact]
    public async Task Analyze_Without_PostEx_Json_Returns_Error_Code()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new WindowsVulnsCommand(stdout, stderr);
        var opts = new CommandLineOptions
        {
            WindowsVulnsSubcommand = true,
            WindowsVulnsAnalyze = true,
        };

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Contains("--postex-json", stderr.ToString());
    }

    [Fact]
    public async Task Analyze_With_Missing_File_Returns_Error_Code()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new WindowsVulnsCommand(stdout, stderr);
        var opts = new CommandLineOptions
        {
            WindowsVulnsSubcommand = true,
            WindowsVulnsAnalyze = true,
            WindowsVulnsPostExJson = "/tmp/does-not-exist-" + Guid.NewGuid(),
        };

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Contains("not found", stderr.ToString());
    }

    [Fact]
    public async Task Analyze_With_Win10_1809_PostEx_Surfaces_Candidates()
    {
        var jsonPath = Path.Combine(Path.GetTempPath(), $"drederick-postex-{Guid.NewGuid():N}.json");
        try
        {
            // Hand-roll a minimal PostEx JSON: Server 2019 DC, no patches.
            var postex = new PostExWindowsResult
            {
                Target = "10.10.10.5",
                HostInfo = new WindowsHostInfoResult
                {
                    OsName = "Microsoft Windows Server 2019 Datacenter",
                    OsBuild = "17763.1",
                },
                InstalledHotfixes = new InstalledHotfixesResult
                {
                    KbIds = new List<string> { "KB4000000" }, // unrelated
                },
            };
            var json = JsonSerializer.Serialize(postex);
            File.WriteAllText(jsonPath, json, Encoding.UTF8);

            var stdout = new StringWriter();
            var stderr = new StringWriter();
            var cmd = new WindowsVulnsCommand(stdout, stderr);
            var opts = new CommandLineOptions
            {
                WindowsVulnsSubcommand = true,
                WindowsVulnsAnalyze = true,
                WindowsVulnsPostExJson = jsonPath,
                WindowsVulnsJson = true,
            };

            var rc = await cmd.ExecuteAsync(opts);
            Assert.Equal(0, rc);
            var text = stdout.ToString();
            using var doc = JsonDocument.Parse(text);
            var candidates = doc.RootElement.GetProperty("candidates");
            Assert.True(candidates.GetArrayLength() > 0,
                "expected at least one MSRC candidate for unpatched Server 2019");
        }
        finally
        {
            if (File.Exists(jsonPath)) File.Delete(jsonPath);
        }
    }

    [Fact]
    public async Task Without_List_Or_Analyze_Prints_Usage()
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();
        var cmd = new WindowsVulnsCommand(stdout, stderr);
        var opts = new CommandLineOptions { WindowsVulnsSubcommand = true };

        var rc = await cmd.ExecuteAsync(opts);

        Assert.Equal(2, rc);
        Assert.Contains("--list", stderr.ToString());
    }

    [Fact]
    public void Cli_Parser_Recognises_Windows_Vulns_Subcommand()
    {
        var opts = CommandLineOptions.Parse(new[] { "windows-vulns", "--list" });
        Assert.True(opts.WindowsVulnsSubcommand);
        Assert.True(opts.WindowsVulnsList);
        Assert.False(opts.WindowsVulnsAnalyze);
    }

    [Fact]
    public void Cli_Parser_Recognises_Analyze_With_File()
    {
        var opts = CommandLineOptions.Parse(new[]
        {
            "windows-vulns", "--analyze", "--postex-json", "/tmp/foo.json", "--json",
        });
        Assert.True(opts.WindowsVulnsSubcommand);
        Assert.True(opts.WindowsVulnsAnalyze);
        Assert.Equal("/tmp/foo.json", opts.WindowsVulnsPostExJson);
        Assert.True(opts.WindowsVulnsJson);
    }
}
