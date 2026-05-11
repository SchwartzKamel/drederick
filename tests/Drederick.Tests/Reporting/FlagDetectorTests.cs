using Drederick.Reporting;
using Xunit;

namespace Drederick.Tests.Reporting;

public class FlagDetectorTests
{
    private readonly FlagDetector _det = new();

    [Fact]
    public void Detects_HTB_Braced_Flag()
    {
        var best = _det.DetectBest("trophy: HTB{w3lc0m3_t0_th3_b0x} on box",
            FlagSource.NetworkServiceResponse, "https://10.0.0.5/dashboard");
        Assert.NotNull(best);
        Assert.Equal("HTB{w3lc0m3_t0_th3_b0x}", best!.Value);
        Assert.True(best.Confidence >= 0.95, $"conf={best.Confidence}");
        Assert.Null(best.Rejection);
        Assert.Equal(FlagSource.ExplicitFlagMarker, best.Source);
    }

    [Fact]
    public void Detects_RootTxt_Content()
    {
        const string content = "abc123def456abc123def456abc12345\n";
        var best = _det.DetectBest(content, FlagSource.ShellCommandOutput, "/root/root.txt");
        Assert.NotNull(best);
        Assert.Equal("abc123def456abc123def456abc12345", best!.Value);
        Assert.True(best.Confidence >= 0.85, $"conf={best.Confidence}");
        Assert.Null(best.Rejection);
    }

    [Fact]
    public void Rejects_Hex_In_URL_Path()
    {
        var results = _det.Detect(
            "GET /api/file/abc123def456abc123def456abc12345/download HTTP/1.1",
            FlagSource.NetworkServiceResponse,
            "https://target/api/file/abc123def456abc123def456abc12345/download");
        Assert.All(results, r => Assert.NotNull(r.Rejection));
        Assert.Null(_det.DetectBest(
            "GET /api/file/abc123def456abc123def456abc12345/download HTTP/1.1",
            FlagSource.NetworkServiceResponse,
            "https://target/api/file/abc123def456abc123def456abc12345/download"));
    }

    [Fact]
    public void Rejects_Hex_In_JSON_Key()
    {
        var content = "{\"abc123def456abc123def456abc12345\": \"value\"}";
        var best = _det.DetectBest(content, FlagSource.NetworkServiceResponse, "response.json");
        Assert.Null(best);
        var all = _det.Detect(content, FlagSource.NetworkServiceResponse, "response.json");
        var hex = Assert.Single(all);
        Assert.NotNull(hex.Rejection);
        Assert.Contains("json", hex.Rejection!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_GUID_Dashed()
    {
        // Dashed GUIDs cannot match \b[hex]{32}\b — nothing surfaces.
        var content = "session=550e8400-e29b-41d4-a716-446655440000;";
        var best = _det.DetectBest(content, FlagSource.NetworkServiceResponse, "/api/sess");
        Assert.Null(best);
    }

    [Fact]
    public void Rejects_GUID_Brace_Literal()
    {
        var content = "guid={abc123def456abc123def456abc12345}";
        var all = _det.Detect(content, FlagSource.ShellCommandOutput, "/tmp/out");
        var hex = Assert.Single(all);
        Assert.NotNull(hex.Rejection);
        Assert.Contains("guid", hex.Rejection!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_Vulners_Id()
    {
        var best = _det.DetectBest(
            "vulners:abc123def456abc123def456abc12345",
            FlagSource.ScanMetadata, "nmap-vulners");
        Assert.Null(best);
    }

    [Fact]
    public void Rejects_Etag()
    {
        var best = _det.DetectBest(
            "ETag: abc123def456abc123def456abc12345",
            FlagSource.NetworkServiceResponse, "http-headers");
        Assert.Null(best);
    }

    [Fact]
    public void Rejects_Sha256_Prefix()
    {
        var best = _det.DetectBest(
            "sha256:abc123def456abc123def456abc12345",
            FlagSource.FileSystemContent, "manifest.txt");
        Assert.Null(best);
    }

    [Fact]
    public void Rejects_Cve_Same_Line()
    {
        var best = _det.DetectBest(
            "CVE-2021-1234 references abc123def456abc123def456abc12345",
            FlagSource.ScanMetadata, "searchsploit.json");
        Assert.Null(best);
    }

    [Fact]
    public void Accepts_HTB_In_HTML_Body()
    {
        var body = "<html><body>flag is HTB{p0wn3d_via_web} congrats</body></html>";
        var best = _det.DetectBest(body, FlagSource.NetworkServiceResponse,
            "https://10.0.0.5/?q=1");
        Assert.NotNull(best);
        Assert.Equal("HTB{p0wn3d_via_web}", best!.Value);
        Assert.True(best.Confidence >= 0.95);
    }

    [Fact]
    public void Multiple_Flags_Returns_All()
    {
        var content =
            "HTB{first_flag_value}\n" +
            "flag{second_one_here}\n" +
            "picoCTF{third_pico_one}";
        var results = _det.Detect(content, FlagSource.FileSystemContent, "loot.txt");
        var accepted = results.Where(r => r.Rejection is null).ToList();
        Assert.Equal(3, accepted.Count);
        Assert.Contains(accepted, r => r.Value == "HTB{first_flag_value}");
        Assert.Contains(accepted, r => r.Value == "flag{second_one_here}");
        Assert.Contains(accepted, r => r.Value == "picoCTF{third_pico_one}");
    }

    [Fact]
    public void Best_Returns_Highest_Confidence()
    {
        var content = "noise abc123def456abc123def456abc12345 then HTB{the_real_flag} end";
        var best = _det.DetectBest(content, FlagSource.FileSystemContent, "scratch.txt");
        Assert.NotNull(best);
        Assert.Equal("HTB{the_real_flag}", best!.Value);
    }

    [Fact]
    public void Empty_Content_Returns_Empty()
    {
        Assert.Empty(_det.Detect(null, FlagSource.FileSystemContent, "x"));
        Assert.Empty(_det.Detect("", FlagSource.FileSystemContent, "x"));
        Assert.Empty(_det.Detect("   \n\t  ", FlagSource.FileSystemContent, "x"));
        Assert.Null(_det.DetectBest(null, FlagSource.FileSystemContent, "x"));
        Assert.Null(_det.DetectBest("", FlagSource.FileSystemContent, "x"));
    }

    [Fact]
    public void Source_Priority_Influences_Confidence()
    {
        const string hex = "abc123def456abc123def456abc12345";
        var fromScan = _det.DetectBest(hex, FlagSource.ScanMetadata, "nmap-banner");
        var fromFs = _det.DetectBest(hex, FlagSource.FileSystemContent, "loot/data.bin");
        var fromShell = _det.DetectBest(hex, FlagSource.ShellCommandOutput, "/root/root.txt");
        Assert.NotNull(fromScan);
        Assert.NotNull(fromFs);
        Assert.NotNull(fromShell);
        Assert.True(fromScan!.Confidence < fromFs!.Confidence,
            $"scan={fromScan.Confidence} fs={fromFs.Confidence}");
        Assert.True(fromFs.Confidence < fromShell!.Confidence,
            $"fs={fromFs.Confidence} shell={fromShell.Confidence}");
    }

    [Fact]
    public void Url_Origin_Rejects_Bare_Hex()
    {
        var best = _det.DetectBest(
            "id=abc123def456abc123def456abc12345 found",
            FlagSource.NetworkServiceResponse,
            "https://target/api/v1?id=abc123def456abc123def456abc12345");
        Assert.Null(best);
    }

    [Fact]
    public void Csrf_Token_Rejected()
    {
        var best = _det.DetectBest(
            "csrf_token=abc123def456abc123def456abc12345",
            FlagSource.NetworkServiceResponse, "form-body");
        Assert.Null(best);
    }
}
