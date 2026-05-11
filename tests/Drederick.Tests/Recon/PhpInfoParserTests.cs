using Drederick.Recon;
using Xunit;

namespace Drederick.Tests.Recon;

public class PhpInfoParserTests
{
    private static string FindFixturePath(string name)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "tests", "fixtures", "phpinfo", name);
            if (File.Exists(candidate)) return candidate;
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException($"phpinfo fixture not found: {name}");
    }

    [Fact]
    public void Parse_PterodactylFixture_ExtractsAllTwelveDirectives()
    {
        var html = File.ReadAllText(FindFixturePath("pterodactyl.html"));
        var f = PhpInfoParser.Parse(html, "/phpinfo.php");

        Assert.Equal("8.4.8", f.PhpVersion);
        Assert.Equal("", f.DisableFunctions);
        Assert.Equal("", f.OpenBasedir);
        Assert.Equal("On", f.AllowUrlFopen);
        Assert.Equal("Off", f.AllowUrlInclude);
        Assert.Equal("On", f.FileUploads);
        Assert.Equal("2M", f.UploadMaxFilesize);
        Assert.Equal("", f.UploadTmpDir);
        Assert.Equal(".user.ini", f.UserIniFilename);
        Assert.Equal("", f.SessionSavePath);
        Assert.Equal(".:/usr/share/php8:/usr/share/php/PEAR", f.IncludePath);
        Assert.Equal("wwwrun", f.FpmUser);
        Assert.Equal("www", f.FpmGroup);

        Assert.True(f.RceOnWriteLikely,
            "empty disable_functions + empty open_basedir + file_uploads=On => write-then-execute is feasible");
        Assert.True(f.UserIniInjectionLikely,
            ".user.ini is honoured; uploaded directories with .user.ini can override php settings");
        Assert.Equal("/phpinfo.php", f.SourcePath);
    }

    [Fact]
    public void Parse_HardenedFixture_RceOnWriteLikelyIsFalse()
    {
        var html = File.ReadAllText(FindFixturePath("hardened.html"));
        var f = PhpInfoParser.Parse(html, "/info.php");

        Assert.Equal("8.2.18", f.PhpVersion);
        Assert.NotEqual("", f.DisableFunctions);
        Assert.Contains("exec", f.DisableFunctions);
        Assert.Equal("/var/www/html:/tmp", f.OpenBasedir);
        Assert.Equal("Off", f.FileUploads);
        Assert.Equal("/var/php-uploads", f.UploadTmpDir);
        Assert.Equal("/var/lib/php/sessions", f.SessionSavePath);
        Assert.Equal("www-data", f.FpmUser);
        Assert.Equal("www-data", f.FpmGroup);

        Assert.False(f.RceOnWriteLikely);
        Assert.False(f.UserIniInjectionLikely);
    }

    [Fact]
    public void Parse_MultiPoolFixture_ReturnsFirstPoolFpmIdentity()
    {
        var html = File.ReadAllText(FindFixturePath("multipool.html"));
        var f = PhpInfoParser.Parse(html);

        Assert.Equal("poolA-user", f.FpmUser);
        Assert.Equal("poolA-grp", f.FpmGroup);
        Assert.True(f.RceOnWriteLikely);
        Assert.True(f.UserIniInjectionLikely);
    }

    [Fact]
    public void Parse_EmptyOrMalformedHtml_ReturnsEmptyFinding()
    {
        var f = PhpInfoParser.Parse("", "/x");
        Assert.Equal("", f.PhpVersion);
        Assert.Equal("", f.DisableFunctions);
        Assert.False(f.RceOnWriteLikely);
        Assert.False(f.UserIniInjectionLikely);

        var g = PhpInfoParser.Parse("<html><body>not phpinfo at all</body></html>");
        Assert.Equal("", g.PhpVersion);
        Assert.Equal("", g.FpmUser);
        Assert.False(g.RceOnWriteLikely);
    }

    [Fact]
    public void Parse_NoTablesButTitlePresent_StillReturnsVersion()
    {
        var html = "<html><head><title>PHP 7.4.33 - phpinfo()</title></head><body>truncated</body></html>";
        var f = PhpInfoParser.Parse(html);
        Assert.Equal("7.4.33", f.PhpVersion);
        Assert.False(f.RceOnWriteLikely);
    }

    [Fact]
    public void LooksLikePhpInfo_DetectsTitleSignature()
    {
        Assert.True(PhpInfoParser.LooksLikePhpInfo(
            "<html><head><title>PHP 8.1.0 - phpinfo()</title></head><body/></html>"));
        Assert.True(PhpInfoParser.LooksLikePhpInfo("...phpinfo() output..."));
        Assert.False(PhpInfoParser.LooksLikePhpInfo("<html><body>hello</body></html>"));
        Assert.False(PhpInfoParser.LooksLikePhpInfo(""));
        Assert.False(PhpInfoParser.LooksLikePhpInfo(null));
    }

    [Fact]
    public void Parse_HtmlEntitiesAreDecodedInValues()
    {
        var html = "<html><head><title>PHP 8.0.0 - phpinfo()</title></head><body>"
                   + "<table><tr><td class=\"e\">Configure Command </td>"
                   + "<td class=\"v\"> &#039;--with-fpm-user=nginx&#039; &#039;--with-fpm-group=nginx&#039; </td></tr></table>"
                   + "</body></html>";
        var f = PhpInfoParser.Parse(html);
        Assert.Equal("nginx", f.FpmUser);
        Assert.Equal("nginx", f.FpmGroup);
    }
}
