using Drederick.Memory;
using Xunit;

namespace Drederick.Tests.Memory;

public class BriefingMarkdownExtractorsTests
{
    [Fact]
    public void SplitSections_Splits_On_H2_Headers()
    {
        const string md = """
# Title

## Targets

- 10.10.10.5

## Users

- alice
- bob
""";
        var sections = BriefingMarkdownExtractors.SplitSections(md);
        Assert.True(sections.ContainsKey("Targets"));
        Assert.True(sections.ContainsKey("Users"));
        Assert.Contains(sections["Users"], l => l.Contains("alice"));
        Assert.Contains(sections["Users"], l => l.Contains("bob"));
    }

    [Fact]
    public void ExtractTargets_Strips_Comments_And_Parentheticals()
    {
        var lines = new[]
        {
            "- 10.10.10.5  # primary",
            "- 10.10.10.6 (dc)",
            "- 10.10.10.7 - file share",
            "  not a bullet",
        };
        var targets = BriefingMarkdownExtractors.ExtractTargets(lines);
        Assert.Equal(new[] { "10.10.10.5", "10.10.10.6", "10.10.10.7" }, targets);
    }

    [Fact]
    public void ExtractUsers_Picks_First_Token()
    {
        var lines = new[]
        {
            "- alice",
            "* bob (helpdesk)",
            "- svc_sql # service account",
        };
        var users = BriefingMarkdownExtractors.ExtractUsers(lines);
        Assert.Equal(new[] { "alice", "bob", "svc_sql" }, users);
    }

    [Fact]
    public void ExtractCredentials_Parses_Bullet_Plaintext()
    {
        var lines = new[] { "- alice:hunter2" };
        var creds = BriefingMarkdownExtractors.ExtractCredentials(lines);
        Assert.Single(creds);
        Assert.Equal("alice", creds[0].Username);
        Assert.Equal("password", creds[0].Kind);
        Assert.Equal("hunter2", creds[0].Secret);
    }

    [Fact]
    public void ExtractCredentials_Parses_Bullet_Ntlm()
    {
        var lines = new[] { "- bob NTLM:31d6cfe0d16ae931b73c59d7e0c089c0" };
        var creds = BriefingMarkdownExtractors.ExtractCredentials(lines);
        Assert.Single(creds);
        Assert.Equal("bob", creds[0].Username);
        Assert.Equal("ntlm", creds[0].Kind);
        Assert.Equal("31d6cfe0d16ae931b73c59d7e0c089c0", creds[0].Secret);
    }

    [Fact]
    public void ExtractCredentials_Parses_Markdown_Table_With_Kind_Column()
    {
        var lines = new[]
        {
            "| user | kind | secret |",
            "| --- | --- | --- |",
            "| alice | password | hunter2 |",
            "| bob | NTLM | aad3b435b51404eeaad3b435b51404ee |",
        };
        var creds = BriefingMarkdownExtractors.ExtractCredentials(lines);
        Assert.Equal(2, creds.Count);
        Assert.Equal("alice", creds[0].Username);
        Assert.Equal("password", creds[0].Kind);
        Assert.Equal("hunter2", creds[0].Secret);
        Assert.Equal("bob", creds[1].Username);
        Assert.Equal("ntlm", creds[1].Kind);
    }

    [Fact]
    public void ExtractCredentials_Parses_Markdown_Table_Without_Kind_Column()
    {
        var lines = new[]
        {
            "| user | password |",
            "| --- | --- |",
            "| alice | hunter2 |",
        };
        var creds = BriefingMarkdownExtractors.ExtractCredentials(lines);
        Assert.Single(creds);
        Assert.Equal("alice", creds[0].Username);
        Assert.Equal("password", creds[0].Kind);
        Assert.Equal("hunter2", creds[0].Secret);
    }

    [Fact]
    public void ExtractCredentials_Ignores_Garbage_Lines()
    {
        var lines = new[]
        {
            "not a credential",
            "- :no_user",
            "- justuser_no_secret:",
            "- alice:hunter2",
        };
        var creds = BriefingMarkdownExtractors.ExtractCredentials(lines);
        Assert.Single(creds);
        Assert.Equal("alice", creds[0].Username);
    }

    [Fact]
    public void ExtractConstraints_Returns_Each_Bullet_As_Constraint()
    {
        var lines = new[]
        {
            "- no DoS",
            "- no Tor exit",
            "- lockout: 5 per 30min",
        };
        var c = BriefingMarkdownExtractors.ExtractConstraints(lines);
        Assert.Equal(3, c.Count);
        Assert.Contains("no DoS", c);
        Assert.Contains("lockout: 5 per 30min", c);
    }

    [Fact]
    public void ExtractNotes_Joins_To_Single_String_Or_Null()
    {
        Assert.Null(BriefingMarkdownExtractors.ExtractNotes(Array.Empty<string>()));
        Assert.Null(BriefingMarkdownExtractors.ExtractNotes(new[] { "", "   ", "" }));
        var notes = BriefingMarkdownExtractors.ExtractNotes(new[] { "line 1", "line 2" });
        Assert.NotNull(notes);
        Assert.Contains("line 1", notes);
        Assert.Contains("line 2", notes);
    }

    [Fact]
    public void ExtractBulletList_Handles_Mixed_Bullet_Markers()
    {
        var lines = new[] { "- a", "* b", "+ c", "1. d", "• e", "no bullet" };
        var items = BriefingMarkdownExtractors.ExtractBulletList(lines);
        Assert.Equal(new[] { "a", "b", "c", "d", "e" }, items);
    }
}
