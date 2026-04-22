using System.Text.Json;
using Drederick.Cli;
using Drederick.Jeopardy.Cli;
using Xunit;

namespace Drederick.Tests.Cli;

public class CtfMsgCliTests
{
    [Fact]
    public void Parses_Hint_Message_Flags()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "ctf-msg", "--kind", "hint", "--chal", "7", "--body", "hi there",
        });
        Assert.True(o.CtfMsgSubcommand);
        Assert.Equal("hint", o.CtfMsgKind);
        Assert.Equal("7", o.CtfMsgChallengeId);
        Assert.Equal("hi there", o.CtfMsgBody);
    }

    [Fact]
    public void Parses_Solver_And_Inbox_Override()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "dx-" + Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            var o = CommandLineOptions.Parse(new[]
            {
                "ctf-msg", "--kind", "focus", "--solver", "claude@c1",
                "--inbox", tmp,
            });
            Assert.True(o.CtfMsgSubcommand);
            Assert.Equal("focus", o.CtfMsgKind);
            Assert.Equal("claude@c1", o.CtfMsgSolverId);
            Assert.Equal(tmp, o.CtfInboxPath);
        }
        finally { try { File.Delete(tmp); } catch { } }
    }

    [Fact]
    public async Task RunAsync_Writes_Valid_Jsonl_Line()
    {
        var tmpRoot = Path.Combine(Path.GetTempPath(), "drederick-ctfmsg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpRoot);
        try
        {
            var inbox = Path.Combine(tmpRoot, "sub", "inbox.jsonl");
            var opts = CommandLineOptions.Parse(new[]
            {
                "ctf-msg", "--kind", "hint", "--chal", "42",
                "--body", "try ret2libc",
                "--inbox", inbox,
                "--out", tmpRoot,
            });

            var exit = await CtfMsgRunner.RunAsync(opts, CancellationToken.None);
            Assert.Equal(0, exit);
            Assert.True(File.Exists(inbox));
            var lines = File.ReadAllLines(inbox);
            Assert.Single(lines);

            using var doc = JsonDocument.Parse(lines[0]);
            var root = doc.RootElement;
            Assert.Equal("hint", root.GetProperty("Kind").GetString());
            Assert.Equal("42", root.GetProperty("ChallengeId").GetString());
            Assert.Equal("try ret2libc", root.GetProperty("Body").GetString());
        }
        finally { try { Directory.Delete(tmpRoot, recursive: true); } catch { } }
    }

    [Fact]
    public async Task RunAsync_Rejects_Missing_Kind()
    {
        var opts = CommandLineOptions.Parse(new[] { "ctf-msg" });
        var exit = await CtfMsgRunner.RunAsync(opts, CancellationToken.None);
        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task RunAsync_Rejects_Invalid_Kind()
    {
        var opts = CommandLineOptions.Parse(new[] { "ctf-msg", "--kind", "bogus" });
        var exit = await CtfMsgRunner.RunAsync(opts, CancellationToken.None);
        Assert.Equal(2, exit);
    }

    [Fact]
    public async Task RunAsync_Accepts_Stop_Kind_Without_Body()
    {
        var tmpRoot = Path.Combine(Path.GetTempPath(), "drederick-ctfmsg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmpRoot);
        try
        {
            var inbox = Path.Combine(tmpRoot, "inbox.jsonl");
            var opts = CommandLineOptions.Parse(new[]
            {
                "ctf-msg", "--kind", "stop", "--inbox", inbox, "--out", tmpRoot,
            });
            var exit = await CtfMsgRunner.RunAsync(opts, CancellationToken.None);
            Assert.Equal(0, exit);
            Assert.True(File.Exists(inbox));
        }
        finally { try { Directory.Delete(tmpRoot, recursive: true); } catch { } }
    }
}
