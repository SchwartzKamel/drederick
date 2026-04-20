using System.Reflection;
using Drederick.Recon;
using Xunit;

namespace Drederick.Tests;

public class PortSpecTests
{
    // Validate NmapTool.RejectUnsafePortSpec via reflection — it's private but
    // guards subprocess args from LLM-chosen input, so it's worth direct testing.
    private static void Invoke(string spec)
    {
        var m = typeof(NmapTool).GetMethod("RejectUnsafePortSpec",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        try { m.Invoke(null, new object[] { spec }); }
        catch (TargetInvocationException tie) when (tie.InnerException is not null)
        { throw tie.InnerException; }
    }

    [Theory]
    [InlineData("80")]
    [InlineData("80,443")]
    [InlineData("1-65535")]
    [InlineData("22,80,443")]
    [InlineData("80-90,443,8000-8100")]
    [InlineData("-")]
    public void Accepts_Well_Formed_Specs(string spec)
    {
        Invoke(spec); // should not throw
    }

    [Theory]
    [InlineData("--top-ports 100")]  // space
    [InlineData("80;443")]            // semicolon
    [InlineData("80 443")]            // space
    [InlineData("80|443")]            // pipe
    [InlineData("80$(id)")]           // command substitution characters
    [InlineData("")]                  // empty
    [InlineData(",80")]               // leading separator
    [InlineData("80,")]               // trailing separator
    [InlineData("80,,443")]           // double separator
    [InlineData("80--90")]            // adjacent dashes
    [InlineData("-80")]               // leading dash (ambiguous: could be flag)
    [InlineData("80-")]               // trailing dash
    [InlineData("---")]               // all-separator
    public void Rejects_Unsafe_Specs(string spec)
    {
        Assert.Throws<ArgumentException>(() => Invoke(spec));
    }
}
