using Drederick.Cli;
using Xunit;

namespace Drederick.Tests.Autopilot;

public class CommandLineOptionsAutopilotTests
{
    [Fact]
    public void Parses_Autopilot_Flag()
    {
        var o = CommandLineOptions.Parse(new[] { "--autopilot" });
        Assert.True(o.Autopilot);
    }

    [Fact]
    public void Parses_Autopilot_Subflags()
    {
        var o = CommandLineOptions.Parse(new[]
        {
            "--autopilot",
            "--autopilot-default-creds",
            "--autopilot-max-iterations", "7",
            "--autopilot-max-actions", "128",
            "--cred", "alice:hunter2",
            "--cred", "CORP\\bob:Pa55w0rd!",
        });
        Assert.True(o.Autopilot);
        Assert.True(o.AutopilotDefaultCreds);
        Assert.Equal(7, o.AutopilotMaxIterations);
        Assert.Equal(128, o.AutopilotMaxActionsPerIteration);
        Assert.Equal(2, o.AutopilotCreds.Count);
        Assert.Contains("alice:hunter2", o.AutopilotCreds);
        Assert.Contains("CORP\\bob:Pa55w0rd!", o.AutopilotCreds);
    }

    [Fact]
    public void Rejects_Out_Of_Range_Iterations()
    {
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--autopilot-max-iterations", "0" }));
        Assert.Throws<ArgumentException>(() =>
            CommandLineOptions.Parse(new[] { "--autopilot-max-iterations", "101" }));
    }

    [Fact]
    public void Autopilot_Off_By_Default()
    {
        var o = CommandLineOptions.Parse(Array.Empty<string>());
        Assert.False(o.Autopilot);
        Assert.False(o.AutopilotDefaultCreds);
        Assert.Equal(3, o.AutopilotMaxIterations);
    }
}
