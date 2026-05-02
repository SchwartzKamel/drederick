using Drederick.Ops;
using Xunit;

namespace Drederick.Tests.Ops;

public class PathResolverTests
{
    [Fact]
    public void Which_ShOnLinux_ReturnsNonNullPathContainingSh()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return; // not applicable on this OS
        var result = PathResolver.Which("sh");
        Assert.NotNull(result);
        Assert.Contains("sh", result);
        Assert.True(File.Exists(result));
    }

    [Fact]
    public void Which_NonexistentBinary_ReturnsNull()
    {
        var result = PathResolver.Which("nonexistent_binary_xyz_abc_12345");
        Assert.Null(result);
    }

    [Fact]
    public void IsAvailable_LsOnLinux_ReturnsTrue()
    {
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
            return;
        Assert.True(PathResolver.IsAvailable("ls"));
    }

    [Fact]
    public void IsAvailable_Dotnet_ReturnsTrue()
    {
        // We are running inside a dotnet process, so dotnet must be on PATH.
        Assert.True(PathResolver.IsAvailable("dotnet"));
    }

    [Fact]
    public void Which_AbsolutePathThatExists_ReturnsSelf()
    {
        var exe = Environment.ProcessPath;
        if (exe is null) return;
        var result = PathResolver.Which(exe);
        Assert.Equal(exe, result);
    }

    [Fact]
    public void Which_AbsolutePathThatDoesNotExist_ReturnsNull()
    {
        var result = PathResolver.Which("/this/path/does/not/exist/ever_xyz");
        Assert.Null(result);
    }
}
