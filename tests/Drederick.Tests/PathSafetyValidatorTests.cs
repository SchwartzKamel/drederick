using Drederick.Scope;
using Xunit;

namespace Drederick.Tests;

public class PathSafetyValidatorTests : IDisposable
{
    private readonly string _root;

    public PathSafetyValidatorTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "drederick_psv_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void Validate_RegularFileInsideWorkdir_Ok()
    {
        var p = Path.Combine(_root, "list.iL");
        File.WriteAllText(p, "10.0.0.1\n");
        var r = PathSafetyValidator.Validate(p, _root);
        Assert.Equal(PathSafetyValidator.Status.Ok, r.Status);
        Assert.False(r.WasSymlink);
    }

    [Fact]
    public void Validate_PathOutsideWorkdir_Refused()
    {
        var other = Path.Combine(Path.GetTempPath(), "drederick_other_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(other);
        try
        {
            var p = Path.Combine(other, "list.iL");
            File.WriteAllText(p, "10.0.0.1\n");
            var r = PathSafetyValidator.Validate(p, _root);
            Assert.Equal(PathSafetyValidator.Status.OutsideWorkdir, r.Status);
        }
        finally { Directory.Delete(other, recursive: true); }
    }

    [Fact]
    public void Validate_DirectoryPath_Refused()
    {
        var d = Path.Combine(_root, "subdir");
        Directory.CreateDirectory(d);
        var r = PathSafetyValidator.Validate(d, _root);
        Assert.Equal(PathSafetyValidator.Status.IsDirectory, r.Status);
    }

    [Fact]
    public void Validate_SymlinkPointingInsideWorkdir_Ok()
    {
        if (OperatingSystem.IsWindows()) return;
        var real = Path.Combine(_root, "real.iL");
        File.WriteAllText(real, "10.0.0.1\n");
        var link = Path.Combine(_root, "link.iL");
        File.CreateSymbolicLink(link, real);
        var r = PathSafetyValidator.Validate(link, _root);
        Assert.Equal(PathSafetyValidator.Status.Ok, r.Status);
        Assert.True(r.WasSymlink);
    }

    [Fact]
    public void Validate_SymlinkEscapingWorkdir_Refused()
    {
        if (OperatingSystem.IsWindows()) return;
        var outside = Path.Combine(Path.GetTempPath(), "drederick_outside_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outside);
        try
        {
            var realOutside = Path.Combine(outside, "secret.iL");
            File.WriteAllText(realOutside, "secret\n");
            var link = Path.Combine(_root, "link.iL");
            File.CreateSymbolicLink(link, realOutside);
            var r = PathSafetyValidator.Validate(link, _root);
            Assert.Equal(PathSafetyValidator.Status.OutsideWorkdir, r.Status);
            Assert.True(r.WasSymlink);
        }
        finally { Directory.Delete(outside, recursive: true); }
    }

    [Fact]
    public void Validate_SymlinkLoop_DetectedOrFailsClosed()
    {
        if (OperatingSystem.IsWindows()) return;
        var a = Path.Combine(_root, "a.lnk");
        var b = Path.Combine(_root, "b.lnk");
        File.CreateSymbolicLink(a, b);
        File.CreateSymbolicLink(b, a);
        var r = PathSafetyValidator.Validate(a, _root);
        Assert.NotEqual(PathSafetyValidator.Status.Ok, r.Status);
    }

    [Fact]
    public void Validate_EmptyPath_PathResolutionFailed()
    {
        var r = PathSafetyValidator.Validate("", _root);
        Assert.Equal(PathSafetyValidator.Status.PathResolutionFailed, r.Status);
    }
}
