namespace Drederick.Doctor;

public enum PackageManager
{
    None,
    Apt,
    Dnf,
    Pacman,
    Zypper,
    Brew,
}

public static class PackageManagerDetection
{
    /// <summary>
    /// Returns the first available system package manager in a fixed preference
    /// order: apt-get, dnf, pacman, zypper, brew. <see cref="PackageManager.None"/>
    /// if none are found on PATH.
    /// </summary>
    public static PackageManager Detect(IToolLocator locator)
    {
        if (locator.Which("apt-get") is not null) return PackageManager.Apt;
        if (locator.Which("dnf") is not null) return PackageManager.Dnf;
        if (locator.Which("pacman") is not null) return PackageManager.Pacman;
        if (locator.Which("zypper") is not null) return PackageManager.Zypper;
        if (locator.Which("brew") is not null) return PackageManager.Brew;
        return PackageManager.None;
    }

    public static string DisplayName(PackageManager pm) => pm switch
    {
        PackageManager.Apt => "apt-get",
        PackageManager.Dnf => "dnf",
        PackageManager.Pacman => "pacman",
        PackageManager.Zypper => "zypper",
        PackageManager.Brew => "brew",
        _ => "none",
    };
}
