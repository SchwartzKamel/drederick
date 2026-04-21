using System.Text.Json;
using Drederick.Audit;
using Drederick.Doctor;

namespace Drederick.Cli;

/// <summary>
/// Interactive first-time setup wizard for new users.
/// Guides through credential setup, tool verification, and scope file creation.
/// </summary>
public sealed class InitCommand
{
    private readonly TextReader _stdin;
    private readonly TextWriter _stdout;
    private readonly TextWriter _stderr;
    private readonly AuditLog _audit;

    public InitCommand(TextReader stdin, TextWriter stdout, TextWriter stderr, AuditLog audit)
    {
        _stdin = stdin;
        _stdout = stdout;
        _stderr = stderr;
        _audit = audit;
    }

    public async Task<int> ExecuteAsync(CommandLineOptions opts)
    {
        _audit.Record("init.start", new Dictionary<string, object?>
        {
            ["skip_creds"] = opts.InitSkipCreds,
            ["skip_scope"] = opts.InitSkipScope,
            ["assume_yes"] = opts.AssumeYes,
        });

        try
        {
            PrintWelcome();

            // Step 1: Verify tools
            _stdout.WriteLine();
            await RunDoctorVerification(opts);

            // Step 2: Credential setup
            if (!opts.InitSkipCreds)
            {
                _stdout.WriteLine();
                await SetupCredentials(opts);
            }

            // Step 3: Create scope file
            if (!opts.InitSkipScope)
            {
                _stdout.WriteLine();
                await CreateScopeFile(opts);
            }

            // Step 4: Verify installation
            _stdout.WriteLine();
            VerifyInstallation();

            // Step 5: Print next steps
            _stdout.WriteLine();
            PrintNextSteps();

            _audit.Record("init.finish", new Dictionary<string, object?>
            {
                ["status"] = "success",
            });

            return 0;
        }
        catch (Exception ex)
        {
            _stderr.WriteLine($"init: error: {ex.Message}");
            _audit.Record("init.error", new Dictionary<string, object?>
            {
                ["error"] = ex.Message,
            });
            return 1;
        }
    }

    private void PrintWelcome()
    {
        _stdout.WriteLine("Welcome to Drederick!");
        _stdout.WriteLine("This wizard will help you set up the basics.");
        _stdout.WriteLine("You can re-run this anytime with: drederick init");
    }

    private async Task RunDoctorVerification(CommandLineOptions opts)
    {
        _stdout.WriteLine("Step 1: Verifying required tools...");
        _stdout.WriteLine();

        try
        {
            var doctor = new DoctorRunner(_audit);
            var tools = doctor.Detect();
            var pm = PackageManagerDetection.Detect(new PathToolLocator());

            DoctorRunner.PrintReport(tools, pm, _stdout);

            var missing = tools.Where(t => !t.Found).ToList();
            if (missing.Count > 0)
            {
                _stdout.WriteLine();
                if (opts.AssumeYes)
                {
                    _stdout.WriteLine("Installing missing tools (--yes mode)...");
                    try
                    {
                        doctor.Install(tools, pm, assumeYes: true, _stdin, _stdout);
                    }
                    catch (Exception ex)
                    {
                        _stdout.WriteLine($"Note: Tool installation encountered an issue: {ex.Message}");
                        _stdout.WriteLine("You can install tools later with: drederick doctor --install");
                    }
                }
                else
                {
                    _stdout.Write("Would you like to install missing tools? (y/n) ");
                    var response = _stdin.ReadLine();
                    if (response is not null && response.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            doctor.Install(tools, pm, assumeYes: false, _stdin, _stdout);
                        }
                        catch (Exception ex)
                        {
                            _stdout.WriteLine($"Note: Tool installation encountered an issue: {ex.Message}");
                            _stdout.WriteLine("You can install tools later with: drederick doctor --install");
                        }
                    }
                }
            }
            else
            {
                _stdout.WriteLine("✓ All required tools are present.");
            }
        }
        catch (Exception ex)
        {
            _stdout.WriteLine($"Note: Could not verify tools: {ex.Message}");
            _stdout.WriteLine("You can verify tools later with: drederick doctor");
        }
    }

    private async Task SetupCredentials(CommandLineOptions opts)
    {
        _stdout.WriteLine("Step 2: Credential setup");

        if (opts.AssumeYes)
        {
            _stdout.WriteLine("Skipping credential setup (--yes mode). You can configure credentials later.");
            return;
        }

        _stdout.Write("Do you need to configure credentials? (y/n) ");
        var response = _stdin.ReadLine();
        if (response is null || !response.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            _stdout.WriteLine("Skipping credential setup. You can configure credentials later.");
            return;
        }

        _audit.Record("init.credential_setup", new Dictionary<string, object?> { ["started"] = true });

        var configPath = GetConfigPath();

        // Warn if config already exists
        if (File.Exists(configPath))
        {
            _stdout.WriteLine($"Warning: Config file already exists at {configPath}");
            _stdout.Write("Overwrite? (y/n) ");
            var overwrite = _stdin.ReadLine();
            if (overwrite is null || !overwrite.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
            {
                _stdout.WriteLine("Skipping credential setup.");
                return;
            }
        }

        // Get HTB API token (silent input)
        _stdout.Write("HTB API token (or press Enter to skip): ");
        var token = ReadSilentLine();
        _stdout.WriteLine();

        // Get HTTP proxy (optional)
        _stdout.Write("HTTP proxy URL (optional, press Enter to skip): ");
        var proxy = _stdin.ReadLine();
        _stdout.WriteLine();

        // Create config
        var config = new Dictionary<string, object?>
        {
            ["version"] = 1,
            ["created_at"] = DateTimeOffset.UtcNow.ToString("o"),
        };

        if (!string.IsNullOrWhiteSpace(token))
        {
            config["htb_api_token"] = token;
        }
        if (!string.IsNullOrWhiteSpace(proxy))
        {
            config["http_proxy"] = proxy;
        }

        // Write config file
        var dir = Path.GetDirectoryName(configPath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        var json = JsonSerializer.Serialize(config, jsonOptions);
        File.WriteAllText(configPath, json);

        // Set permissions to 0600
        try
        {
#pragma warning disable CA1416
            File.SetUnixFileMode(configPath,
                System.IO.UnixFileMode.UserRead | System.IO.UnixFileMode.UserWrite);
#pragma warning restore CA1416
        }
        catch (PlatformNotSupportedException)
        {
            _stdout.WriteLine($"Note: Could not set file permissions. On Windows, please ensure {configPath} is readable only by your user.");
        }

        _stdout.WriteLine($"✓ Credentials saved to {configPath}");
        _audit.Record("init.credential_setup", new Dictionary<string, object?>
        {
            ["status"] = "complete",
            ["has_token"] = !string.IsNullOrWhiteSpace(token),
            ["has_proxy"] = !string.IsNullOrWhiteSpace(proxy),
        });
    }

    private async Task CreateScopeFile(CommandLineOptions opts)
    {
        _stdout.WriteLine("Step 3: Sample scope file");

        if (opts.AssumeYes)
        {
            _stdout.WriteLine("Skipping scope file creation (--yes mode).");
            return;
        }

        _stdout.Write("Create a sample scope file at ~/scope.txt? (y/n) ");
        var response = _stdin.ReadLine();
        if (response is null || !response.Trim().Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            _stdout.WriteLine("Skipping scope file creation.");
            return;
        }

        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var scopePath = Path.Combine(home, "scope.txt");

        if (File.Exists(scopePath))
        {
            _stdout.WriteLine($"File {scopePath} already exists. Skipping.");
            return;
        }

        var exampleScope = """
            # Example scope
            # One CIDR or IP per line. Lines starting with # are comments.
            # Lab environment examples:
            10.0.0.0/24
            192.168.1.0/24
            """;

        File.WriteAllText(scopePath, exampleScope);
        _stdout.WriteLine($"✓ Sample scope created at {scopePath}");
        _stdout.WriteLine("  Edit this file to add your target IP addresses or CIDR ranges.");
    }

    private void VerifyInstallation()
    {
        _stdout.WriteLine("Step 4: Verifying installation...");

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("drederick")
            {
                Arguments = "--help",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is null)
            {
                throw new InvalidOperationException("Failed to start drederick --help");
            }

            proc.WaitForExit();
            if (proc.ExitCode == 0)
            {
                _stdout.WriteLine("✓ Drederick is ready to use!");
            }
            else
            {
                throw new InvalidOperationException($"drederick --help exited with code {proc.ExitCode}");
            }
        }
        catch (Exception ex)
        {
            _stdout.WriteLine($"✓ Drederick is installed (verification skipped: {ex.Message})");
        }
    }

    private void PrintNextSteps()
    {
        _stdout.WriteLine("Quick Start:");
        _stdout.WriteLine("  drederick doctor                # Verify tools");
        _stdout.WriteLine("  drederick --scope ~/scope.txt  # Run a scan");
        _stdout.WriteLine("  drederick serve                # View results in Datasette");
        _stdout.WriteLine();
        _stdout.WriteLine("Full docs: https://github.com/SchwartzKamel/drederick/tree/main/docs");
    }

    private static string GetConfigPath()
    {
        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".drederick", "config.json");
    }

    /// <summary>
    /// Read a line from stdin without echoing to the terminal (for password-like input).
    /// Falls back to regular ReadLine on unsupported platforms.
    /// </summary>
    private string? ReadSilentLine()
    {
        try
        {
            // On Windows, we can't easily disable echo, so fall back to regular input
            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                return _stdin.ReadLine();
            }

            // On Unix, disable echo
            var originalMode = GetConsoleMode();
            try
            {
                DisableEcho();
                return _stdin.ReadLine();
            }
            finally
            {
                RestoreConsoleMode(originalMode);
            }
        }
        catch
        {
            // Fall back to regular input if anything fails
            return _stdin.ReadLine();
        }
    }

    private static string GetConsoleMode()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("stty", "-g")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc is not null)
            {
                proc.WaitForExit();
                var mode = proc.StandardOutput.ReadToEnd().Trim();
                return mode;
            }
            return string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static void DisableEcho()
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("stty", "-echo")
            {
                UseShellExecute = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit();
        }
        catch { }
    }

    private static void RestoreConsoleMode(string mode)
    {
        if (string.IsNullOrEmpty(mode)) return;
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("stty", mode)
            {
                UseShellExecute = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit();
        }
        catch { }
    }
}
