using System.Diagnostics;
using Drederick.Audit;

namespace Drederick.Jeopardy.Llm;

internal enum CopilotTokenSource
{
    None,
    CopilotToken,
    GhToken,
    GithubToken,
    GitHubCli,
}

internal static class CopilotAuthTokenResolver
{
    private static readonly TimeSpan TokenCommandTimeout = TimeSpan.FromSeconds(10);

    internal static (string? Token, CopilotTokenSource Source) ResolveToken(
        bool allowGitHubCliAuth = true,
        AuditLog? audit = null)
    {
        var c = Environment.GetEnvironmentVariable("COPILOT_TOKEN");
        if (!string.IsNullOrWhiteSpace(c)) return (c, CopilotTokenSource.CopilotToken);

        var g = Environment.GetEnvironmentVariable("GH_TOKEN");
        if (!string.IsNullOrWhiteSpace(g)) return (g, CopilotTokenSource.GhToken);

        var h = Environment.GetEnvironmentVariable("GITHUB_TOKEN");
        if (!string.IsNullOrWhiteSpace(h)) return (h, CopilotTokenSource.GithubToken);

        if (!allowGitHubCliAuth) return (null, CopilotTokenSource.None);

        var ghToken = TryReadGitHubCliToken();
        if (!string.IsNullOrWhiteSpace(ghToken)) return (ghToken, CopilotTokenSource.GitHubCli);

        if (TryRunInteractiveGitHubLogin(audit))
        {
            ghToken = TryReadGitHubCliToken();
            if (!string.IsNullOrWhiteSpace(ghToken)) return (ghToken, CopilotTokenSource.GitHubCli);
        }

        return (null, CopilotTokenSource.None);
    }

    internal static string? TryReadGitHubCliToken(string ghBinary = "gh")
    {
        var result = RunGitHubCli(
            ghBinary,
            new[] { "auth", "token", "--hostname", "github.com" },
            TokenCommandTimeout,
            redirectOutput: true);

        if (result.ExitCode != 0) return null;
        var token = result.StandardOutput.Trim();
        return string.IsNullOrWhiteSpace(token) ? null : token;
    }

    private static bool TryRunInteractiveGitHubLogin(AuditLog? audit)
    {
        if (!CanRunInteractiveGitHubLogin()) return false;

        Console.Error.WriteLine(
            "Copilot auth: no token found in env or gh CLI. Starting `gh auth login --web --skip-ssh-key`.");
        Console.Error.WriteLine(
            "Follow the GitHub device/browser prompt, then Drederick will reuse that auth token automatically.");

        audit?.Record("copilot.auth.gh_login.start", new Dictionary<string, object?>
        {
            ["hostname"] = "github.com",
            ["method"] = "gh_auth_login_web",
        });

        var result = RunGitHubCli(
            "gh",
            new[] { "auth", "login", "--hostname", "github.com", "--git-protocol", "ssh", "--web", "--skip-ssh-key" },
            timeout: null,
            redirectOutput: false);

        var success = result.ExitCode == 0;
        audit?.Record("copilot.auth.gh_login.finish", new Dictionary<string, object?>
        {
            ["hostname"] = "github.com",
            ["success"] = success,
            ["exit_code"] = result.ExitCode,
        });

        return success;
    }

    private static bool CanRunInteractiveGitHubLogin()
        => !Console.IsInputRedirected;

    private static GitHubCliResult RunGitHubCli(
        string ghBinary,
        IReadOnlyList<string> arguments,
        TimeSpan? timeout,
        bool redirectOutput)
    {
        var psi = new ProcessStartInfo(ghBinary)
        {
            UseShellExecute = false,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectOutput,
            RedirectStandardInput = false,
        };

        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        try
        {
            using var process = Process.Start(psi);
            if (process is null) return new GitHubCliResult(-1, "", "failed to start gh");

            if (redirectOutput)
            {
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();

                if (timeout is not null && !process.WaitForExit(timeout.Value))
                {
                    process.Kill(entireProcessTree: true);
                    return new GitHubCliResult(-1, "", "gh auth token timed out");
                }

                process.WaitForExit();
                return new GitHubCliResult(
                    process.ExitCode,
                    stdout.GetAwaiter().GetResult(),
                    stderr.GetAwaiter().GetResult());
            }

            process.WaitForExit();
            return new GitHubCliResult(process.ExitCode, "", "");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
            or InvalidOperationException
            or IOException
            or UnauthorizedAccessException)
        {
            return new GitHubCliResult(-1, "", ex.GetType().Name);
        }
    }

    private sealed record GitHubCliResult(int ExitCode, string StandardOutput, string StandardError);
}
