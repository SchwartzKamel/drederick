using System.Net;
using System.Security.Cryptography;
using Drederick.Web.Auth;

namespace Drederick.Web.Cli;

/// <summary>
/// Parsed, validated CLI args for the standalone <c>drederick-web</c> entry
/// point. A deliberately minimal parser — the main <c>drederick</c> CLI
/// (<c>src/Drederick/Cli/CommandLineOptions.cs</c>) owns the unified flag
/// surface; this parser only covers the four flags the standalone binary
/// exposes so that <c>dotnet run --project src/Drederick.Web</c> works
/// without pulling in the full command-line machinery.
/// </summary>
internal sealed class WebRunnerArgs
{
    public string BindHost { get; set; } = "127.0.0.1";
    public int BindPort { get; set; } = 7070;
    public string? Token { get; set; }
    public string OutputDir { get; set; } = "out";

    public static WebRunnerArgs Parse(string[] args)
    {
        var o = new WebRunnerArgs();
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "--web-bind":
                    o.BindHost = RequireNext(args, ref i, a);
                    break;
                case "--web-port":
                    {
                        var v = RequireNext(args, ref i, a);
                        if (!int.TryParse(v, out var n) || n < 1 || n > 65535)
                            throw new ArgumentException(
                                $"--web-port must be a TCP port in [1, 65535], got '{v}'.");
                        o.BindPort = n;
                        break;
                    }
                case "--web-token":
                    o.Token = RequireNext(args, ref i, a);
                    break;
                case "-o":
                case "--out":
                    o.OutputDir = RequireNext(args, ref i, a);
                    break;
                default:
                    // Unknown args are ignored here — ASP.NET's own config
                    // system may consume some of them (e.g. --urls).
                    break;
            }
        }
        return o;
    }

    public static WebAppSettings ResolveSettings(WebRunnerArgs args)
    {
        var requireBearer = !IsLoopback(args.BindHost);
        var token = ResolveToken(args, requireBearer);

        return new WebAppSettings
        {
            BindHost = args.BindHost,
            BindPort = args.BindPort,
            RequireBearer = requireBearer,
            Token = token,
            OutputDir = args.OutputDir,
        };
    }

    private static string? ResolveToken(WebRunnerArgs args, bool requireBearer)
    {
        // Priority: --web-token → $DREDERICK_WEB_TOKEN → auto-generate (only
        // when we actually need a token, i.e. bearer is required).
        if (!string.IsNullOrEmpty(args.Token)) return args.Token;
        var env = Environment.GetEnvironmentVariable("DREDERICK_WEB_TOKEN");
        if (!string.IsNullOrEmpty(env)) return env;
        if (!requireBearer) return null;

        var token = GenerateToken();
        PersistTokenToDisk(args.OutputDir, token);
        Console.Error.WriteLine($"drederick web: generated bearer token (also written to {Path.Combine(args.OutputDir, "web-token.txt")}):");
        Console.Error.WriteLine(token);
        return token;
    }

    private static string GenerateToken()
    {
        // 32 bytes → 43 base64url characters. URL-safe, no padding.
        var raw = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(raw)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static void PersistTokenToDisk(string outputDir, string token)
    {
        Directory.CreateDirectory(outputDir);
        var path = Path.Combine(outputDir, "web-token.txt");
        File.WriteAllText(path, token + Environment.NewLine);
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                File.SetUnixFileMode(
                    path,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // Best-effort; missing chmod capability must not kill the server.
            }
        }
    }

    internal static bool IsLoopback(string host)
    {
        if (string.IsNullOrEmpty(host)) return true;
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
    }

    private static string RequireNext(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length)
            throw new ArgumentException($"Flag {flag} requires a value.");
        return args[++i];
    }
}
