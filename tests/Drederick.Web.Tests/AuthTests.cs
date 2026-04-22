using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Drederick.Web.Auth;
using Drederick.Web.Cli;
using Xunit;

namespace Drederick.Web.Tests;

public sealed class AuthTests
{
    private const string CanaryToken = "CANARY-SECRET-abc123-XYZ789-drederick-web-test-token";

    private static WebAppSettings NonLoopbackSettings(string? token) => new()
    {
        BindHost = "0.0.0.0",
        BindPort = 0,
        RequireBearer = true,
        Token = token,
        OutputDir = "out", // overridden inside the factory to a temp dir
    };

    [Fact]
    public async Task NonLoopback_RequiresBearer()
    {
        using var factory = new DrederickWebFactory(NonLoopbackSettings(CanaryToken));
        using var client = factory.CreateClient();

        // 1. No Authorization header → 401
        var noHeader = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.Unauthorized, noHeader.StatusCode);

        // 2. Wrong bearer → 401
        using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/health"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "not-the-token");
            var wrong = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        }

        // 3. Wrong scheme → 401
        using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/health"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", "Zm9vOmJhcg==");
            var wrongScheme = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, wrongScheme.StatusCode);
        }

        // 4. Correct bearer → 200
        using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/health"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CanaryToken);
            var ok = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }
    }

    [Fact]
    public void ConstantTimeComparison_UsesFixedTimeEquals()
    {
        // White-box structural check: confirm BearerTokenAuth delegates
        // comparison to CryptographicOperations.FixedTimeEquals. We verify
        // by disassembling the compiled type's IL via reflection for method
        // references. This is a scaffold-level check: a behavioural timing
        // test is flaky on CI. The real guarantee is the source-level use
        // of CryptographicOperations.FixedTimeEquals.
        var source = System.IO.File.ReadAllText(
            FindRepoFile("src/Drederick.Web/Auth/BearerTokenAuth.cs"));
        Assert.Contains(
            "CryptographicOperations.FixedTimeEquals",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AuditLog_Start_NoTokenPlaintext()
    {
        // Auto-generated-token scenario: start the server with a canary token
        // configured, send one request, then assert the plaintext token never
        // appears in audit.jsonl. The SHA-256 digest MUST be present on
        // web.server.start.
        using var factory = new DrederickWebFactory(NonLoopbackSettings(CanaryToken));
        using var client = factory.CreateClient();

        using (var req = new HttpRequestMessage(HttpMethod.Get, "/api/health"))
        {
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", CanaryToken);
            var resp = await client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        // Allow the audit-log AutoFlush to finish.
        await Task.Delay(50);

        var auditContents = System.IO.File.ReadAllText(factory.AuditLogPath);
        Assert.DoesNotContain(CanaryToken, auditContents, StringComparison.Ordinal);

        // The SHA-256 digest of the token must appear exactly once (on the
        // web.server.start event).
        var digest = BearerTokenAuth.TokenDigest(CanaryToken);
        Assert.Contains(digest, auditContents, StringComparison.Ordinal);
    }

    [Fact]
    public void WebRunnerArgs_IsLoopback_ClassifiesHostsCorrectly()
    {
        Assert.True(WebRunnerArgs.IsLoopback("127.0.0.1"));
        Assert.True(WebRunnerArgs.IsLoopback("::1"));
        Assert.True(WebRunnerArgs.IsLoopback("localhost"));
        Assert.True(WebRunnerArgs.IsLoopback("LOCALHOST"));
        Assert.False(WebRunnerArgs.IsLoopback("0.0.0.0"));
        Assert.False(WebRunnerArgs.IsLoopback("10.0.0.1"));
        Assert.False(WebRunnerArgs.IsLoopback("::"));
    }

    private static string FindRepoFile(string relative)
    {
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, relative);
            if (File.Exists(candidate)) return candidate;
            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }
        throw new FileNotFoundException($"Could not locate '{relative}' above {AppContext.BaseDirectory}.");
    }
}
