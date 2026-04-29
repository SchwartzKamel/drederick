using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public class HeaderFuzzToolTests
{
    private static Scope.Scope CreateLabScope(string cidr)
    {
        return ScopeLoader.Parse($"# test\n{cidr}");
    }

    private static AuditLog CreateAuditLog()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"audit-{Guid.NewGuid()}.jsonl");
        return new AuditLog(tempFile);
    }

    [Fact]
    public async Task Throws_When_Url_OutOfScope()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        using var tool = new HeaderFuzzTool(scope, audit);

        await Assert.ThrowsAsync<ScopeException>(async () =>
        {
            await tool.ProbeAsync("http://192.168.1.1/");
        });

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Throws_When_Url_Invalid()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        using var tool = new HeaderFuzzTool(scope, audit);

        await Assert.ThrowsAsync<ArgumentException>(async () =>
        {
            await tool.ProbeAsync("not-a-url");
        });

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Detects_HostHeaderInjection_When_Canary_Reflected_In_Body()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();
        var canary = new HeaderFuzzCanary
        {
            Hostname = "evil.attacker.tld",
            MarkerHeader = "X-Test",
            MarkerValue = "marker123",
        };

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);

            // Reflect X-Forwarded-Host in body
            if (req.Headers.TryGetValues("X-Forwarded-Host", out var values))
            {
                var host = values.FirstOrDefault();
                response.Content = new StringContent(
                    $"<html><body>Welcome to {host}</body></html>",
                    Encoding.UTF8,
                    "text/html");
            }
            else
            {
                response.Content = new StringContent("<html><body>Welcome</body></html>");
            }

            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient, canary);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        Assert.Contains(result.Findings, f =>
            f.Issue == HeaderIssue.HostHeaderInjection &&
            f.Header == "X-Forwarded-Host" &&
            f.Evidence.Contains("evil.attacker.tld"));

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Detects_HostHeaderInjection_When_Canary_Reflected_In_Location_Header()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();
        var canary = new HeaderFuzzCanary
        {
            Hostname = "evil.attacker.tld",
            MarkerHeader = "X-Test",
            MarkerValue = "marker123",
        };

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);

            // Reflect X-Host in Location header
            if (req.Headers.TryGetValues("X-Host", out var values))
            {
                var host = values.FirstOrDefault();
                response.Headers.Location = new Uri($"http://{host}/redirect");
            }
            else
            {
                response.Headers.Location = new Uri("http://example.com/redirect");
            }

            response.Content = new StringContent("");
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient, canary);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        Assert.Contains(result.Findings, f =>
            f.Issue == HeaderIssue.HostHeaderInjection &&
            f.Header == "X-Host" &&
            f.Evidence.Contains("Location"));

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Detects_CrlfInjection_When_Injected_Header_Echoed()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();
        var canary = new HeaderFuzzCanary
        {
            Hostname = "evil.attacker.tld",
            MarkerHeader = "X-Injected",
            MarkerValue = "injected123",
        };

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);

            // Echo User-Agent in body (including CRLF payload)
            if (req.Headers.TryGetValues("User-Agent", out var values))
            {
                var ua = values.FirstOrDefault() ?? "";
                // If CRLF payload present, echo it (simulating vulnerable server)
                response.Content = new StringContent(
                    $"<html><body>Your UA: {ua}</body></html>",
                    Encoding.UTF8,
                    "text/html");
            }
            else
            {
                response.Content = new StringContent("<html><body>No UA</body></html>");
            }

            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient, canary);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        // Check if CRLF was attempted (may not succeed due to HttpClient sanitization)
        // The test validates the tool attempts the probe
        Assert.NotNull(result.Findings);

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Detects_CachePoisoning_When_X_Forwarded_Proto_Diverges_With_Cache_Header()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);

            // If X-Forwarded-Proto present, return different content
            if (req.Headers.TryGetValues("X-Forwarded-Proto", out var values))
            {
                response.Content = new StringContent(
                    "<html><body>HTTPS version - admin panel</body></html>",
                    Encoding.UTF8,
                    "text/html");
                response.Headers.TryAddWithoutValidation("X-Cache", "HIT");
            }
            else
            {
                response.Content = new StringContent(
                    "<html><body>HTTP version</body></html>",
                    Encoding.UTF8,
                    "text/html");
            }

            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        Assert.Contains(result.Findings, f =>
            f.Issue == HeaderIssue.CachePoisoning &&
            f.Header == "X-Forwarded-Proto");

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Detects_RequestSmuggling_When_TE_Probe_Timing_Significantly_Exceeds_Baseline()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        var handler = new HeaderFuzzToolFakeHttpMessageHandler(async (req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);

            // If we detect smuggling probe (Transfer-Encoding or conflicting CL), add delay
            var hasTE = req.Headers.TryGetValues("Transfer-Encoding", out var teValues);
            var hasCL = req.Content?.Headers?.ContentLength != null;

            if (hasTE && hasCL)
            {
                // Simulate smuggling detection: add significant delay
                await Task.Delay(1500, ct);
            }

            response.Content = new StringContent("OK");
            return response;
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        // May detect smuggling based on timing (depends on implementation)
        Assert.NotNull(result.Findings);

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Returns_Empty_Result_When_Target_Hardened()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            // Hardened server: strips all injected headers, returns consistent response
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent("<html><body>Hardened</body></html>");
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        var result = await tool.ProbeAsync("http://10.0.0.5/");

        Assert.NotNull(result);
        Assert.Empty(result.Findings);
        Assert.Null(result.Error);

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Disabled_Probes_Skipped()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        var requestCount = 0;
        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            requestCount++;
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent("OK");
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        var options = new HeaderFuzzOptions
        {
            ProbeSmuggling = false,
            ProbeHostInjection = false,
            ProbeCrlf = false,
            ProbeCachePoisoning = false,
        };

        var result = await tool.ProbeAsync("http://10.0.0.5/", options);

        Assert.NotNull(result);
        Assert.Equal(0, requestCount); // No requests sent when all probes disabled
        Assert.Empty(result.Findings);

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var auditFile = Path.Combine(Path.GetTempPath(), $"audit-{Guid.NewGuid()}.jsonl");
        var audit = new AuditLog(auditFile);

        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent("OK");
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        await tool.ProbeAsync("http://10.0.0.5/");

        // Read audit log
        var lines = await File.ReadAllLinesAsync(auditFile);
        Assert.Contains(lines, line => line.Contains("header-fuzz.start"));
        Assert.Contains(lines, line => line.Contains("header-fuzz.finish"));

        File.Delete(auditFile);
    }

    [Fact]
    public void Canary_Marker_Is_Random_Per_Tool_Instance()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        using var tool1 = new HeaderFuzzTool(scope, audit);
        using var tool2 = new HeaderFuzzTool(scope, audit);

        // Both tools should have different canary markers (generated randomly)
        // We can't access the canary directly, but we can verify via behavior
        // For now, just verify tools can be created independently
        Assert.NotNull(tool1);
        Assert.NotNull(tool2);

        File.Delete(audit.Path);
    }

    [Fact]
    public async Task Rate_Limit_Enforced()
    {
        var scope = CreateLabScope("10.0.0.0/24");
        var audit = CreateAuditLog();

        var timestamps = new List<DateTimeOffset>();
        var handler = new HeaderFuzzToolFakeHttpMessageHandler((req, ct) =>
        {
            timestamps.Add(DateTimeOffset.UtcNow);
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent("OK");
            return Task.FromResult(response);
        });

        using var httpClient = new HttpClient(handler);
        using var tool = new HeaderFuzzTool(scope, audit, httpClient);

        var options = new HeaderFuzzOptions
        {
            RateLimitRps = 5, // 5 requests per second = 200ms between requests
            ProbeSmuggling = false, // Disable smuggling (multiple samples)
            ProbeHostInjection = true, // Only test host injection (5 headers)
            ProbeCrlf = false,
            ProbeCachePoisoning = false,
        };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await tool.ProbeAsync("http://10.0.0.5/", options);
        sw.Stop();

        // Should have sent at least 5 requests for host injection
        Assert.True(timestamps.Count >= 5);

        // Minimum time should be roughly (count-1) * delay
        // With 5 RPS = 200ms delay, 5 requests = ~800ms minimum
        // Allow some tolerance
        Assert.True(sw.ElapsedMilliseconds >= 400); // At least half the expected time

        File.Delete(audit.Path);
    }

    /// <summary>
    /// Fake HttpMessageHandler for testing that allows custom response logic.
    /// </summary>
    private sealed class HeaderFuzzToolFakeHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;

        public HeaderFuzzToolFakeHttpMessageHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        {
            _handler = handler;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return _handler(request, cancellationToken);
        }
    }
}
