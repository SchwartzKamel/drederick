using System.Net;
using System.Text;
using Drederick.Audit;
using Drederick.Recon.Fuzz;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Fuzz;

public sealed class LlmPayloadFuzzToolTests
{
    private static Scope.Scope CreateScope(params string[] hosts)
    {
        var cidr = hosts.Length > 0 ? hosts[0] : "10.0.0.1";
        return ScopeLoader.Parse(cidr, labMode: true, allowBroad: true);
    }

    private static AuditLog CreateAudit()
    {
        var tempPath = System.IO.Path.Combine(AppContext.BaseDirectory, $"audit-{Guid.NewGuid():N}.jsonl");
        return new AuditLog(tempPath);
    }

    private sealed class FakeLlmMutator : ILlmMutator
    {
        public bool IsAvailable { get; set; } = true;
        public Func<string, string, int, string, CancellationToken, Task<string>>? MutateFunc { get; set; }

        public Task<string> MutateAsync(
            string objective,
            string previousPayload,
            int previousStatus,
            string previousResponseSnippet,
            CancellationToken ct)
        {
            if (MutateFunc is null)
            {
                return Task.FromResult(previousPayload + "_mutated");
            }
            return MutateFunc(objective, previousPayload, previousStatus, previousResponseSnippet, ct);
        }
    }

    private sealed class FakeLlmFuzzHttpHandler : HttpMessageHandler
    {
        public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? SendFunc { get; set; }
        public List<HttpRequestMessage> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (SendFunc is null)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("default response", Encoding.UTF8, "text/plain"),
                });
            }
            return SendFunc(request, cancellationToken);
        }
    }

    [Fact]
    public void Throws_When_Url_OutOfScope()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var ex = Assert.ThrowsAsync<ScopeException>(async () =>
            await tool.ProbeAsync("http://192.168.1.1/", "test", "seed"));

        Assert.NotNull(ex);
    }

    [Fact]
    public async Task Throws_When_Url_Invalid()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("not-a-url", "test", "seed"));

        Assert.Contains("absolute http/https URL", ex.Message);
    }

    [Fact]
    public async Task Throws_When_SeedPayload_Empty()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("http://10.0.0.1/", "test", ""));

        Assert.Contains("seedPayload cannot be empty", ex.Message);
    }

    [Fact]
    public async Task Throws_When_SeedPayload_TooLarge()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var hugePayload = new string('A', 65 * 1024); // 65 KB

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("http://10.0.0.1/", "test", hugePayload));

        Assert.Contains("exceeds", ex.Message);
    }

    [Fact]
    public async Task Throws_When_ParameterName_Invalid()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var opts = new LlmPayloadFuzzOptions { ParameterName = "invalid name!" };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts));

        Assert.Contains("ParameterName must match", ex.Message);
    }

    [Fact]
    public async Task Throws_When_Method_Invalid()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var opts = new LlmPayloadFuzzOptions { Method = "DELETE" };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts));

        Assert.Contains("Method must be one of GET/POST/PUT", ex.Message);
    }

    [Fact]
    public async Task Throws_When_ContentType_NotWhitelisted()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var tool = new LlmPayloadFuzzTool(scope, audit);

        var opts = new LlmPayloadFuzzOptions { ContentType = "application/xml" };

        var ex = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts));

        Assert.Contains("ContentType must be one of", ex.Message);
    }

    [Fact]
    public async Task Returns_Empty_Result_When_Llm_Unavailable()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator { IsAvailable = false };
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var result = await tool.ProbeAsync("http://10.0.0.1/", "test objective", "seed");

        Assert.False(result.LlmAvailable);
        Assert.Equal(0, result.Rounds);
        Assert.Empty(result.Mutations);
        Assert.Empty(fakeHandler.Requests); // No HTTP requests sent
    }

    [Fact]
    public async Task Caps_MaxRounds_At_HardMaxRounds()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 100,
            HardMaxRounds = 5,
            RateLimitMsBetweenRequests = 0, // Speed up test
        };

        var result = await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts);

        Assert.True(result.LlmAvailable);
        Assert.Equal(5, result.Rounds); // Clamped to HardMaxRounds
        Assert.Equal(5, fakeHandler.Requests.Count);
    }

    [Fact]
    public async Task Stops_When_Llm_Returns_Invalid_Payload()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var callCount = 0;
        var fakeMutator = new FakeLlmMutator
        {
            MutateFunc = (obj, prev, status, snippet, ct) =>
            {
                callCount++;
                return callCount <= 1
                    ? Task.FromResult("valid_payload")
                    : Task.FromResult(""); // Empty string on round 2
            }
        };
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 10,
            RateLimitMsBetweenRequests = 0,
        };

        var result = await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts);

        Assert.True(result.LlmAvailable);
        // Round 1: seed, Round 2: valid_payload, then LLM returns empty and we break
        Assert.Equal(2, fakeHandler.Requests.Count);
        Assert.Contains(result.Mutations, m => m.Notes == "llm-returned-invalid-payload");
    }

    [Fact]
    public async Task Stops_When_Cancelled()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var requestCount = 0;
        var cts = new CancellationTokenSource();

        var fakeHandler = new FakeLlmFuzzHttpHandler
        {
            SendFunc = (req, ct) =>
            {
                requestCount++;
                if (requestCount >= 2) cts.Cancel();
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("response", Encoding.UTF8, "text/plain"),
                });
            }
        };
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 10,
            RateLimitMsBetweenRequests = 0,
        };

        var result = await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts, cts.Token);

        Assert.True(result.LlmAvailable);
        Assert.True(result.Rounds < 10); // Stopped before completing all rounds
        Assert.InRange(result.Rounds, 1, 3); // Should have processed 1-2 rounds before cancellation
    }

    [Fact]
    public async Task Stops_When_Llm_Returns_NUL_Byte_Payload()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var callCount = 0;
        var fakeMutator = new FakeLlmMutator
        {
            MutateFunc = (obj, prev, status, snippet, ct) =>
            {
                callCount++;
                return callCount <= 1
                    ? Task.FromResult("valid_payload")
                    : Task.FromResult("payload\0with_nul"); // NUL byte on round 2
            }
        };
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 10,
            RateLimitMsBetweenRequests = 0,
        };

        var result = await tool.ProbeAsync("http://10.0.0.1/", "test", "seed", opts);

        Assert.True(result.LlmAvailable);
        Assert.Equal(2, fakeHandler.Requests.Count);
        Assert.Contains(result.Mutations, m => m.Notes == "llm-returned-invalid-payload");
    }

    [Fact]
    public async Task Audit_Records_Digests_Not_Plaintext_Objective_Or_Payload()
    {
        var scope = CreateScope("10.0.0.1");
        var tempPath = System.IO.Path.Combine(AppContext.BaseDirectory, $"audit-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(tempPath);
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var objective = "SECRET_OBJECTIVE_12345";
        var seedPayload = "SECRET_PAYLOAD_67890";

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 1,
            RateLimitMsBetweenRequests = 0,
        };

        await tool.ProbeAsync("http://10.0.0.1/", objective, seedPayload, opts);

        audit.Dispose();

        // Read audit log
        var auditContent = File.ReadAllText(tempPath);

        // Assert plaintext secrets are NOT in the audit log
        Assert.DoesNotContain("SECRET_OBJECTIVE_12345", auditContent);
        Assert.DoesNotContain("SECRET_PAYLOAD_67890", auditContent);

        // Assert digests ARE in the audit log
        Assert.Contains("objective_digest", auditContent);
        Assert.Contains("seed_digest", auditContent);

        File.Delete(tempPath);
    }

    [Fact]
    public async Task Audit_Records_Start_And_Finish_Events()
    {
        var scope = CreateScope("10.0.0.1");
        var tempPath = System.IO.Path.Combine(AppContext.BaseDirectory, $"audit-{Guid.NewGuid():N}.jsonl");
        var audit = new AuditLog(tempPath);
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 2,
            RateLimitMsBetweenRequests = 0,
        };

        await tool.ProbeAsync("http://10.0.0.1/test", "objective", "seed", opts);

        audit.Dispose();

        var auditContent = File.ReadAllText(tempPath);

        Assert.Contains("llm-payload-fuzz.start", auditContent);
        Assert.Contains("llm-payload-fuzz.finish", auditContent);
        Assert.Contains("\"llm_available\":true", auditContent);
        Assert.Contains("rounds_completed", auditContent);

        File.Delete(tempPath);
    }

    [Fact]
    public async Task Rate_Limit_Enforced()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 3,
            RateLimitMsBetweenRequests = 100, // 100ms between requests
        };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await tool.ProbeAsync("http://10.0.0.1/", "objective", "seed", opts);
        sw.Stop();

        // 3 rounds with 100ms between each = at least 200ms total (2 delays)
        Assert.True(sw.ElapsedMilliseconds >= 180, $"Expected >= 180ms, got {sw.ElapsedMilliseconds}ms");
    }

    [Fact]
    public async Task Mutations_Use_Sha256_Hex_Digests()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            MaxRounds = 2,
            RateLimitMsBetweenRequests = 0,
        };

        var result = await tool.ProbeAsync("http://10.0.0.1/", "objective", "seed", opts);

        Assert.True(result.LlmAvailable);
        Assert.Equal(2, result.Mutations.Count);

        foreach (var mutation in result.Mutations)
        {
            // SHA-256 hex digest is 64 lowercase hex chars
            Assert.Matches("^[a-f0-9]{64}$", mutation.PayloadDigest);
        }
    }

    [Fact]
    public async Task GET_Request_Includes_Payload_In_Query()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            Method = "GET",
            ParameterName = "test_param",
            MaxRounds = 1,
            RateLimitMsBetweenRequests = 0,
        };

        await tool.ProbeAsync("http://10.0.0.1/endpoint", "objective", "my_payload", opts);

        Assert.Single(fakeHandler.Requests);
        var req = fakeHandler.Requests[0];
        Assert.Equal(HttpMethod.Get, req.Method);
        Assert.Contains("test_param=my_payload", req.RequestUri!.Query);
    }

    [Fact]
    public async Task POST_FormUrlEncoded_Request_Includes_Payload_In_Body()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            Method = "POST",
            ContentType = "application/x-www-form-urlencoded",
            ParameterName = "input",
            MaxRounds = 1,
            RateLimitMsBetweenRequests = 0,
        };

        await tool.ProbeAsync("http://10.0.0.1/", "objective", "test_value", opts);

        Assert.Single(fakeHandler.Requests);
        var req = fakeHandler.Requests[0];
        Assert.Equal(HttpMethod.Post, req.Method);
        var body = await req.Content!.ReadAsStringAsync();
        Assert.Contains("input=test_value", body);
    }

    [Fact]
    public async Task POST_Json_Request_Includes_Payload_In_Json_Body()
    {
        var scope = CreateScope("10.0.0.1");
        var audit = CreateAudit();
        var fakeMutator = new FakeLlmMutator();
        var fakeHandler = new FakeLlmFuzzHttpHandler();
        var httpClient = new HttpClient(fakeHandler);

        var tool = new LlmPayloadFuzzTool(scope, audit, fakeMutator, httpClient);

        var opts = new LlmPayloadFuzzOptions
        {
            Method = "POST",
            ContentType = "application/json",
            ParameterName = "data",
            MaxRounds = 1,
            RateLimitMsBetweenRequests = 0,
        };

        await tool.ProbeAsync("http://10.0.0.1/", "objective", "json_payload", opts);

        Assert.Single(fakeHandler.Requests);
        var req = fakeHandler.Requests[0];
        Assert.Equal(HttpMethod.Post, req.Method);
        var body = await req.Content!.ReadAsStringAsync();
        Assert.Contains("\"data\"", body);
        Assert.Contains("\"json_payload\"", body);
    }
}
