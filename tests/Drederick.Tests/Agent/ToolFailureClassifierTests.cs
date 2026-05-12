using System.Net.Http;
using System.Net.Sockets;
using Drederick.Agent;
using Drederick.Scope;
using Xunit;

namespace Drederick.Tests.Agent;

public class ToolFailureClassifierTests
{
    private readonly ToolFailureClassifier _c = new();

    [Theory]
    [InlineData("nmap", "Connection refused", "transient_network", true, "reduce_concurrency")]
    [InlineData("hydra", "account is locked", "account_lockout", false, null)]
    [InlineData("http", "HTTP 429 Too Many Requests", "rate_limited", true, "reduce_rps")]
    [InlineData("ssh", "401 Unauthorized: invalid credentials", "auth_failed", false, null)]
    [InlineData("msf", "Segmentation fault (core dumped)", "tool_crash", true, "switch_to_fallback")]
    [InlineData("nuclei", "you need root to bind raw socket", "permission_denied", false, null)]
    [InlineData("legacy_poc", "/usr/bin/python2: No such file or directory", "interpreter_missing", false, null)]
    [InlineData("anything", "weird output we have never seen", "unknown", true, "reduce_concurrency")]
    public void Classifies_Each_Failure_Kind(string tool, string output, string expectedKind, bool recoverable, string? downgrade)
    {
        var c = _c.Classify(tool, exception: null, exitCode: null, stderrOrOutput: output);
        Assert.Equal(expectedKind, c.Kind);
        Assert.Equal(recoverable, c.Recoverable);
        Assert.Equal(downgrade, c.SuggestedDowngrade);
    }

    [Fact]
    public void Classifies_ScopeException_AsOutOfScopeRuntime()
    {
        var c = _c.Classify("nmap", new ScopeException("x"), exitCode: null, stderrOrOutput: null);
        Assert.Equal("out_of_scope_runtime", c.Kind);
        Assert.False(c.Recoverable);
    }

    [Fact]
    public void TransientNetwork_BackoffGrowsExponentially_Capped60s()
    {
        var c1 = _c.Classify("t", new SocketException(), null, "connection refused", attempt: 1);
        var c2 = _c.Classify("t", new SocketException(), null, "connection refused", attempt: 2);
        var c5 = _c.Classify("t", new SocketException(), null, "connection refused", attempt: 5);
        Assert.Equal(TimeSpan.FromSeconds(5), c1.SuggestedBackoff);
        Assert.Equal(TimeSpan.FromSeconds(10), c2.SuggestedBackoff);
        Assert.Equal(TimeSpan.FromSeconds(60), c5.SuggestedBackoff);
    }

    [Fact]
    public void RateLimit_RespectsRetryAfterHeader_Seconds()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Retry-After"] = "12",
        };
        var c = _c.Classify("http", null, null, "rate limit hit", responseHeaders: headers);
        Assert.Equal("rate_limited", c.Kind);
        Assert.Equal(TimeSpan.FromSeconds(12), c.SuggestedBackoff);
    }

    [Fact]
    public void HttpRequestException_Treated_AsTransientNetwork_NotAuth()
    {
        var c = _c.Classify("http", new HttpRequestException("boom"), null, null);
        Assert.Equal("transient_network", c.Kind);
    }
}
