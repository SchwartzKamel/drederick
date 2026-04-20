using System.Net;
using Drederick.Audit;
using Drederick.Scope;

namespace Drederick.Recon;

public sealed class DnsProbeTool
{
    private readonly Scope.Scope _scope;
    private readonly AuditLog _audit;

    public DnsProbeTool(Scope.Scope scope, AuditLog audit)
    {
        _scope = scope;
        _audit = audit;
    }

    public async Task<DnsResult> ProbeAsync(string target, CancellationToken ct = default)
    {
        _scope.Require(target);
        _audit.Record("dns.request", new Dictionary<string, object?> { ["target"] = target });
        var result = new DnsResult { Target = target };

        try
        {
            var entry = await Dns.GetHostEntryAsync(target, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(entry.HostName) && entry.HostName != target)
                result.Reverse = entry.HostName;
        }
        catch (Exception ex) { result.ReverseError = ex.Message; }

        try
        {
            var addrs = await Dns.GetHostAddressesAsync(target, ct).ConfigureAwait(false);
            if (addrs.Length > 0) result.Forward = addrs[0].ToString();
        }
        catch (Exception ex) { result.ForwardError = ex.Message; }

        return result;
    }
}
