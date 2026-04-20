using System.Text;
using Drederick.Recon;

namespace Drederick.Reporting;

public static class MarkdownReport
{
    public static void Write(string path, IEnumerable<HostFinding> hosts, string scopeSource)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var sb = new StringBuilder();
        sb.AppendLine("# drederick recon report");
        sb.AppendLine();
        sb.Append("_Scope source: `").Append(scopeSource).AppendLine("`_");
        sb.AppendLine();
        sb.AppendLine("> Authorized-lab reconnaissance only. Non-exploitative discovery and fingerprinting.");
        sb.AppendLine();

        foreach (var h in hosts)
        {
            sb.Append("## ").AppendLine(h.Target);
            sb.Append("- Started: ").AppendLine(h.Started);
            sb.Append("- Finished: ").AppendLine(h.Finished ?? "-");
            if (h.Dns is not null)
            {
                sb.Append("- DNS forward: `").Append(h.Dns.Forward ?? "-")
                  .Append("`  reverse: `").Append(h.Dns.Reverse ?? "-").AppendLine("`");
            }
            sb.AppendLine();

            sb.AppendLine("### Open TCP services");
            sb.AppendLine();
            var ports = h.Nmap?.OpenPorts ?? [];
            if (ports.Count == 0)
            {
                sb.AppendLine("_no open TCP ports observed_");
            }
            else
            {
                sb.AppendLine("| Port | Proto | Service | Product | Version |");
                sb.AppendLine("|------|-------|---------|---------|---------|");
                foreach (var p in ports)
                {
                    sb.Append("| ").Append(p.Port)
                      .Append(" | ").Append(p.Protocol)
                      .Append(" | ").Append(p.Service ?? "")
                      .Append(" | ").Append(p.Product ?? "")
                      .Append(" | ").Append(p.Version ?? "")
                      .AppendLine(" |");
                }
            }
            sb.AppendLine();

            if (h.Http.Count > 0)
            {
                sb.AppendLine("### HTTP");
                sb.AppendLine();
                foreach (var e in h.Http)
                {
                    if (!string.IsNullOrEmpty(e.Error))
                    {
                        sb.Append("- ").Append(e.Url).Append(" — error: ").AppendLine(e.Error);
                        continue;
                    }
                    sb.Append("- ").Append(e.Url).Append(" → ").Append(e.Status)
                      .Append(' ').Append(e.Title ?? "")
                      .Append(" (server: `").Append(e.Server ?? "-").AppendLine("`)");
                    if (e.MissingSecurityHeaders.Count > 0)
                    {
                        sb.Append("  - Missing security headers: ")
                          .AppendLine(string.Join(", ", e.MissingSecurityHeaders));
                    }
                }
                sb.AppendLine();
            }

            if (h.Tls.Count > 0)
            {
                sb.AppendLine("### TLS");
                sb.AppendLine();
                foreach (var e in h.Tls)
                {
                    if (!string.IsNullOrEmpty(e.Error))
                    {
                        sb.Append("- port ").Append(e.Port).Append(" — error: ").AppendLine(e.Error);
                        continue;
                    }
                    sb.Append("- port ").Append(e.Port)
                      .Append(": ").Append(e.TlsVersion)
                      .Append(" subj=`").Append(e.Subject ?? "-")
                      .Append("` expires=").Append(e.NotAfter ?? "-")
                      .Append(" (").Append(e.DaysUntilExpiry?.ToString() ?? "?").AppendLine(" days)");
                }
                sb.AppendLine();
            }

            if (h.Errors.Count > 0)
            {
                sb.AppendLine("### Errors");
                foreach (var err in h.Errors) sb.Append("- ").AppendLine(err);
                sb.AppendLine();
            }
        }

        File.WriteAllText(path, sb.ToString());
    }
}
