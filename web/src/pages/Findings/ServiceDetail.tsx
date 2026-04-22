import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useService } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";
import { SeverityBadge } from "./SeverityBadge";

export function ServiceDetail() {
  const { service_id } = useParams({ strict: false }) as { service_id: string };
  const serviceIdNum = Number.parseInt(service_id, 10);
  const { data, isLoading, isError } = useService(
    Number.isFinite(serviceIdNum) ? serviceIdNum : undefined,
  );

  if (isLoading) {
    return <LoadingSkeleton rows={4} columns={2} cellClassName="h-10" />;
  }
  if (isError || !data) return <EmptyState kind="no_services" />;
  if (isNoDatabase(data)) return <EmptyState kind="no_database" />;

  const svc = data;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/findings/services">
          <ArrowLeft className="h-4 w-4" /> See all services
        </Link>
      </Button>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-lg">
            {svc.protocol.toUpperCase()}/{svc.port}
            {svc.service_name ? ` — ${svc.service_name}` : ""}
          </CardTitle>
          <p className="text-xs text-muted-foreground">
            The ring card on this service.
          </p>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm sm:grid-cols-2">
          <MetaRow label="Host ID" value={String(svc.host_id)} />
          <MetaRow label="Port" value={String(svc.port)} />
          <MetaRow label="Protocol" value={svc.protocol.toUpperCase()} />
          <MetaRow label="Service name" value={svc.service_name ?? "—"} />
          <MetaRow label="Product" value={svc.product ?? "—"} />
          <MetaRow label="Version" value={svc.version ?? "—"} />
        </CardContent>
      </Card>

      <div className="space-y-2">
        <h3 className="font-mono text-sm uppercase tracking-wider text-muted-foreground">
          Linked CVEs
        </h3>
        {svc.cves.length === 0 ? (
          <EmptyState kind="no_cves" />
        ) : (
          <Card className="overflow-hidden">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
                      <th className="px-3 py-2">CVE</th>
                      <th className="px-3 py-2">Severity</th>
                      <th className="px-3 py-2 text-right">CVSS</th>
                      <th className="px-3 py-2">Summary</th>
                    </tr>
                  </thead>
                  <tbody>
                    {svc.cves.map((c) => (
                      <tr
                        key={c.cve_id}
                        className="border-b border-border/60 hover:bg-accent/40"
                      >
                        <td className="px-3 py-2 font-mono">
                          <Link
                            to="/findings/cves/$cve_id"
                            params={{ cve_id: c.cve_id }}
                            className="text-primary hover:underline"
                          >
                            {c.cve_id}
                          </Link>
                        </td>
                        <td className="px-3 py-2">
                          <SeverityBadge severity={c.severity} />
                        </td>
                        <td className="px-3 py-2 text-right font-mono">
                          {c.cvss !== null && c.cvss !== undefined
                            ? c.cvss.toFixed(1)
                            : "—"}
                        </td>
                        <td className="max-w-[32rem] truncate px-3 py-2 text-muted-foreground">
                          {c.summary ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-border/60 bg-card/40 px-3 py-2">
      <span className="font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className="text-right">{value}</span>
    </div>
  );
}
