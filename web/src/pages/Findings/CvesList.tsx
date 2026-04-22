import { useState, useMemo, useEffect } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatCount } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { useCves } from "@/api/hooks/useFindings";
import { isNoDatabase, type Severity } from "@/api/types";
import { SeverityBadge } from "./SeverityBadge";

export type CvesListProps = {
  hostId?: number;
  serviceId?: number;
  severity?: Severity;
  limit?: number;
  hidePager?: boolean;
  hideSeverityChips?: boolean;
  className?: string;
};

const SEV_CHIPS: Array<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
];

export function CvesList({
  hostId,
  serviceId,
  severity: severityProp,
  limit,
  hidePager,
  hideSeverityChips,
  className,
}: CvesListProps) {
  const pageSize = limit ?? 25;
  const [offset, setOffset] = useState(0);
  const [localSev, setLocalSev] = useState<Severity | undefined>(severityProp);
  const effectiveSev = severityProp ?? localSev;

  useEffect(() => {
    setOffset(0);
  }, [effectiveSev, hostId, serviceId]);

  const { data, isLoading, isError } = useCves({
    host_id: hostId,
    service_id: serviceId,
    severity: effectiveSev,
    limit: pageSize,
    offset,
  });

  const body = useMemo(() => {
    if (isLoading) return <LoadingSkeleton rows={5} columns={5} />;
    if (isError || !data) return <EmptyState kind="no_cves" />;
    if (isNoDatabase(data)) return <EmptyState kind="no_database" />;
    if (data.items.length === 0) return <EmptyState kind="no_cves" />;
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2">CVE</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2 text-right">CVSS</th>
              <th className="px-3 py-2">Summary</th>
              <th className="px-3 py-2">Published</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((c) => (
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
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {c.published?.slice(0, 10) ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }, [data, isError, isLoading]);

  const total = data && !isNoDatabase(data) ? data.total : 0;
  const canPrev = offset > 0;
  const canNext = data && !isNoDatabase(data) && offset + pageSize < total;

  return (
    <Card className={cn("overflow-hidden", className)}>
      {!hideSeverityChips && !severityProp ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <span className="font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
            severity
          </span>
          {SEV_CHIPS.map((chip) => {
            const active =
              (chip === "all" && !localSev) || localSev === chip;
            return (
              <button
                key={chip}
                type="button"
                onClick={() =>
                  setLocalSev(chip === "all" ? undefined : (chip as Severity))
                }
                className={cn(
                  "rounded-md border px-2 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider",
                  active
                    ? "border-primary bg-primary text-primary-foreground"
                    : "border-border text-muted-foreground hover:bg-accent",
                )}
              >
                {chip}
              </button>
            );
          })}
        </div>
      ) : null}
      <CardContent className="p-0">{body}</CardContent>
      {!hidePager && data && !isNoDatabase(data) && data.items.length > 0 ? (
        <div className="flex items-center justify-between border-t border-border p-3 font-mono text-xs text-muted-foreground">
          <span>
            {offset + 1}–{Math.min(offset + data.items.length, total)} of{" "}
            {formatCount(total)}
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!canPrev}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              <ChevronLeft className="h-3 w-3" /> Prev
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!canNext}
              onClick={() => setOffset(offset + pageSize)}
            >
              Next <ChevronRight className="h-3 w-3" />
            </Button>
          </div>
        </div>
      ) : null}
    </Card>
  );
}
