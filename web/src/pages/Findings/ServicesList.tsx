import { useState, useMemo, useEffect } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatCount } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { useServices } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";

export type ServicesListProps = {
  hostId?: number;
  limit?: number;
  hidePager?: boolean;
  className?: string;
};

export function ServicesList({
  hostId,
  limit,
  hidePager,
  className,
}: ServicesListProps) {
  const pageSize = limit ?? 25;
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    setOffset(0);
  }, [hostId]);

  const { data, isLoading, isError } = useServices({
    host_id: hostId,
    limit: pageSize,
    offset,
  });

  const body = useMemo(() => {
    if (isLoading) return <LoadingSkeleton rows={5} columns={5} />;
    if (isError || !data) return <EmptyState kind="no_services" />;
    if (isNoDatabase(data)) return <EmptyState kind="no_database" />;
    if (data.items.length === 0) return <EmptyState kind="no_services" />;
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2 text-right">Port</th>
              <th className="px-3 py-2">Proto</th>
              <th className="px-3 py-2">Service</th>
              <th className="px-3 py-2">Product</th>
              <th className="px-3 py-2">Version</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((s) => (
              <tr
                key={s.id}
                className="border-b border-border/60 hover:bg-accent/40"
              >
                <td className="px-3 py-2 text-right font-mono">
                  <Link
                    to="/findings/services/$service_id"
                    params={{ service_id: String(s.id) }}
                    className="text-primary hover:underline"
                  >
                    {s.port}
                  </Link>
                </td>
                <td className="px-3 py-2 font-mono uppercase text-muted-foreground">
                  {s.protocol}
                </td>
                <td className="px-3 py-2">{s.service_name ?? "—"}</td>
                <td className="px-3 py-2 text-muted-foreground">
                  {s.product ?? "—"}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {s.version ?? "—"}
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
