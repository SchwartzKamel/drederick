import { useEffect, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatTimestamp, formatCount } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { useHosts } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";

export type HostsListProps = {
  /** Optional limit — when set the search bar + pagination are hidden. */
  limit?: number;
  /** Hide the search bar (used on landing widgets). */
  hideSearch?: boolean;
  /** Hide the pagination bar (used on landing widgets). */
  hidePager?: boolean;
  /** Optional className for outer Card. */
  className?: string;
};

export function HostsList({
  limit,
  hideSearch,
  hidePager,
  className,
}: HostsListProps) {
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [offset, setOffset] = useState(0);
  const pageSize = limit ?? 25;

  useEffect(() => {
    const id = window.setTimeout(() => {
      setDebounced(q);
      setOffset(0);
    }, 250);
    return () => window.clearTimeout(id);
  }, [q]);

  const { data, isLoading, isError } = useHosts({
    q: debounced || undefined,
    limit: pageSize,
    offset,
  });

  const body = useMemo(() => {
    if (isLoading) {
      return <LoadingSkeleton rows={5} columns={5} />;
    }
    if (isError || !data) {
      return <EmptyState kind="no_hosts" />;
    }
    if (isNoDatabase(data)) {
      return <EmptyState kind="no_database" />;
    }
    if (data.items.length === 0) {
      return <EmptyState kind="no_hosts" />;
    }
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2">Address</th>
              <th className="px-3 py-2">Hostname</th>
              <th className="px-3 py-2">First seen</th>
              <th className="px-3 py-2">Last seen</th>
              <th className="px-3 py-2 text-right">Services</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((h) => (
              <tr
                key={h.id}
                className="border-b border-border/60 hover:bg-accent/40"
              >
                <td className="px-3 py-2 font-mono">
                  <Link
                    to="/findings/hosts/$host_id"
                    params={{ host_id: String(h.id) }}
                    className="text-primary hover:underline"
                  >
                    {h.address}
                  </Link>
                </td>
                <td className="px-3 py-2 text-muted-foreground">
                  {h.hostname ?? "—"}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {formatTimestamp(h.first_seen)}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {formatTimestamp(h.last_seen)}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {formatCount(h.services_count)}
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
      {!hideSearch ? (
        <div className="flex items-center gap-2 border-b border-border p-3">
          <Search className="h-4 w-4 text-muted-foreground" aria-hidden />
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter by address or hostname…"
            className="w-full border-0 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            aria-label="Search opponents"
          />
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
