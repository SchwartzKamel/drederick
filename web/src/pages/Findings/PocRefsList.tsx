import { useState, useEffect, useMemo } from "react";
import { Check, ChevronLeft, ChevronRight, Copy, ExternalLink } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { RedactedValue } from "@/components/RedactedValue";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { formatCount } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { tatumisms } from "@/lib/tatumisms";
import { usePocRefs } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";

export type PocRefsListProps = {
  cveId?: string;
  source?: string;
  limit?: number;
  hidePager?: boolean;
  className?: string;
};

function CopyPath({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };
  return (
    <span className="inline-flex items-center gap-1 font-mono text-xs">
      <span className="max-w-[16rem] truncate text-muted-foreground" title={path}>
        {path}
      </span>
      <button
        type="button"
        onClick={onCopy}
        aria-label={copied ? tatumisms.actions.copied : tatumisms.actions.copy}
        className="inline-flex h-4 w-4 items-center justify-center rounded opacity-60 hover:opacity-100"
      >
        {copied ? (
          <Check className="h-3 w-3" aria-hidden />
        ) : (
          <Copy className="h-3 w-3" aria-hidden />
        )}
      </button>
    </span>
  );
}

export function PocRefsList({
  cveId,
  source,
  limit,
  hidePager,
  className,
}: PocRefsListProps) {
  const pageSize = limit ?? 25;
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    setOffset(0);
  }, [cveId, source]);

  const { data, isLoading, isError } = usePocRefs({
    cve_id: cveId,
    source,
    limit: pageSize,
    offset,
  });

  const body = useMemo(() => {
    if (isLoading) return <LoadingSkeleton rows={5} columns={5} />;
    if (isError || !data) return <EmptyState kind="no_poc_refs" />;
    if (isNoDatabase(data)) return <EmptyState kind="no_database" />;
    if (data.items.length === 0) return <EmptyState kind="no_poc_refs" />;
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2">Source</th>
              <th className="px-3 py-2">URL</th>
              <th className="px-3 py-2">Match</th>
              <th className="px-3 py-2">sha256</th>
              <th className="px-3 py-2">Local path</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((p) => (
              <tr
                key={p.id}
                className="border-b border-border/60 hover:bg-accent/40"
              >
                <td className="px-3 py-2">
                  <span className="rounded-md border border-border bg-muted px-2 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
                    {p.source}
                  </span>
                </td>
                <td className="px-3 py-2">
                  {p.url ? (
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="inline-flex max-w-[24rem] items-center gap-1 truncate text-primary hover:underline"
                      title={p.url}
                    >
                      <span className="truncate">{p.url}</span>
                      <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
                    </a>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {p.match_confidence ?? "—"}
                </td>
                <td className="px-3 py-2">
                  {p.sha256 ? (
                    <RedactedValue sha256={p.sha256} />
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  {p.local_path ? (
                    <CopyPath path={p.local_path} />
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
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
