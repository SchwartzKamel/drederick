import { useState } from "react";
import { useSessionRows } from "@/api/hooks/useFindings";
import { isNoDatabase, type SessionRow, type SessionState } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { formatRelative, formatTimestamp } from "@/lib/formatters";
import { cn } from "@/lib/utils";

export function SessionsPanel() {
  const [state, setState] = useState<SessionState>("open");
  const query = useSessionRows({ state, limit: 100 });

  return (
    <div className="space-y-3">
      <div className="inline-flex overflow-hidden rounded-md border border-border">
        {(["open", "closed"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => setState(s)}
            className={cn(
              "px-4 py-1.5 font-mono text-xs uppercase tracking-wider",
              s === state
                ? "bg-primary text-primary-foreground"
                : "bg-background text-muted-foreground hover:bg-accent",
            )}
          >
            {s}
          </button>
        ))}
      </div>

      {query.isLoading ? (
        <LoadingSkeleton rows={5} columns={4} />
      ) : query.isError || !query.data ? (
        <EmptyState
          kind="no_sessions"
          title="The referee has called a timeout."
          body="Could not load session records."
        />
      ) : isNoDatabase(query.data) ? (
        <EmptyState kind="no_database" />
      ) : query.data.items.length === 0 ? (
        <EmptyState
          kind="no_sessions"
          title="The cage is quiet."
          body="No sessions in the cage."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2">target</th>
                <th className="px-3 py-2">protocol</th>
                <th className="px-3 py-2">via</th>
                <th className="px-3 py-2">opened</th>
                <th className="px-3 py-2">closed</th>
                <th className="px-3 py-2">state</th>
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((r) => (
                <SessionRowView key={r.id} row={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function SessionRowView({ row }: { row: SessionRow }) {
  return (
    <tr className="border-t border-border/60 hover:bg-accent/30">
      <td className="px-3 py-2 font-mono text-xs">{row.target}</td>
      <td className="px-3 py-2 font-mono text-xs">{row.protocol}</td>
      <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
        {row.via_tool ?? "—"}
      </td>
      <td className="px-3 py-2 text-xs" title={row.opened_at}>
        {formatRelative(row.opened_at)}
      </td>
      <td className="px-3 py-2 text-xs" title={row.closed_at ?? ""}>
        {row.closed_at ? formatTimestamp(row.closed_at) : "—"}
      </td>
      <td className="px-3 py-2">
        <span
          className={cn(
            "inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider",
            row.state === "open"
              ? "bg-emerald-500/15 text-emerald-400"
              : "bg-zinc-500/20 text-zinc-300",
          )}
        >
          {row.state}
        </span>
      </td>
    </tr>
  );
}
