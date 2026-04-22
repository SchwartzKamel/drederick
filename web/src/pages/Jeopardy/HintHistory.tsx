import { useJeopardyHints } from "@/api/hooks/useJeopardy";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { RedactedValue } from "@/components/RedactedValue";
import { formatRelative } from "@/lib/formatters";
import { cn } from "@/lib/utils";

export type HintHistoryProps = {
  sessionId: string;
};

const KIND_STYLES: Record<string, string> = {
  hint: "bg-blue-500/15 text-blue-400",
  note: "bg-slate-500/15 text-slate-300",
  command: "bg-amber-500/15 text-amber-400",
  nudge: "bg-purple-500/15 text-purple-400",
};

function kindClasses(k: string): string {
  return KIND_STYLES[k.toLowerCase()] ?? KIND_STYLES.note!;
}

export function HintHistory({ sessionId }: HintHistoryProps) {
  const { data, isLoading, isError } = useJeopardyHints(sessionId);

  if (isLoading) return <LoadingSkeleton rows={4} />;
  if (isError) {
    return (
      <EmptyState
        kind="no_events"
        title="Hint log unavailable."
        body="The corner did not respond."
      />
    );
  }
  if (!data || data.length === 0) {
    return (
      <EmptyState
        kind="no_events"
        title="No instructions from the corner."
        body="Hints sent to this session will appear here."
      />
    );
  }

  const sorted = [...data].sort(
    (a, b) => new Date(b.at).getTime() - new Date(a.at).getTime(),
  );

  return (
    <ul className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
      {sorted.map((h, i) => (
        <li
          key={`${h.at}-${i}`}
          className="rounded-md border border-border bg-card/60 p-2 text-xs"
        >
          <div className="mb-1 flex items-center justify-between gap-2">
            <span
              className={cn(
                "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[0.6rem] uppercase tracking-wider",
                kindClasses(h.kind),
              )}
            >
              {h.kind}
            </span>
            <span className="font-mono text-[0.65rem] text-muted-foreground">
              {h.challenge_id ? `challenge ${h.challenge_id}` : "broadcast"}
            </span>
            <span className="font-mono text-[0.65rem] text-muted-foreground">
              {formatRelative(h.at)}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[0.65rem] text-muted-foreground">
              body
            </span>
            <RedactedValue sha256={h.body_sha256} label="sha256" />
            {h.solver_id ? (
              <span className="font-mono text-[0.65rem] text-muted-foreground">
                → {h.solver_id}
              </span>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  );
}
