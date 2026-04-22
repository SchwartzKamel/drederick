import { useJeopardySwarm } from "@/api/hooks/useJeopardy";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { cn } from "@/lib/utils";

export type SwarmPanelProps = {
  sessionId: string;
  /** When true, shows the full (row per challenge × col per model) matrix. */
  full?: boolean;
};

const STATE_COLOR: Record<string, string> = {
  pending: "bg-muted",
  racing: "bg-yellow-500/40",
  solved: "bg-emerald-500/50",
  failed: "bg-red-500/40",
  skipped: "bg-slate-500/30",
};

function stateDot(state: string): string {
  return STATE_COLOR[state.toLowerCase()] ?? "bg-muted";
}

/**
 * Compact swarm overview: one row per challenge, one cell per model
 * participating. Green when that model solved; yellow if it's still in
 * the ring; red if it tapped out.
 */
export function SwarmPanel({ sessionId, full = false }: SwarmPanelProps) {
  const { data, isLoading, isError } = useJeopardySwarm(sessionId);

  if (isLoading) return <LoadingSkeleton rows={6} columns={3} />;
  if (isError || !data) {
    return (
      <EmptyState
        kind="no_events"
        title="Swarm feed quiet."
        body="The corner has no telemetry to share yet."
      />
    );
  }
  if (data.length === 0) {
    return (
      <EmptyState
        kind="no_events"
        title="Swarm empty."
        body="No challenges have been dispatched to the corner yet."
      />
    );
  }

  const models = Array.from(
    new Set(
      data.flatMap((c) => [
        ...c.active_solvers.map((s) => s.model),
        ...(c.solved_by_model ? [c.solved_by_model] : []),
      ]),
    ),
  ).sort();

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-xs">
        <thead className="bg-card/60 text-left text-muted-foreground">
          <tr>
            <th className="sticky left-0 bg-card/80 px-2 py-1 font-mono font-normal">
              challenge
            </th>
            <th className="px-2 py-1 font-mono font-normal">cat</th>
            <th className="px-2 py-1 font-mono font-normal">state</th>
            {models.map((m) => (
              <th
                key={m}
                className="px-2 py-1 font-mono font-normal"
                title={m}
              >
                <span className="inline-block max-w-[6rem] truncate align-bottom">
                  {m}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((c) => (
            <tr key={c.id} className="border-t border-border">
              <td className="sticky left-0 max-w-[14rem] truncate bg-background px-2 py-1 font-mono">
                {c.name}
              </td>
              <td className="px-2 py-1 font-mono text-muted-foreground">
                {c.category}
              </td>
              <td className="px-2 py-1">
                <span
                  className={cn(
                    "inline-flex rounded px-1.5 py-0.5 font-mono text-[0.6rem] uppercase tracking-wider",
                    stateDot(c.state),
                  )}
                >
                  {c.state}
                </span>
              </td>
              {models.map((m) => {
                const solver = c.active_solvers.find((s) => s.model === m);
                const isSolverOfRecord = c.solved_by_model === m;
                let cell = "bg-transparent";
                let label = "—";
                if (isSolverOfRecord) {
                  cell = STATE_COLOR.solved!;
                  label = "✓";
                } else if (solver) {
                  cell = STATE_COLOR.racing!;
                  label = full ? `t${solver.turns_taken}` : "·";
                }
                return (
                  <td
                    key={m}
                    className={cn("px-2 py-1 text-center font-mono", cell)}
                    title={
                      solver
                        ? `${m}: turn ${solver.turns_taken}`
                        : isSolverOfRecord
                          ? `${m}: solved`
                          : `${m}: idle`
                    }
                  >
                    {label}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
