import { Link } from "@tanstack/react-router";
import type { RunRecord, RunStatus } from "@/api/types";
import { useCancelRun } from "@/api/hooks/useRuns";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { formatRelative, truncateSha256 } from "@/lib/formatters";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

export type RunsTableProps = {
  runs: RunRecord[] | undefined;
  isLoading: boolean;
};

export function RunsTable({ runs, isLoading }: RunsTableProps) {
  if (isLoading) {
    return <LoadingSkeleton rows={5} columns={5} />;
  }
  if (!runs || runs.length === 0) {
    return <EmptyState kind="no_runs" />;
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-sm">
        <thead className="bg-muted/40 text-left text-xs uppercase tracking-wider text-muted-foreground">
          <tr>
            <th className="px-3 py-2 font-mono">run_id</th>
            <th className="px-3 py-2">started</th>
            <th className="px-3 py-2">finished</th>
            <th className="px-3 py-2">status</th>
            <th className="px-3 py-2 text-right">targets</th>
            <th className="px-3 py-2 text-right">findings</th>
            <th className="px-3 py-2 text-right">actions</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((r) => (
            <RunRow key={r.run_id} run={r} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RunRow({ run }: { run: RunRecord }) {
  const cancel = useCancelRun();
  const isLive = run.status === "running" || run.status === "pending";

  const onCancel = async () => {
    try {
      await cancel.mutateAsync(run.run_id);
      toast.success("Bout called.", { description: `run ${run.run_id}` });
    } catch {
      toast.fromTatum("server");
    }
  };

  return (
    <tr className="border-t border-border/60 hover:bg-accent/30">
      <td className="px-3 py-2 font-mono text-xs">
        <Link
          to="/runs/$run_id"
          params={{ run_id: run.run_id }}
          className="text-primary hover:underline"
          title={run.run_id}
        >
          {truncateSha256(run.run_id, 6, 4)}
        </Link>
      </td>
      <td className="px-3 py-2 text-xs" title={run.started_at}>
        {formatRelative(run.started_at)}
      </td>
      <td className="px-3 py-2 text-xs" title={run.finished_at ?? ""}>
        {run.finished_at ? formatRelative(run.finished_at) : "—"}
      </td>
      <td className="px-3 py-2">
        <StatusBadge status={run.status} />
      </td>
      <td className="px-3 py-2 text-right font-mono text-xs">
        {run.target_count}
      </td>
      <td className="px-3 py-2 text-right font-mono text-xs">
        {run.finding_count}
      </td>
      <td className="px-3 py-2 text-right">
        <div className="flex justify-end gap-2">
          <Button asChild size="sm" variant="outline">
            <Link to="/runs/$run_id" params={{ run_id: run.run_id }}>
              View detail
            </Link>
          </Button>
          {isLive ? (
            <Button
              size="sm"
              variant="destructive"
              disabled={cancel.isPending}
              onClick={onCancel}
            >
              Cancel run
            </Button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

export function StatusBadge({ status }: { status: RunStatus }) {
  const label = String(status);
  const cls = STATUS_CLS[label] ?? "bg-muted text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider",
        cls,
      )}
    >
      {label}
    </span>
  );
}

const STATUS_CLS: Record<string, string> = {
  pending: "bg-amber-500/15 text-amber-400",
  running: "bg-sky-500/15 text-sky-400",
  finished: "bg-emerald-500/15 text-emerald-400",
  completed: "bg-emerald-500/15 text-emerald-400",
  cancelled: "bg-zinc-500/20 text-zinc-300",
  failed: "bg-rose-500/15 text-rose-400",
};


