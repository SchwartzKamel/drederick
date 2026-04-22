import { Link } from "@tanstack/react-router";
import { Eye, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/lib/toast";
import { DrederickApiError } from "@/api/client";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { formatRelative } from "@/lib/formatters";
import {
  useCancelJeopardySession,
  useJeopardySessions,
} from "@/api/hooks/useJeopardy";
import type { JeopardySessionSummary } from "@/api/types";
import { SpendMeter } from "./SpendMeter";

const STATUS_STYLES: Record<string, string> = {
  running: "bg-yellow-500/20 text-yellow-400",
  finished: "bg-emerald-500/20 text-emerald-400",
  failed: "bg-red-500/20 text-red-400",
  cancelled: "bg-slate-500/20 text-slate-400",
};

function statusClasses(s: string): string {
  return STATUS_STYLES[s.toLowerCase()] ?? "bg-muted text-muted-foreground";
}

function short(id: string): string {
  return id.length > 12 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

/** Budget is not returned on the summary; show spend against a fixed $1 so
 * the bar remains informative (over-purse never triggers). Full budget
 * lands in the detail view. */
function SpendCell({ row }: { row: JeopardySessionSummary }) {
  const budget = Math.max(row.total_usd_cost, 1);
  return (
    <SpendMeter
      spent_usd={row.total_usd_cost}
      budget_usd={budget}
      mode="tiny"
    />
  );
}

function CancelButton({ sessionId }: { sessionId: string }) {
  const mutation = useCancelJeopardySession();
  async function onClick() {
    if (!window.confirm("Throw in the towel on this session?")) return;
    try {
      await mutation.mutateAsync(sessionId);
      toast.success("Towel thrown. Session cancelled.");
    } catch (err) {
      if (err instanceof DrederickApiError && err.isNotFound) {
        toast.fromTatum("not_found");
      } else {
        toast.fromTatum("server");
      }
    }
  }
  return (
    <Button
      size="sm"
      variant="ghost"
      onClick={onClick}
      disabled={mutation.isPending}
      aria-label="Cancel session"
    >
      <X className="h-3 w-3" aria-hidden />
      {mutation.isPending ? "Tossing…" : "Throw in the towel"}
    </Button>
  );
}

export function SessionsTable() {
  const { data, isLoading, isError } = useJeopardySessions();

  if (isLoading) {
    return <LoadingSkeleton rows={4} columns={6} />;
  }
  if (isError) {
    return (
      <EmptyState
        kind="no_sessions"
        title="The corner is unreachable."
        body="Session listing failed."
      />
    );
  }
  if (!data || data.length === 0) {
    return <EmptyState kind="no_sessions" />;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full border-collapse text-sm">
        <thead className="bg-card/60 text-left">
          <tr>
            {[
              "session",
              "started",
              "status",
              "found",
              "solved",
              "spend",
              "",
            ].map((h) => (
              <th
                key={h}
                className="px-3 py-2 font-mono text-xs font-normal uppercase tracking-wider text-muted-foreground"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((s) => {
            const id = s.session_id;
            const open = s.status.toLowerCase() === "running";
            return (
              <tr key={id} className="border-t border-border">
                <td className="px-3 py-2 font-mono text-xs">
                  <Link
                    to="/jeopardy/sessions/$session_id"
                    params={{ session_id: id }}
                    className="text-primary hover:underline"
                  >
                    {short(id)}
                  </Link>
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {formatRelative(s.started_at)}
                </td>
                <td className="px-3 py-2">
                  <span
                    className={`inline-flex rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider ${statusClasses(s.status)}`}
                  >
                    {s.status}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-xs">
                  {s.challenges_discovered}
                </td>
                <td className="px-3 py-2 font-mono text-xs">
                  {s.challenges_solved}
                </td>
                <td className="min-w-[10rem] px-3 py-2">
                  <SpendCell row={s} />
                </td>
                <td className="flex items-center gap-1 px-3 py-2">
                  <Button size="sm" variant="ghost" asChild>
                    <Link
                      to="/jeopardy/sessions/$session_id"
                      params={{ session_id: id }}
                    >
                      <Eye className="h-3 w-3" aria-hidden />
                      view
                    </Link>
                  </Button>
                  {open ? <CancelButton sessionId={id} /> : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
