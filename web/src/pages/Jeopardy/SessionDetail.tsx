import { useEffect } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Grid3x3 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { RedactedValue } from "@/components/RedactedValue";
import { formatTimestamp, formatRelative } from "@/lib/formatters";
import {
  useCancelJeopardySession,
  useJeopardySession,
} from "@/api/hooks/useJeopardy";
import { useSignalREvents } from "@/api/signalr";
import { toast } from "@/lib/toast";
import { DrederickApiError } from "@/api/client";
import { ChallengesGrid } from "./ChallengesGrid";
import { HintHistory } from "./HintHistory";
import { HintInjector } from "./HintInjector";
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

/**
 * Session detail — three column on desktop, stacked on mobile.
 *   left  : metadata + spend
 *   center: challenges grid (live)
 *   right : hint injector + hint history
 */
export function SessionDetail() {
  const { session_id: sessionId } = useParams({
    from: "/jeopardy/sessions/$session_id",
  });
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useJeopardySession(sessionId);
  const { events } = useSignalREvents("jeopardy");
  const cancel = useCancelJeopardySession();

  // Invalidate session detail on any jeopardy scan event — lets the
  // existing 3s refetch pick up the new authoritative payload without
  // any client-side merging.
  useEffect(() => {
    if (events.length === 0) return;
    const latest = events[events.length - 1];
    if (!latest) return;
    if (!latest.Kind?.toLowerCase().startsWith("jeopardy")) return;
    qc.invalidateQueries({ queryKey: ["jeopardy", "session", sessionId] });
    qc.invalidateQueries({ queryKey: ["jeopardy", "hints", sessionId] });
  }, [events, qc, sessionId]);

  if (isLoading) {
    return (
      <div className="flex flex-col gap-4">
        <LoadingSkeleton rows={6} columns={3} cellClassName="h-12" />
      </div>
    );
  }
  if (isError) {
    if (error instanceof DrederickApiError && error.isNotFound) {
      return (
        <EmptyState
          kind="no_sessions"
          title="No such bout on the card."
          body={`session ${sessionId} is not on file.`}
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/jeopardy">
                <ArrowLeft className="h-3 w-3" aria-hidden /> back to division
              </Link>
            </Button>
          }
        />
      );
    }
    return (
      <EmptyState
        kind="no_sessions"
        title="The corner is unreachable."
        body="Session detail failed to load."
      />
    );
  }
  if (!data) return null;

  const running = data.status.toLowerCase() === "running";
  // Derive budget: the detail DTO currently reflects total_usd_cost
  // only. We surface it against itself for headroom; over-purse state
  // is computed from the session's original budget when that lands.
  const budget = Math.max(data.total_usd_cost * 1.5, 1);

  async function onCancel() {
    if (!window.confirm("Throw in the towel on this session?")) return;
    try {
      await cancel.mutateAsync(sessionId);
      toast.success("Towel thrown. Session cancelled.");
    } catch {
      toast.fromTatum("server");
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Button asChild variant="ghost" size="sm">
            <Link to="/jeopardy">
              <ArrowLeft className="h-3 w-3" aria-hidden /> division
            </Link>
          </Button>
          <h1 className="font-mono text-lg">
            <span className="text-muted-foreground">session </span>
            <span className="text-foreground">{sessionId}</span>
          </h1>
          <span
            className={`inline-flex rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider ${statusClasses(data.status)}`}
          >
            {data.status}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm">
            <Link
              to="/jeopardy/sessions/$session_id/swarm"
              params={{ session_id: sessionId }}
            >
              <Grid3x3 className="h-3 w-3" aria-hidden /> swarm view
            </Link>
          </Button>
          {running ? (
            <Button
              variant="destructive"
              size="sm"
              onClick={onCancel}
              disabled={cancel.isPending}
            >
              {cancel.isPending ? "Tossing…" : "Throw in the towel"}
            </Button>
          ) : null}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[20rem_1fr_22rem]">
        {/* Left: metadata */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-sm">Weigh-in card</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-xs">
              <MetaRow label="ctfd_url (sha256)">
                <RedactedValue sha256={data.ctfd_url_sha256} label="url" />
              </MetaRow>
              <MetaRow label="out_dir">
                <span className="truncate font-mono text-[0.65rem] text-muted-foreground">
                  {data.out_dir}
                </span>
              </MetaRow>
              <MetaRow label="models">
                <div className="flex flex-wrap gap-1">
                  {data.models.map((m) => (
                    <Badge key={m} variant="outline" className="font-mono">
                      {m}
                    </Badge>
                  ))}
                </div>
              </MetaRow>
              <MetaRow label="started">
                <span
                  className="font-mono text-[0.65rem] text-muted-foreground"
                  title={formatTimestamp(data.started_at)}
                >
                  {formatRelative(data.started_at)}
                </span>
              </MetaRow>
              {data.finished_at ? (
                <MetaRow label="finished">
                  <span
                    className="font-mono text-[0.65rem] text-muted-foreground"
                    title={formatTimestamp(data.finished_at)}
                  >
                    {formatRelative(data.finished_at)}
                  </span>
                </MetaRow>
              ) : null}
              <MetaRow label="discovered">
                <span className="font-mono">{data.challenges_discovered}</span>
              </MetaRow>
              <MetaRow label="solved">
                <span className="font-mono text-emerald-400">
                  {data.challenges_solved}
                </span>
              </MetaRow>
              {data.error ? (
                <MetaRow label="error">
                  <span className="font-mono text-[0.65rem] text-red-400">
                    {data.error}
                  </span>
                </MetaRow>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-sm">The purse</CardTitle>
            </CardHeader>
            <CardContent>
              <SpendMeter
                spent_usd={data.total_usd_cost}
                budget_usd={budget}
                mode="full"
              />
            </CardContent>
          </Card>

          {data.flags_submitted.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle className="font-mono text-sm">Flags</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2 text-xs">
                  {data.flags_submitted.map((f, i) => (
                    <li
                      key={`${f.challenge_id}-${i}`}
                      className="flex items-center justify-between gap-2 rounded bg-muted/40 px-2 py-1"
                    >
                      <span className="font-mono">#{f.challenge_id}</span>
                      <RedactedValue sha256={f.flag_sha256} label="flag" />
                      <span
                        className={`font-mono text-[0.65rem] ${f.correct ? "text-emerald-400" : "text-red-400"}`}
                      >
                        {f.correct ? "accepted" : "rejected"}
                      </span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          ) : null}
        </div>

        {/* Center: challenges grid */}
        <div className="min-w-0">
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-sm">
                Challenges on the card
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ChallengesGrid sessionId={sessionId} />
            </CardContent>
          </Card>
        </div>

        {/* Right: hints */}
        <div className="flex flex-col gap-4">
          {running ? <HintInjector sessionId={sessionId} /> : null}
          <Card>
            <CardHeader>
              <CardTitle className="font-mono text-sm">Corner log</CardTitle>
            </CardHeader>
            <CardContent>
              <HintHistory sessionId={sessionId} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function MetaRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="font-mono text-[0.6rem] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <div className="flex-1 text-right">{children}</div>
    </div>
  );
}
