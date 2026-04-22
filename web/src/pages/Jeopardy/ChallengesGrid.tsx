import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { useJeopardyChallenges } from "@/api/hooks/useJeopardy";
import { useSignalREvents } from "@/api/signalr";
import { ChallengeCard } from "./ChallengeCard";

export type ChallengesGridProps = {
  sessionId: string;
};

/**
 * Live challenge grid. Strategy:
 *   1. Baseline state via `useJeopardyChallenges` (already polls).
 *   2. SignalR `jeopardy` events act as a push notification — on any
 *      relevant event we invalidate the TanStack cache and let the
 *      query refetch the authoritative shape. No client-side merging;
 *      the server is the single source of truth (audit invariant).
 *   3. If SignalR is disconnected, the underlying query still polls at
 *      its existing `refetchInterval`, so coverage does not regress.
 */
export function ChallengesGrid({ sessionId }: ChallengesGridProps) {
  const qc = useQueryClient();
  const { data, isLoading, isError } = useJeopardyChallenges(sessionId);
  const { events, connected } = useSignalREvents("jeopardy");

  useEffect(() => {
    if (events.length === 0) return;
    const latest = events[events.length - 1];
    if (!latest) return;
    const kind = latest.Kind?.toLowerCase() ?? "";
    if (
      kind.startsWith("jeopardy.challenge") ||
      kind.startsWith("jeopardy.swarm") ||
      kind.startsWith("jeopardy.solve") ||
      kind.startsWith("jeopardy.flag")
    ) {
      qc.invalidateQueries({
        queryKey: ["jeopardy", "challenges", sessionId],
      });
      qc.invalidateQueries({ queryKey: ["jeopardy", "swarm", sessionId] });
      qc.invalidateQueries({ queryKey: ["jeopardy", "session", sessionId] });
    }
  }, [events, qc, sessionId]);

  if (isLoading) {
    return <LoadingSkeleton rows={4} columns={4} cellClassName="h-24" />;
  }
  if (isError || !data) {
    return <EmptyState kind="no_sessions" />;
  }
  if (data.length === 0) {
    return (
      <EmptyState
        kind="no_sessions"
        title="The card has no contenders yet."
        body="CTFd scrape is pending. Challenges will appear as the session spins up."
      />
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span className="font-mono">{data.length} challenges on the card</span>
        <span className="font-mono">
          live feed: {connected ? "on-air" : "off-air (polling)"}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6">
        {data.map((c) => (
          <ChallengeCard key={c.id} challenge={c} />
        ))}
      </div>
    </div>
  );
}
