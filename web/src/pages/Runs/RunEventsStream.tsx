import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { useRunEvents } from "@/api/hooks/useRuns";
import { useSignalREvents } from "@/api/signalr";
import type { ScanEventDto, ScanEventPayload } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { formatTimestamp } from "@/lib/formatters";
import { cn } from "@/lib/utils";

const MAX_DISPLAY = 200;
const DISCONNECT_GRACE_MS = 5_000;
const POLL_INTERVAL_MS = 2_000;

type NormalizedEvent = {
  kind: string;
  timestamp: string;
  target: string | null;
  tool: string | null;
  message: string | null;
  source: "live" | "poll";
};

function fromPayload(p: ScanEventPayload): NormalizedEvent {
  return {
    kind: p.Kind,
    timestamp: p.Timestamp,
    target: p.Target,
    tool: p.Tool,
    message: p.Message,
    source: "live",
  };
}

function fromDto(d: ScanEventDto): NormalizedEvent {
  return {
    kind: d.kind,
    timestamp: d.timestamp,
    target: d.target,
    tool: d.tool,
    message: d.message,
    source: "poll",
  };
}

export type RunEventsStreamProps = {
  runId: string;
  /** Optional list of targets belonging to this run — used to filter
   *  the shared recon SignalR group down to this run's events. */
  targets?: ReadonlyArray<string>;
};

export function RunEventsStream({ runId, targets }: RunEventsStreamProps) {
  const { events: liveEvents, state } = useSignalREvents("recon");
  const [fallbackOn, setFallbackOn] = useState(false);
  const [pollSince, setPollSince] = useState<string | null>(null);
  const disconnectedSinceRef = useRef<number | null>(null);

  useEffect(() => {
    if (state === "connected") {
      disconnectedSinceRef.current = null;
      setFallbackOn(false);
      return;
    }
    if (disconnectedSinceRef.current === null) {
      disconnectedSinceRef.current = Date.now();
    }
    const t = window.setTimeout(() => {
      if (
        disconnectedSinceRef.current !== null &&
        Date.now() - disconnectedSinceRef.current >= DISCONNECT_GRACE_MS
      ) {
        setFallbackOn(true);
      }
    }, DISCONNECT_GRACE_MS + 50);
    return () => window.clearTimeout(t);
  }, [state]);

  const pollQuery = useRunEvents(fallbackOn ? runId : null, {
    since: pollSince ?? undefined,
  });

  useEffect(() => {
    if (!fallbackOn) return;
    const id = window.setInterval(() => {
      pollQuery.refetch();
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [fallbackOn, pollQuery]);

  useEffect(() => {
    const batch = pollQuery.data;
    if (!batch || batch.events.length === 0) return;
    const last = batch.events[batch.events.length - 1];
    if (last?.timestamp) setPollSince(last.timestamp);
  }, [pollQuery.data]);

  const targetSet = useMemo(
    () => (targets && targets.length > 0 ? new Set(targets) : null),
    [targets],
  );

  const merged = useMemo<NormalizedEvent[]>(() => {
    const out: NormalizedEvent[] = [];
    for (const e of liveEvents) {
      if (targetSet && e.Target && !targetSet.has(e.Target)) continue;
      out.push(fromPayload(e));
    }
    if (fallbackOn && pollQuery.data) {
      for (const e of pollQuery.data.events) {
        if (targetSet && e.target && !targetSet.has(e.target)) continue;
        out.push(fromDto(e));
      }
    }
    out.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
    return out.slice(0, MAX_DISPLAY);
  }, [liveEvents, pollQuery.data, fallbackOn, targetSet]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = 0;
  }, [merged, autoScroll]);

  const onScroll = (e: React.UIEvent<HTMLDivElement>) => {
    const el = e.currentTarget;
    setAutoScroll(el.scrollTop < 8);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <h4 className="font-mono text-sm font-semibold">Live events</h4>
        <StreamStatus
          state={state}
          fallbackOn={fallbackOn}
          autoScroll={autoScroll}
        />
      </div>
      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="max-h-[480px] overflow-auto rounded-md border border-border bg-background/60 font-mono text-xs"
      >
        {merged.length === 0 ? (
          <div className="p-4">
            <EmptyState kind="no_events" />
          </div>
        ) : (
          <ul className="divide-y divide-border/60">
            {merged.map((e, i) => (
              <li
                key={`${e.timestamp}-${i}`}
                className="flex items-start gap-3 px-3 py-1.5"
              >
                <span className="shrink-0 text-muted-foreground">
                  {formatTimestamp(e.timestamp, {
                    year: undefined,
                    month: undefined,
                    day: undefined,
                    fractionalSecondDigits: 3,
                  })}
                </span>
                <span
                  className={cn(
                    "shrink-0 rounded px-1.5 text-[10px] uppercase tracking-wider",
                    kindClass(e.kind),
                  )}
                >
                  {e.kind}
                </span>
                {e.tool ? (
                  <span className="shrink-0 text-sky-400">{e.tool}</span>
                ) : null}
                {e.target ? (
                  <span className="shrink-0 text-emerald-400">{e.target}</span>
                ) : null}
                <span className="truncate text-foreground/90">
                  {e.message ?? ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function StreamStatus({
  state,
  fallbackOn,
  autoScroll,
}: {
  state: string;
  fallbackOn: boolean;
  autoScroll: boolean;
}) {
  if (fallbackOn) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-amber-400">
        <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
        The corner has lost communication. Polling every 2s.
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
      <span
        className={cn(
          "h-2 w-2 rounded-full",
          state === "connected"
            ? "bg-emerald-500"
            : state === "connecting"
              ? "bg-amber-500 animate-pulse"
              : "bg-zinc-500",
        )}
        aria-hidden
      />
      <span className="font-mono">{state}</span>
      {!autoScroll ? <span>· paused</span> : null}
    </span>
  );
}

function kindClass(kind: string): string {
  if (kind.includes("error") || kind.includes("fail")) {
    return "bg-rose-500/15 text-rose-400";
  }
  if (kind.includes("finish") || kind.includes("complete")) {
    return "bg-emerald-500/15 text-emerald-400";
  }
  if (kind.includes("start")) {
    return "bg-sky-500/15 text-sky-400";
  }
  return "bg-muted text-muted-foreground";
}
