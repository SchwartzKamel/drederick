import { Pause, Radio } from "lucide-react";
import { cn } from "@/lib/utils";

export type AuditLiveToggleProps = {
  live: boolean;
  pendingCount: number;
  onToggle: (next: boolean) => void;
  onCatchUp: () => void;
};

/**
 * On/off switch for the live-tail poller. When paused, surfaces a
 * "N new entries" counter that commits the buffered rows on click.
 */
export function AuditLiveToggle({
  live,
  pendingCount,
  onToggle,
  onCatchUp,
}: AuditLiveToggleProps) {
  return (
    <div className="flex items-center gap-2">
      <button
        type="button"
        onClick={() => onToggle(!live)}
        aria-pressed={live}
        className={cn(
          "inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors",
          live
            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
            : "border-border bg-background text-muted-foreground hover:bg-accent",
        )}
      >
        {live ? (
          <>
            <Radio className="h-3.5 w-3.5 animate-pulse" aria-hidden />
            <span>Live</span>
          </>
        ) : (
          <>
            <Pause className="h-3.5 w-3.5" aria-hidden />
            <span>Paused</span>
          </>
        )}
      </button>
      {!live && pendingCount > 0 ? (
        <button
          type="button"
          onClick={onCatchUp}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-2.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20"
        >
          {pendingCount} new {pendingCount === 1 ? "entry" : "entries"} — catch up
        </button>
      ) : null}
    </div>
  );
}
