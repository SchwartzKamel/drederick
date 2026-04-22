import { useState } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { RedactedValue } from "@/components/RedactedValue";
import { formatRelative, formatTimestamp } from "@/lib/formatters";
import type { JeopardyChallengeState } from "@/api/types";

/**
 * Category → tailwind chip colors. Raw category names only (pwn/rev/
 * crypto/forensics/web/stego/misc); no cute renames.
 */
const CATEGORY_STYLES: Record<string, string> = {
  pwn: "bg-red-500/15 text-red-400 border-red-500/30",
  rev: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  crypto: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  forensics: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  web: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  stego: "bg-pink-500/15 text-pink-400 border-pink-500/30",
  misc: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

function categoryClasses(cat: string): string {
  return CATEGORY_STYLES[cat.toLowerCase()] ?? CATEGORY_STYLES.misc!;
}

const STATE_STYLES: Record<string, string> = {
  pending: "bg-muted text-muted-foreground",
  racing: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/40",
  solved: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40",
  failed: "bg-red-500/20 text-red-400 border border-red-500/40",
  skipped: "bg-slate-500/20 text-slate-400 border border-slate-500/40",
};

function stateClasses(state: string): string {
  return STATE_STYLES[state.toLowerCase()] ?? STATE_STYLES.pending!;
}

export type ChallengeCardProps = {
  challenge: JeopardyChallengeState;
};

export function ChallengeCard({ challenge }: ChallengeCardProps) {
  const [open, setOpen] = useState(false);
  const racing = challenge.state.toLowerCase() === "racing";
  const solved = challenge.state.toLowerCase() === "solved";

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          "group flex h-full w-full flex-col gap-2 rounded-lg border border-border bg-card/60 p-3 text-left transition-colors",
          "hover:border-primary/60 hover:bg-card",
        )}
        aria-label={`Open challenge ${challenge.name}`}
      >
        <div className="flex items-center justify-between gap-2">
          <span
            className={cn(
              "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider",
              categoryClasses(challenge.category),
            )}
          >
            {challenge.category}
          </span>
          <span className="font-mono text-sm font-bold text-foreground">
            {challenge.value}
          </span>
        </div>
        <div className="flex-1 text-sm font-medium text-foreground line-clamp-2">
          {challenge.name}
        </div>
        <div className="flex items-center justify-between gap-2">
          <span
            className={cn(
              "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider",
              stateClasses(challenge.state),
            )}
          >
            {challenge.state}
          </span>
          {racing && challenge.active_solvers.length > 0 ? (
            <span className="font-mono text-[0.65rem] text-muted-foreground">
              {challenge.active_solvers.length} in ring
            </span>
          ) : null}
          {solved && challenge.solved_by_model ? (
            <span className="truncate font-mono text-[0.65rem] text-emerald-400">
              {challenge.solved_by_model}
            </span>
          ) : null}
        </div>
        {racing ? (
          <div className="flex flex-wrap gap-1">
            {challenge.active_solvers.slice(0, 4).map((s) => (
              <span
                key={s.model}
                className="inline-flex items-center gap-1 rounded bg-yellow-500/10 px-1 py-0.5 font-mono text-[0.6rem] text-yellow-300"
                title={`started ${formatRelative(s.started_at)}`}
              >
                <span className="truncate max-w-[6rem]">{s.model}</span>
                <span className="opacity-60">×{s.turns_taken}</span>
              </span>
            ))}
          </div>
        ) : null}
      </button>
      {open ? (
        <ChallengeModal
          challenge={challenge}
          onClose={() => setOpen(false)}
        />
      ) : null}
    </>
  );
}

function ChallengeModal({
  challenge,
  onClose,
}: {
  challenge: JeopardyChallengeState;
  onClose: () => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-lg rounded-xl border border-border bg-card p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider",
                  categoryClasses(challenge.category),
                )}
              >
                {challenge.category}
              </span>
              <Badge variant="outline" className="font-mono">
                {challenge.value} pts
              </Badge>
              <span
                className={cn(
                  "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider",
                  stateClasses(challenge.state),
                )}
              >
                {challenge.state}
              </span>
            </div>
            <h3 className="font-mono text-lg font-semibold">
              {challenge.name}
            </h3>
            <span className="font-mono text-xs text-muted-foreground">
              challenge #{challenge.id}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
            aria-label="Close"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <div className="space-y-3 text-sm">
          {challenge.active_solvers.length > 0 ? (
            <section>
              <h4 className="mb-1 font-mono text-xs uppercase tracking-wider text-muted-foreground">
                active solvers
              </h4>
              <ul className="space-y-1">
                {challenge.active_solvers.map((s) => (
                  <li
                    key={s.model}
                    className="flex items-center justify-between rounded bg-muted/40 px-2 py-1 font-mono text-xs"
                  >
                    <span>{s.model}</span>
                    <span className="text-muted-foreground">
                      turn {s.turns_taken} · {formatRelative(s.started_at)}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {challenge.flag_sha256 ? (
            <section>
              <h4 className="mb-1 font-mono text-xs uppercase tracking-wider text-muted-foreground">
                flag
              </h4>
              <div className="flex items-center gap-2">
                <RedactedValue sha256={challenge.flag_sha256} label="flag" />
                {challenge.solved_by_model ? (
                  <span className="font-mono text-xs text-emerald-400">
                    by {challenge.solved_by_model}
                  </span>
                ) : null}
                {challenge.solved_at ? (
                  <span className="font-mono text-xs text-muted-foreground">
                    {formatTimestamp(challenge.solved_at)}
                  </span>
                ) : null}
              </div>
            </section>
          ) : null}
        </div>
      </div>
    </div>
  );
}
