import type { DoctorCheck, DoctorStatus } from "@/api/types";
import { AlertTriangle, CircleHelp, CircleSlash, ShieldCheck, XOctagon } from "lucide-react";
import { cn } from "@/lib/utils";

export interface CheckCardProps {
  check: DoctorCheck;
}

const STATUS_META: Record<
  DoctorStatus,
  {
    label: string;
    icon: typeof ShieldCheck;
    /** Tailwind classes for the icon + accent. */
    accent: string;
    border: string;
  }
> = {
  ok: {
    label: "Ready",
    icon: ShieldCheck,
    accent: "text-emerald-400",
    border: "border-emerald-500/30",
  },
  warn: {
    label: "Warn",
    icon: AlertTriangle,
    accent: "text-amber-400",
    border: "border-amber-500/30",
  },
  fail: {
    label: "Fail",
    icon: XOctagon,
    accent: "text-destructive",
    border: "border-destructive/40",
  },
  missing: {
    label: "Missing",
    icon: CircleSlash,
    accent: "text-muted-foreground",
    border: "border-muted-foreground/30",
  },
};

/**
 * Single doctor check. No install button — the doctor-workstation-only
 * invariant keeps install on the TTY. Operators are pointed to the CLI.
 */
export function CheckCard({ check }: CheckCardProps) {
  const meta = STATUS_META[check.status] ?? {
    label: check.status,
    icon: CircleHelp,
    accent: "text-muted-foreground",
    border: "border-border",
  };
  const Icon = meta.icon;

  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-lg border bg-card/40 p-3",
        meta.border,
      )}
    >
      <Icon
        className={cn("mt-0.5 h-5 w-5 shrink-0", meta.accent)}
        aria-label={meta.label}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-sm font-semibold text-foreground">
            {check.name}
          </span>
          <span className="truncate font-mono text-[11px] text-muted-foreground">
            {check.id}
          </span>
        </div>
        {check.detail ? (
          <p className="mt-0.5 text-sm text-muted-foreground">{check.detail}</p>
        ) : null}
      </div>
      {check.recommendation ? (
        <div className="hidden w-64 shrink-0 text-right text-[11px] text-muted-foreground md:block">
          <div className="font-mono uppercase tracking-wide opacity-70">
            Recommendation
          </div>
          <div className="font-mono">{check.recommendation}</div>
        </div>
      ) : null}
    </div>
  );
}
