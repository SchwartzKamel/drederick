import { cn } from "@/lib/utils";
import { formatUsd } from "@/lib/formatters";

export type SpendMeterProps = {
  spent_usd: number;
  budget_usd: number;
  mode?: "tiny" | "full";
  className?: string;
  /** Optional per-model breakdown for `full` mode. */
  breakdown?: ReadonlyArray<{ model: string; spent_usd: number }>;
};

function barColor(ratio: number, over: boolean): string {
  if (over) return "bg-red-500";
  if (ratio >= 0.8) return "bg-red-500";
  if (ratio >= 0.5) return "bg-yellow-500";
  return "bg-emerald-500";
}

function textColor(ratio: number, over: boolean): string {
  if (over) return "text-red-500";
  if (ratio >= 0.8) return "text-red-500";
  if (ratio >= 0.5) return "text-yellow-500";
  return "text-emerald-500";
}

/**
 * Reusable spend gauge. Rule-worship: the budget is the governing body;
 * we announce when we have gone over the purse.
 */
export function SpendMeter({
  spent_usd,
  budget_usd,
  mode = "tiny",
  className,
  breakdown,
}: SpendMeterProps) {
  const budget = budget_usd > 0 ? budget_usd : 0;
  const raw = budget > 0 ? spent_usd / budget : 0;
  const ratio = Math.min(1, Math.max(0, raw));
  const over = budget > 0 && spent_usd > budget;
  const pct = budget > 0 ? Math.round(raw * 100) : 0;

  if (mode === "tiny") {
    return (
      <div className={cn("flex flex-col gap-1", className)}>
        <div className="flex items-baseline justify-between gap-2 font-mono text-xs">
          <span className={cn("font-semibold", textColor(ratio, over))}>
            {formatUsd(spent_usd)}
          </span>
          <span className="text-muted-foreground">
            / {formatUsd(budget_usd)}
          </span>
          {over ? (
            <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-red-500">
              over purse
            </span>
          ) : null}
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className={cn("h-full transition-all", barColor(ratio, over))}
            style={{ width: `${Math.max(2, ratio * 100)}%` }}
          />
        </div>
      </div>
    );
  }

  // Full mode: circular SVG + breakdown.
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  const dash = circumference * ratio;

  return (
    <div className={cn("flex flex-col items-center gap-3", className)}>
      <div className="relative h-28 w-28">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            strokeWidth="8"
            className="stroke-muted"
          />
          <circle
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${dash} ${circumference}`}
            className={cn("transition-all", {
              "stroke-emerald-500": !over && ratio < 0.5,
              "stroke-yellow-500": !over && ratio >= 0.5 && ratio < 0.8,
              "stroke-red-500": over || ratio >= 0.8,
            })}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={cn(
              "font-mono text-lg font-bold",
              textColor(ratio, over),
            )}
          >
            {pct}%
          </span>
          {over ? (
            <span className="text-[0.6rem] font-bold uppercase tracking-wider text-red-500">
              over purse
            </span>
          ) : null}
        </div>
      </div>
      <div className="text-center font-mono text-xs">
        <div className={cn("text-sm font-semibold", textColor(ratio, over))}>
          {formatUsd(spent_usd)}
        </div>
        <div className="text-muted-foreground">
          of {formatUsd(budget_usd)} purse
        </div>
      </div>
      {breakdown && breakdown.length > 0 ? (
        <ul className="w-full space-y-1 border-t border-border pt-2">
          {breakdown.map((b) => (
            <li
              key={b.model}
              className="flex items-center justify-between font-mono text-xs"
            >
              <span className="truncate text-muted-foreground">{b.model}</span>
              <span>{formatUsd(b.spent_usd)}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
