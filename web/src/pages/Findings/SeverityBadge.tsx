import { cn } from "@/lib/utils";
import type { Severity } from "@/api/types";

export type SeverityBadgeProps = {
  severity: Severity | null | undefined;
  className?: string;
};

const CLASSES: Record<Severity, string> = {
  critical: "bg-red-600 text-white border-red-700",
  high: "bg-orange-500 text-white border-orange-600",
  medium: "bg-yellow-400 text-black border-yellow-500",
  low: "bg-blue-500 text-white border-blue-600",
  unknown: "bg-muted text-muted-foreground border-border",
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  if (severity === null || severity === undefined) {
    return <span className="text-muted-foreground">—</span>;
  }
  const cls = CLASSES[severity] ?? CLASSES.unknown;
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[0.65rem] font-semibold uppercase tracking-wider",
        cls,
        className,
      )}
    >
      {severity}
    </span>
  );
}
