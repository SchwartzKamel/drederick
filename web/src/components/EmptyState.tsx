import type { ReactNode } from "react";
import { tatumisms, type TatumEmptyKind } from "@/lib/tatumisms";
import { cn } from "@/lib/utils";

export type EmptyStateProps = {
  kind: TatumEmptyKind;
  /** Optional override — defaults to the Tatum microcopy for `kind`. */
  title?: string;
  body?: string;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
};

/**
 * Standard "no rows yet" placeholder. Reads voice from
 * `tatumisms.empty[kind]` so every page emits the same billing.
 */
export function EmptyState({
  kind,
  title,
  body,
  action,
  icon,
  className,
}: EmptyStateProps) {
  const copy = tatumisms.empty[kind];
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-card/40 p-8 text-center",
        className,
      )}
    >
      {icon ? <div className="mb-3 text-muted-foreground">{icon}</div> : null}
      <h3 className="font-mono text-sm font-semibold text-foreground">
        {title ?? copy.title}
      </h3>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">
        {body ?? copy.body}
      </p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
