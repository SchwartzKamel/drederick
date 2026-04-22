import { cn } from "@/lib/utils";

export type LoadingSkeletonProps = {
  rows?: number;
  columns?: number;
  className?: string;
  /** Per-cell height in tailwind units (default: `h-4`). */
  cellClassName?: string;
};

/**
 * Tailwind-based `animate-pulse` placeholder grid. For simple card
 * skeletons pass `columns={1}`; for tables pass the column count.
 */
export function LoadingSkeleton({
  rows = 3,
  columns = 1,
  className,
  cellClassName = "h-4",
}: LoadingSkeletonProps) {
  return (
    <div
      role="status"
      aria-busy="true"
      aria-label="Loading"
      className={cn("w-full animate-pulse space-y-2", className)}
    >
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          className={cn(
            "grid gap-2",
            columns === 1 ? "grid-cols-1" : undefined,
            columns === 2 ? "grid-cols-2" : undefined,
            columns === 3 ? "grid-cols-3" : undefined,
            columns === 4 ? "grid-cols-4" : undefined,
            columns >= 5 ? "grid-cols-5" : undefined,
          )}
        >
          {Array.from({ length: columns }).map((_, c) => (
            <div
              key={c}
              className={cn("rounded-md bg-muted", cellClassName)}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/** Single-line shimmer; use inline where a full grid is overkill. */
export function SkeletonLine({ className }: { className?: string }) {
  return <div className={cn("h-4 w-full animate-pulse rounded bg-muted", className)} />;
}
