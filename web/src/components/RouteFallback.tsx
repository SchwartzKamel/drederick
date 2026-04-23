import { LoadingSkeleton } from "@/components/LoadingSkeleton";

/**
 * Default Suspense fallback for code-split route chunks. "Between rounds..."
 * — keeps the shell visible while the chunk streams in.
 */
export function RouteFallback() {
  return (
    <div className="p-6" role="status" aria-live="polite" aria-busy="true">
      <LoadingSkeleton rows={6} columns={1} />
    </div>
  );
}
