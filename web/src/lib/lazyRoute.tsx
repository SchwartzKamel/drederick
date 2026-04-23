import React, { Suspense } from "react";
import { RouteFallback } from "@/components/RouteFallback";

/**
 * Wraps a lazy-loaded component in a Suspense boundary using the shared
 * `RouteFallback`. Use when registering TanStack Router routes whose
 * component is produced by `React.lazy(...)`.
 */
export function lazyRoute<P extends object>(Component: React.ComponentType<P>) {
  return function LazyRouted(props: P) {
    return (
      <Suspense fallback={<RouteFallback />}>
        <Component {...props} />
      </Suspense>
    );
  };
}
