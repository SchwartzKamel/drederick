import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  RouterProvider,
  createRouter,
  createRootRoute,
  createRoute,
  Outlet,
} from "@tanstack/react-router";
import { App } from "@/App";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Toaster } from "@/components/Toast";
import { RouteFallback } from "@/components/RouteFallback";
import { lazyRoute } from "@/lib/lazyRoute";
import { DashboardPage } from "@/pages/DashboardPage";
import { ScopePage } from "@/pages/ScopePage";
import { DoctorPage } from "@/pages/DoctorPage";
import { JEOPARDY_ROUTE_PATHS } from "@/App";
import { useParams } from "@tanstack/react-router";
import "@/styles/globals.css";

// Lazy-loaded heavy routes — code-split to keep the initial bundle small.
// Each page uses a named export, so adapt it to React.lazy's default-export
// contract inline.
const RunsPage = lazy(() =>
  import("@/pages/Runs/RunsPage").then((m) => ({ default: m.RunsPage })),
);
const RunDetail = lazy(() =>
  import("@/pages/Runs/RunDetail").then((m) => ({ default: m.RunDetail })),
);
const FindingsPage = lazy(() =>
  import("@/pages/Findings/FindingsPage").then((m) => ({ default: m.FindingsPage })),
);
const FindingsHostsList = lazy(() =>
  import("@/pages/Findings/HostsList").then((m) => ({ default: m.HostsList })),
);
const FindingsHostDetail = lazy(() =>
  import("@/pages/Findings/HostDetail").then((m) => ({ default: m.HostDetail })),
);
const FindingsServicesList = lazy(() =>
  import("@/pages/Findings/ServicesList").then((m) => ({ default: m.ServicesList })),
);
const FindingsServiceDetail = lazy(() =>
  import("@/pages/Findings/ServiceDetail").then((m) => ({ default: m.ServiceDetail })),
);
const FindingsCvesList = lazy(() =>
  import("@/pages/Findings/CvesList").then((m) => ({ default: m.CvesList })),
);
const FindingsCveDetail = lazy(() =>
  import("@/pages/Findings/CveDetail").then((m) => ({ default: m.CveDetail })),
);
const FindingsPocRefsList = lazy(() =>
  import("@/pages/Findings/PocRefsList").then((m) => ({ default: m.PocRefsList })),
);
const JeopardyPage = lazy(() =>
  import("@/pages/Jeopardy/JeopardyPage").then((m) => ({ default: m.JeopardyPage })),
);
const JeopardySessionDetail = lazy(() =>
  import("@/pages/Jeopardy/SessionDetail").then((m) => ({ default: m.SessionDetail })),
);
const JeopardySwarmPanel = lazy(() =>
  import("@/pages/Jeopardy/SwarmPanel").then((m) => ({ default: m.SwarmPanel })),
);
const OffensivePage = lazy(() =>
  import("@/pages/Offensive/OffensivePage").then((m) => ({ default: m.OffensivePage })),
);
const AuditPage = lazy(() =>
  import("@/pages/Audit/AuditPage").then((m) => ({ default: m.AuditPage })),
);
const NotesPage = lazy(() =>
  import("@/pages/Notes/NotesPage").then((m) => ({ default: m.NotesPage })),
);

const rootRoute = createRootRoute({
  component: () => (
    <App>
      <Outlet />
    </App>
  ),
});

const routes = [
  createRoute({ getParentRoute: () => rootRoute, path: "/", component: DashboardPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/runs", component: lazyRoute(RunsPage) }),
  // --- runs-offensive-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/runs/$run_id", component: lazyRoute(RunDetail) }),
  // --- end runs-offensive-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: lazyRoute(FindingsPage) }),
  // --- findings-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/hosts", component: lazyRoute(FindingsHostsList) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/hosts/$host_id", component: lazyRoute(FindingsHostDetail) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/services", component: lazyRoute(FindingsServicesList) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/services/$service_id", component: lazyRoute(FindingsServiceDetail) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/cves", component: lazyRoute(FindingsCvesList) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/cves/$cve_id", component: lazyRoute(FindingsCveDetail) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/poc-refs", component: lazyRoute(FindingsPocRefsList) }),
  // --- /findings-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: JEOPARDY_ROUTE_PATHS.landing, component: lazyRoute(JeopardyPage) }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: JEOPARDY_ROUTE_PATHS.sessionDetail,
    component: lazyRoute(JeopardySessionDetail),
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: JEOPARDY_ROUTE_PATHS.sessionSwarm,
    component: function JeopardySwarmRoute() {
      const { session_id } = useParams({ from: JEOPARDY_ROUTE_PATHS.sessionSwarm });
      return (
        <Suspense fallback={<RouteFallback />}>
          <JeopardySwarmPanel sessionId={session_id} full />
        </Suspense>
      );
    },
  }),
  createRoute({ getParentRoute: () => rootRoute, path: "/offensive", component: lazyRoute(OffensivePage) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/audit", component: lazyRoute(AuditPage) }),
  createRoute({ getParentRoute: () => rootRoute, path: "/scope", component: ScopePage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/doctor", component: DoctorPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/notes", component: lazyRoute(NotesPage) }),
];

const routeTree = rootRoute.addChildren(routes);
const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, retry: 1 } },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
        <Toaster />
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
