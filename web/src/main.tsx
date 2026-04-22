import React from "react";
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
import { DashboardPage } from "@/pages/DashboardPage";
import { RunsPage } from "@/pages/Runs/RunsPage";
import { RunDetail } from "@/pages/Runs/RunDetail";
import { FindingsPage } from "@/pages/Findings/FindingsPage";
import { HostsList as FindingsHostsList } from "@/pages/Findings/HostsList";
import { HostDetail as FindingsHostDetail } from "@/pages/Findings/HostDetail";
import { ServicesList as FindingsServicesList } from "@/pages/Findings/ServicesList";
import { ServiceDetail as FindingsServiceDetail } from "@/pages/Findings/ServiceDetail";
import { CvesList as FindingsCvesList } from "@/pages/Findings/CvesList";
import { CveDetail as FindingsCveDetail } from "@/pages/Findings/CveDetail";
import { PocRefsList as FindingsPocRefsList } from "@/pages/Findings/PocRefsList";
import { JeopardyPage } from "@/pages/Jeopardy/JeopardyPage";
import { SessionDetail as JeopardySessionDetail } from "@/pages/Jeopardy/SessionDetail";
import { SwarmPanel as JeopardySwarmPanel } from "@/pages/Jeopardy/SwarmPanel";
import { JEOPARDY_ROUTE_PATHS } from "@/App";
import { useParams } from "@tanstack/react-router";
import { OffensivePage } from "@/pages/Offensive/OffensivePage";
import { AuditPage } from "@/pages/Audit/AuditPage";
import { ScopePage } from "@/pages/ScopePage";
import { DoctorPage } from "@/pages/DoctorPage";
import { NotesPage } from "@/pages/Notes/NotesPage";
import "@/styles/globals.css";

const rootRoute = createRootRoute({
  component: () => (
    <App>
      <Outlet />
    </App>
  ),
});

const routes = [
  createRoute({ getParentRoute: () => rootRoute, path: "/", component: DashboardPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/runs", component: RunsPage }),
  // --- runs-offensive-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/runs/$run_id", component: RunDetail }),
  // --- end runs-offensive-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: FindingsPage }),
  // --- findings-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/hosts", component: FindingsHostsList }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/hosts/$host_id", component: FindingsHostDetail }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/services", component: FindingsServicesList }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/services/$service_id", component: FindingsServiceDetail }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/cves", component: FindingsCvesList }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/cves/$cve_id", component: FindingsCveDetail }),
  createRoute({ getParentRoute: () => rootRoute, path: "/findings/poc-refs", component: FindingsPocRefsList }),
  // --- /findings-routes ---
  createRoute({ getParentRoute: () => rootRoute, path: JEOPARDY_ROUTE_PATHS.landing, component: JeopardyPage }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: JEOPARDY_ROUTE_PATHS.sessionDetail,
    component: JeopardySessionDetail,
  }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: JEOPARDY_ROUTE_PATHS.sessionSwarm,
    component: function JeopardySwarmRoute() {
      const { session_id } = useParams({ from: JEOPARDY_ROUTE_PATHS.sessionSwarm });
      return <JeopardySwarmPanel sessionId={session_id} full />;
    },
  }),
  createRoute({ getParentRoute: () => rootRoute, path: "/offensive", component: OffensivePage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/audit", component: AuditPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/scope", component: ScopePage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/doctor", component: DoctorPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/notes", component: NotesPage }),
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
