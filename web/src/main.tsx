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
import { RunsPage } from "@/pages/RunsPage";
import { FindingsPage } from "@/pages/FindingsPage";
import { JeopardyPage } from "@/pages/JeopardyPage";
import { OffensivePage } from "@/pages/OffensivePage";
import { AuditPage } from "@/pages/AuditPage";
import { ScopePage } from "@/pages/ScopePage";
import { DoctorPage } from "@/pages/DoctorPage";
import { NotesPage } from "@/pages/NotesPage";
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
  createRoute({ getParentRoute: () => rootRoute, path: "/findings", component: FindingsPage }),
  createRoute({ getParentRoute: () => rootRoute, path: "/jeopardy", component: JeopardyPage }),
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
