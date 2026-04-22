import { type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  FileText,
  Flame,
  Flag,
  HeartPulse,
  Notebook,
  ScrollText,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { HealthIndicator } from "@/components/HealthIndicator";
import { ConnectionDot } from "@/components/ConnectionDot";

const BACKEND_BIND = "127.0.0.1:7070";

const NAV_ITEMS: ReadonlyArray<{ to: string; label: string; icon: typeof Activity }> = [
  { to: "/runs", label: "Runs", icon: Activity },
  { to: "/findings", label: "Findings", icon: AlertTriangle },
  { to: "/jeopardy", label: "Jeopardy", icon: Flag },
  { to: "/offensive", label: "Offensive", icon: Flame },
  { to: "/audit", label: "Audit", icon: ScrollText },
  { to: "/scope", label: "Scope", icon: Target },
  { to: "/doctor", label: "Doctor", icon: HeartPulse },
  { to: "/notes", label: "Notes", icon: Notebook },
];

export function App({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-background text-foreground">
      <TopBar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 overflow-x-hidden">
          <div className="mx-auto max-w-7xl px-6 py-6">
            <SplashHeader />
            {children}
          </div>
        </main>
      </div>
      <Footer />
    </div>
  );
}

function TopBar() {
  return (
    <header className="sticky top-0 z-40 flex items-center justify-between border-b border-border bg-background/95 px-6 py-3 backdrop-blur">
      <div className="flex items-center gap-3">
        <Link to="/" className="flex items-baseline gap-2">
          <span className="font-mono text-xl font-bold tracking-tight text-primary">
            drederick
          </span>
          <span className="text-sm italic text-muted-foreground">
            Kommissar Krupke, schwing!
          </span>
        </Link>
      </div>
      <div className="flex items-center gap-4">
        <Badge variant="outline" className="font-mono text-xs">
          bind {BACKEND_BIND}
        </Badge>
        <ConnectionDot />
      </div>
    </header>
  );
}

function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-border bg-card/40 md:block">
      <nav className="flex flex-col gap-1 p-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <Link
            key={to}
            to={to}
            className={cn(
              "flex items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors",
              "hover:bg-accent hover:text-accent-foreground",
            )}
            activeProps={{ className: "bg-accent text-accent-foreground font-medium" }}
          >
            <Icon className="h-4 w-4" aria-hidden />
            {label}
          </Link>
        ))}
      </nav>
      <Separator />
      <div className="p-3 text-xs text-muted-foreground">
        <p className="font-mono">phase 1 // scaffold</p>
      </div>
    </aside>
  );
}

function SplashHeader() {
  return (
    <div className="mb-6 rounded-lg border border-border bg-card/60 p-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <FileText className="h-4 w-4" aria-hidden />
        <span className="italic">
          &ldquo;A fair fight is one you didn&rsquo;t prepare well enough for.&rdquo;
        </span>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="flex items-center justify-between border-t border-border bg-card/40 px-6 py-2 text-xs text-muted-foreground">
      <span className="font-mono">drederick // operator pane</span>
      <HealthIndicator />
    </footer>
  );
}
