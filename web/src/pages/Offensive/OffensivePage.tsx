import { useState } from "react";
import { Crosshair, KeyRound, Swords } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { cn } from "@/lib/utils";
import { ExploitRunsTable } from "./ExploitRunsTable";
import { SessionsPanel } from "./SessionsPanel";
import { LootPanel } from "./LootPanel";

type TabKey = "exploits" | "sessions" | "loot";

const TABS: ReadonlyArray<{ key: TabKey; label: string; icon: typeof Swords }> = [
  { key: "exploits", label: "Exploit Runs", icon: Swords },
  { key: "sessions", label: "Sessions", icon: Crosshair },
  { key: "loot", label: "Loot", icon: KeyRound },
];

export function OffensivePage() {
  const [tab, setTab] = useState<TabKey>("exploits");

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        <header>
          <h1 className="font-mono text-2xl font-bold tracking-tight">
            Exploitation
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Every blow thrown inside the ropes. Audited, digested, on file
            with the governing body.
          </p>
        </header>

        <div
          role="tablist"
          className="inline-flex overflow-hidden rounded-md border border-border"
        >
          {TABS.map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={cn(
                "inline-flex items-center gap-2 px-4 py-2 text-sm font-medium",
                tab === key
                  ? "bg-primary text-primary-foreground"
                  : "bg-background text-muted-foreground hover:bg-accent",
              )}
            >
              <Icon className="h-4 w-4" aria-hidden />
              {label}
            </button>
          ))}
        </div>

        <Card>
          <CardHeader>
            <h2 className="font-mono text-sm font-semibold">
              {TABS.find((t) => t.key === tab)?.label}
            </h2>
          </CardHeader>
          <CardContent>
            {tab === "exploits" ? <ExploitRunsTable /> : null}
            {tab === "sessions" ? <SessionsPanel /> : null}
            {tab === "loot" ? <LootPanel /> : null}
          </CardContent>
        </Card>
      </div>
    </ErrorBoundary>
  );
}
