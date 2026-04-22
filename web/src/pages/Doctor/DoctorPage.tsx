import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { RefreshCcw, Terminal } from "lucide-react";
import { useDoctorChecks } from "@/api/hooks/useDoctor";
import type { DoctorCheck, DoctorStatus } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";
import { cn } from "@/lib/utils";
import { CheckCategoryGroup } from "./CheckCategoryGroup";

type Filter = "all" | DoctorStatus;

const FILTER_LABELS: Record<Filter, string> = {
  all: "All",
  ok: "OK",
  warn: "Warn",
  fail: "Fail",
  missing: "Missing",
};

/**
 * Doctor page — detect-only workstation preflight dashboard.
 *
 * Invariant: @invariant-id:doctor-workstation-only. This page issues zero
 * install / mutate requests. There is no install button. Operators are
 * directed to the TTY (`drederick doctor --install`) for any action.
 */
export function DoctorPage() {
  const qc = useQueryClient();
  const checks = useDoctorChecks();
  const [filter, setFilter] = useState<Filter>("all");

  const payload = checks.data;
  const allChecks: readonly DoctorCheck[] = useMemo(
    () => payload?.Checks ?? [],
    [payload],
  );
  const summary = payload?.Summary ?? { Ok: 0, Warn: 0, Fail: 0, Missing: 0 };

  const filtered = useMemo(() => {
    if (filter === "all") return allChecks;
    return allChecks.filter((c) => c.status === filter);
  }, [allChecks, filter]);

  const grouped = useMemo(() => {
    const by = new Map<string, DoctorCheck[]>();
    for (const c of filtered) {
      const key = c.category ?? "uncategorized";
      const list = by.get(key) ?? [];
      list.push(c);
      by.set(key, list);
    }
    return Array.from(by.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [filtered]);

  function refresh() {
    qc.invalidateQueries({ queryKey: ["doctor", "checks"] });
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <CardTitle className="font-mono text-xl">
                Pre-Fight Physical
              </CardTitle>
              <CardDescription className="mt-1">
                Equipment check. The governing body insists.
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={checks.isFetching}
              aria-label="Refresh doctor checks"
            >
              <RefreshCcw
                className={cn(
                  "h-4 w-4",
                  checks.isFetching && "animate-spin",
                )}
                aria-hidden
              />
              <span className="ml-2">Refresh</span>
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <SummaryTile label="OK" value={summary.Ok} tone="ok" />
            <SummaryTile label="Warn" value={summary.Warn} tone="warn" />
            <SummaryTile label="Fail" value={summary.Fail} tone="fail" />
            <SummaryTile
              label="Missing"
              value={summary.Missing}
              tone="missing"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {(Object.keys(FILTER_LABELS) as Filter[]).map((f) => {
              const active = filter === f;
              return (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFilter(f)}
                  aria-pressed={active}
                  className={cn(
                    "rounded-full border px-3 py-1 text-xs font-mono uppercase tracking-wide transition-colors",
                    active
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                  )}
                >
                  {FILTER_LABELS[f]}
                </button>
              );
            })}
            <Badge variant="outline" className="ml-auto font-mono text-[10px]">
              {filtered.length} shown / {allChecks.length} total
            </Badge>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
            <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            <span>
              Missing tools? Run{" "}
              <code className="font-mono text-foreground">
                drederick doctor --install
              </code>{" "}
              from the terminal. The web surface is detect-only.
            </span>
          </div>

          {checks.isLoading ? (
            <p className="text-sm text-muted-foreground">
              Weigh-in in progress…
            </p>
          ) : checks.isError ? (
            <p className="text-sm text-destructive">
              The doctor did not pick up. Confirm the backend is reachable.
            </p>
          ) : allChecks.length === 0 ? (
            <EmptyState kind="no_doctor_checks" />
          ) : grouped.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No checks match this filter.
            </p>
          ) : (
            <div className="space-y-3">
              {grouped.map(([cat, items]) => (
                <CheckCategoryGroup
                  key={cat}
                  category={cat}
                  checks={items}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

interface SummaryTileProps {
  label: string;
  value: number;
  tone: DoctorStatus;
}

const TONE_CLASSES: Record<DoctorStatus, string> = {
  ok: "border-emerald-500/30 text-emerald-400",
  warn: "border-amber-500/30 text-amber-400",
  fail: "border-destructive/40 text-destructive",
  missing: "border-muted-foreground/30 text-muted-foreground",
};

function SummaryTile({ label, value, tone }: SummaryTileProps) {
  return (
    <div
      className={cn(
        "rounded-lg border bg-card/40 p-3 text-center",
        TONE_CLASSES[tone],
      )}
    >
      <div className="font-mono text-3xl font-bold tabular-nums">{value}</div>
      <div className="font-mono text-[11px] uppercase tracking-wide opacity-80">
        {label}
      </div>
    </div>
  );
}
