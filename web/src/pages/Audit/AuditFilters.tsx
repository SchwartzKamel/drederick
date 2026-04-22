import { Search } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AuditCategoriesResponse } from "@/api/types";

export type SinceWindow = "5m" | "1h" | "24h" | "all";

export type AuditFiltersProps = {
  categories: AuditCategoriesResponse | undefined;
  selectedPrefixes: ReadonlySet<string>;
  onTogglePrefix: (prefix: string) => void;
  search: string;
  onSearchChange: (value: string) => void;
  since: SinceWindow;
  onSinceChange: (value: SinceWindow) => void;
  prefixCounts?: Readonly<Record<string, number>>;
};

const SINCE_OPTIONS: ReadonlyArray<{ value: SinceWindow; label: string }> = [
  { value: "5m", label: "last 5min" },
  { value: "1h", label: "last 1h" },
  { value: "24h", label: "last 24h" },
  { value: "all", label: "all" },
];

export function AuditFilters({
  categories,
  selectedPrefixes,
  onTogglePrefix,
  search,
  onSearchChange,
  since,
  onSinceChange,
  prefixCounts,
}: AuditFiltersProps) {
  const prefixes = categories?.prefixes ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
          categories
        </span>
        {prefixes.length === 0 ? (
          <span className="text-xs italic text-muted-foreground">
            no categories on the tape yet.
          </span>
        ) : null}
        {prefixes.map((p) => {
          const active = selectedPrefixes.has(p);
          const count = prefixCounts?.[p];
          return (
            <button
              key={p}
              type="button"
              onClick={() => onTogglePrefix(p)}
              aria-pressed={active}
              className={cn(
                "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 font-mono text-xs transition-colors",
                active
                  ? "border-primary bg-primary text-primary-foreground"
                  : "border-border bg-background text-muted-foreground hover:bg-accent",
              )}
            >
              <span>{p}</span>
              {typeof count === "number" ? (
                <span
                  className={cn(
                    "rounded px-1 text-[0.65rem]",
                    active ? "bg-primary-foreground/20" : "bg-muted",
                  )}
                >
                  {count}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <label className="relative flex items-center">
          <Search
            className="pointer-events-none absolute left-2 h-3.5 w-3.5 text-muted-foreground"
            aria-hidden
          />
          <input
            type="text"
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="filter rows (redacted text only)…"
            className="h-8 w-64 rounded-md border border-input bg-background pl-7 pr-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          />
        </label>

        <div className="flex items-center gap-1">
          <span className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
            since
          </span>
          <div className="flex items-center rounded-md border border-border bg-background p-0.5">
            {SINCE_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                type="button"
                onClick={() => onSinceChange(opt.value)}
                aria-pressed={since === opt.value}
                className={cn(
                  "rounded px-2 py-0.5 text-xs transition-colors",
                  since === opt.value
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
