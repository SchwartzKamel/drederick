import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { DoctorCheck } from "@/api/types";
import { cn } from "@/lib/utils";
import { CheckCard } from "./CheckCard";

export interface CheckCategoryGroupProps {
  category: string;
  checks: readonly DoctorCheck[];
}

/**
 * Collapsible group of checks sharing a category. Default expanded so the
 * operator sees everything at once; collapse is for long lists.
 */
export function CheckCategoryGroup({ category, checks }: CheckCategoryGroupProps) {
  const [open, setOpen] = useState(true);

  return (
    <section className="rounded-lg border border-border bg-card/30">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 rounded-t-lg px-3 py-2 text-left hover:bg-accent/40"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" aria-hidden />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
        )}
        <span className="font-mono text-sm font-semibold uppercase tracking-wide text-foreground">
          {category}
        </span>
        <span className="ml-auto font-mono text-xs text-muted-foreground">
          {checks.length}
        </span>
      </button>
      <div className={cn("space-y-2 p-3", open ? "block" : "hidden")}>
        {checks.map((c) => (
          <CheckCard key={c.id} check={c} />
        ))}
      </div>
    </section>
  );
}
