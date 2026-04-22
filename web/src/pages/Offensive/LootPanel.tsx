import { useState } from "react";
import { useLoot } from "@/api/hooks/useFindings";
import { isNoDatabase, type LootRow } from "@/api/types";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { RedactedValue } from "@/components/RedactedValue";
import { formatRelative } from "@/lib/formatters";

const KINDS = ["", "credential", "hash", "ticket", "token", "file"] as const;

export function LootPanel() {
  const [target, setTarget] = useState("");
  const [kind, setKind] = useState<string>("");
  const query = useLoot({
    target: target.trim() || undefined,
    kind: kind || undefined,
    limit: 100,
  });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-end gap-3">
        <Field label="target">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="10.0.0.42"
            className={inputCls}
          />
        </Field>
        <Field label="kind">
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            className={inputCls}
          >
            {KINDS.map((k) => (
              <option key={k || "any"} value={k}>
                {k || "any"}
              </option>
            ))}
          </select>
        </Field>
      </div>

      {query.isLoading ? (
        <LoadingSkeleton rows={5} columns={4} />
      ) : query.isError || !query.data ? (
        <EmptyState
          kind="no_loot"
          title="The referee has called a timeout."
          body="Could not load the purse."
        />
      ) : isNoDatabase(query.data) ? (
        <EmptyState kind="no_database" />
      ) : query.data.items.length === 0 ? (
        <EmptyState kind="no_loot" />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-left text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3 py-2">target</th>
                <th className="px-3 py-2">kind</th>
                <th className="px-3 py-2">value</th>
                <th className="px-3 py-2">source</th>
                <th className="px-3 py-2">captured</th>
              </tr>
            </thead>
            <tbody>
              {query.data.items.map((r) => (
                <LootRowView key={r.id} row={r} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function LootRowView({ row }: { row: LootRow }) {
  return (
    <tr className="border-t border-border/60 hover:bg-accent/30">
      <td className="px-3 py-2 font-mono text-xs">{row.target}</td>
      <td className="px-3 py-2">
        <span className="inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[11px] text-amber-300">
          {row.kind}
        </span>
      </td>
      <td className="px-3 py-2">
        <RedactedValue sha256={row.value_sha256} label="value" />
      </td>
      <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
        {row.source_tool ?? "—"}
      </td>
      <td className="px-3 py-2 text-xs" title={row.captured_at}>
        {formatRelative(row.captured_at)}
      </td>
    </tr>
  );
}

const inputCls =
  "h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}
