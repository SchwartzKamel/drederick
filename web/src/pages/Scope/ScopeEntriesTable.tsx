import type { ScopeEntry } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/EmptyState";

export interface ScopeEntriesTableProps {
  entries: readonly ScopeEntry[];
  path: string | null;
}

/**
 * READ-ONLY render of the sanctioned allow-list. Renders entries as a table.
 * No edit controls — scope-file-read-only invariant.
 */
export function ScopeEntriesTable({ entries, path }: ScopeEntriesTableProps) {
  if (entries.length === 0) {
    return <EmptyState kind="no_scope" />;
  }
  return (
    <div className="overflow-hidden rounded-lg border border-border">
      <table className="w-full text-sm">
        <caption className="sr-only">
          Sanctioned scope entries{path ? ` from ${path}` : ""}
        </caption>
        <thead className="bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
          <tr>
            <th scope="col" className="px-4 py-2 font-medium">
              CIDR / IP
            </th>
            <th scope="col" className="px-4 py-2 font-medium">
              Family
            </th>
            <th scope="col" className="px-4 py-2 font-medium">
              Prefix
            </th>
            <th scope="col" className="px-4 py-2 font-medium">
              Allow broad
            </th>
            <th scope="col" className="px-4 py-2 font-medium">
              Lab mode
            </th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr
              key={`${e.cidr_or_ip}-${i}`}
              className="border-t border-border odd:bg-background even:bg-card/30"
            >
              <td className="px-4 py-2 font-mono text-foreground">
                {e.cidr_or_ip}
              </td>
              <td className="px-4 py-2">
                <Badge variant="outline" className="font-mono text-[10px]">
                  {e.family}
                </Badge>
              </td>
              <td className="px-4 py-2 font-mono text-muted-foreground">
                /{e.prefix_length}
              </td>
              <td className="px-4 py-2 text-muted-foreground">—</td>
              <td className="px-4 py-2 text-muted-foreground">—</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
