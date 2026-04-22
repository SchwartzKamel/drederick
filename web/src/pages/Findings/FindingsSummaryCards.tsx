import { Activity, AlertTriangle, Flame, ServerCog, Target } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { cn } from "@/lib/utils";
import { formatCount } from "@/lib/formatters";
import { useFindingsSummary } from "@/api/hooks/useFindings";
import { isNoDatabase, type FindingsSummary, type Severity } from "@/api/types";

function Tile({
  icon: Icon,
  label,
  value,
  children,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  children?: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
          <CardTitle className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
            {label}
          </CardTitle>
        </div>
      </CardHeader>
      <CardContent>
        <div className="font-mono text-2xl font-bold">{value}</div>
        {children ? <div className="mt-2">{children}</div> : null}
      </CardContent>
    </Card>
  );
}

function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const critical = counts.critical ?? 0;
  const high = counts.high ?? 0;
  const medium = counts.medium ?? 0;
  const low = counts.low ?? 0;
  const total = critical + high + medium + low;
  if (total === 0) {
    return (
      <p className="text-xs text-muted-foreground">No severities matched.</p>
    );
  }
  const seg = (n: number, cls: string, label: string) =>
    n > 0 ? (
      <div
        key={label}
        className={cn("h-2", cls)}
        style={{ width: `${(n / total) * 100}%` }}
        title={`${label}: ${n}`}
      />
    ) : null;
  return (
    <div className="space-y-1">
      <div className="flex h-2 w-full overflow-hidden rounded bg-muted">
        {seg(critical, "bg-red-600", "critical")}
        {seg(high, "bg-orange-500", "high")}
        {seg(medium, "bg-yellow-400", "medium")}
        {seg(low, "bg-blue-500", "low")}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[0.65rem] text-muted-foreground">
        <span><span className="text-red-600">■</span> crit {critical}</span>
        <span><span className="text-orange-500">■</span> high {high}</span>
        <span><span className="text-yellow-500">■</span> med {medium}</span>
        <span><span className="text-blue-500">■</span> low {low}</span>
      </div>
    </div>
  );
}

function ExploitCategoryBreakdown({
  categories,
}: {
  categories: Record<string, number>;
}) {
  const entries = Object.entries(categories ?? {}).sort(
    (a, b) => b[1] - a[1],
  );
  if (entries.length === 0) {
    return <p className="text-xs text-muted-foreground">No rounds contested.</p>;
  }
  return (
    <div className="flex flex-wrap gap-1">
      {entries.slice(0, 5).map(([k, v]) => (
        <span
          key={k}
          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[0.65rem] text-muted-foreground"
        >
          {k}:{v}
        </span>
      ))}
    </div>
  );
}

export function FindingsSummaryCards() {
  const { data, isLoading, isError } = useFindingsSummary();

  if (isLoading) return <LoadingSkeleton rows={1} columns={5} cellClassName="h-28" />;
  if (isError || !data) {
    return <EmptyState kind="no_findings" />;
  }
  if (isNoDatabase(data)) {
    return <EmptyState kind="no_database" />;
  }

  const s: FindingsSummary = data;
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
      <Tile
        icon={Target}
        label="Opponents"
        value={formatCount(s.hosts)}
      />
      <Tile
        icon={ServerCog}
        label="Services fingerprinted"
        value={formatCount(s.services)}
      />
      <Tile icon={AlertTriangle} label="CVEs matched" value={formatCount(s.cves)}>
        <SeverityBar counts={s.cves_by_severity} />
      </Tile>
      <Tile
        icon={Flame}
        label="Exploit runs"
        value={formatCount(s.exploit_runs)}
      >
        <ExploitCategoryBreakdown categories={s.exploit_runs_by_category} />
      </Tile>
      <Tile
        icon={Activity}
        label="Sessions"
        value={`${formatCount(s.sessions_open)} / ${formatCount(s.sessions_closed)}`}
      >
        <p className="font-mono text-[0.65rem] text-muted-foreground">
          open / closed
        </p>
      </Tile>
    </div>
  );
}
