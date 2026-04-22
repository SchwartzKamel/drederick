import { useMemo, useState } from "react";
import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft, ChevronLeft, ChevronRight } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { RedactedValue } from "@/components/RedactedValue";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatTimestamp, formatCount } from "@/lib/formatters";
import { cn } from "@/lib/utils";
import { useHost, useExploitRuns } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";
import { ServicesList } from "./ServicesList";
import { CvesList } from "./CvesList";

type Tab = "services" | "cves" | "exploits";

export function HostDetail() {
  const { host_id } = useParams({ strict: false }) as { host_id: string };
  const hostIdNum = Number.parseInt(host_id, 10);
  const { data, isLoading, isError } = useHost(
    Number.isFinite(hostIdNum) ? hostIdNum : undefined,
  );
  const [tab, setTab] = useState<Tab>("services");

  if (isLoading) {
    return <LoadingSkeleton rows={6} columns={2} cellClassName="h-10" />;
  }
  if (isError || !data) {
    return <EmptyState kind="no_hosts" />;
  }
  if (isNoDatabase(data)) {
    return <EmptyState kind="no_database" />;
  }

  const host = data;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button asChild variant="ghost" size="sm">
          <Link to="/findings/hosts">
            <ArrowLeft className="h-4 w-4" /> See all opponents
          </Link>
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-[20rem_1fr]">
        <Card>
          <CardHeader>
            <CardTitle className="font-mono text-lg">{host.address}</CardTitle>
            <p className="text-xs text-muted-foreground">
              The weigh-in card for this opponent.
            </p>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <MetaRow label="Hostname" value={host.hostname ?? "—"} />
            <MetaRow
              label="First seen"
              value={formatTimestamp(host.first_seen)}
            />
            <MetaRow
              label="Last seen"
              value={formatTimestamp(host.last_seen)}
            />
            <MetaRow label="Services" value={formatCount(host.services_count)} />
            <MetaRow label="CVEs" value={formatCount(host.cves_count)} />
            <MetaRow
              label="Findings"
              value={formatCount(host.findings_count)}
            />
          </CardContent>
        </Card>

        <div className="space-y-4">
          <div className="flex gap-2 border-b border-border">
            <TabBtn active={tab === "services"} onClick={() => setTab("services")}>
              Services
            </TabBtn>
            <TabBtn active={tab === "cves"} onClick={() => setTab("cves")}>
              CVEs
            </TabBtn>
            <TabBtn
              active={tab === "exploits"}
              onClick={() => setTab("exploits")}
            >
              Exploit runs
            </TabBtn>
          </div>
          {tab === "services" ? <ServicesList hostId={host.id} /> : null}
          {tab === "cves" ? <CvesList hostId={host.id} /> : null}
          {tab === "exploits" ? (
            <ExploitRunsInline target={host.address} />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      <span className="text-right text-sm">{value}</span>
    </div>
  );
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "-mb-px border-b-2 px-3 py-2 font-mono text-xs uppercase tracking-wider",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function ExploitRunsInline({ target }: { target: string }) {
  const pageSize = 25;
  const [offset, setOffset] = useState(0);
  const { data, isLoading, isError } = useExploitRuns({
    target,
    limit: pageSize,
    offset,
  });

  const body = useMemo(() => {
    if (isLoading) return <LoadingSkeleton rows={4} columns={5} />;
    if (isError || !data) return <EmptyState kind="no_exploit_runs" />;
    if (isNoDatabase(data)) return <EmptyState kind="no_database" />;
    if (data.items.length === 0) return <EmptyState kind="no_exploit_runs" />;
    return (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2">Tool</th>
              <th className="px-3 py-2">Category</th>
              <th className="px-3 py-2">Started</th>
              <th className="px-3 py-2 text-right">Exit</th>
              <th className="px-3 py-2">Argv digest</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((r) => (
              <tr key={r.id} className="border-b border-border/60">
                <td className="px-3 py-2 font-mono">{r.tool}</td>
                <td className="px-3 py-2 text-muted-foreground">
                  {r.category}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                  {formatTimestamp(r.started_at)}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {r.exit_code ?? "—"}
                </td>
                <td className="px-3 py-2">
                  {r.argv_digest ? (
                    <RedactedValue sha256={r.argv_digest} label="argv" />
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }, [data, isError, isLoading]);

  const total = data && !isNoDatabase(data) ? data.total : 0;
  const canPrev = offset > 0;
  const canNext = data && !isNoDatabase(data) && offset + pageSize < total;

  return (
    <Card className="overflow-hidden">
      <CardContent className="p-0">{body}</CardContent>
      {data && !isNoDatabase(data) && data.items.length > 0 ? (
        <div className="flex items-center justify-between border-t border-border p-3 font-mono text-xs text-muted-foreground">
          <span>
            {offset + 1}–{Math.min(offset + data.items.length, total)} of{" "}
            {formatCount(total)}
          </span>
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!canPrev}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              <ChevronLeft className="h-3 w-3" /> Prev
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!canNext}
              onClick={() => setOffset(offset + pageSize)}
            >
              Next <ChevronRight className="h-3 w-3" />
            </Button>
          </div>
        </div>
      ) : null}
    </Card>
  );
}
