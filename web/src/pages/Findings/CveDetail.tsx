import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { EmptyState } from "@/components/EmptyState";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatTimestamp } from "@/lib/formatters";
import { useCve } from "@/api/hooks/useFindings";
import { isNoDatabase } from "@/api/types";
import { SeverityBadge } from "./SeverityBadge";
import { PocRefsList } from "./PocRefsList";

export function CveDetail() {
  const { cve_id } = useParams({ strict: false }) as { cve_id: string };
  const { data, isLoading, isError } = useCve(cve_id);

  if (isLoading) {
    return <LoadingSkeleton rows={6} columns={1} cellClassName="h-8" />;
  }
  if (isError || !data) return <EmptyState kind="no_cves" />;
  if (isNoDatabase(data)) return <EmptyState kind="no_database" />;

  const cve = data;

  return (
    <div className="space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/findings/cves">
          <ArrowLeft className="h-4 w-4" /> View weigh-in
        </Link>
      </Button>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="font-mono text-lg">{cve.cve_id}</CardTitle>
            <div className="flex items-center gap-3">
              <SeverityBadge severity={cve.severity} />
              <span className="font-mono text-sm text-muted-foreground">
                CVSS{" "}
                {cve.cvss !== null && cve.cvss !== undefined
                  ? cve.cvss.toFixed(1)
                  : "—"}
              </span>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Published {formatTimestamp(cve.published)}
          </p>
        </CardHeader>
        <CardContent>
          <p className="whitespace-pre-wrap text-sm leading-relaxed">
            {cve.summary ?? "No summary on file."}
          </p>
        </CardContent>
      </Card>

      <div className="space-y-2">
        <h3 className="font-mono text-sm uppercase tracking-wider text-muted-foreground">
          Proofs of concept
        </h3>
        <PocRefsList cveId={cve.cve_id} />
      </div>
    </div>
  );
}
