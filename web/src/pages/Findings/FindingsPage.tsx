import { Link } from "@tanstack/react-router";
import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FindingsSummaryCards } from "./FindingsSummaryCards";
import { HostsList } from "./HostsList";
import { CvesList } from "./CvesList";

export function FindingsPage() {
  return (
    <div className="space-y-8">
      <div className="flex items-end justify-between gap-4">
        <div>
          <h1 className="font-mono text-2xl font-bold tracking-tight">
            Pre-Fight Analysis
          </h1>
          <p className="text-sm text-muted-foreground">
            The scorecard. Opponents, services, CVEs, rounds contested.
          </p>
        </div>
      </div>

      <FindingsSummaryCards />

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-sm uppercase tracking-wider text-muted-foreground">
            Recent opponents
          </h2>
          <Button asChild size="sm" variant="outline">
            <Link to="/findings/hosts">
              See all opponents <ArrowRight className="h-3 w-3" />
            </Link>
          </Button>
        </div>
        <HostsList limit={10} hideSearch hidePager />
      </section>

      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-mono text-sm uppercase tracking-wider text-muted-foreground">
            Top critical CVEs
          </h2>
          <Button asChild size="sm" variant="outline">
            <Link to="/findings/cves">
              Drill in <ArrowRight className="h-3 w-3" />
            </Link>
          </Button>
        </div>
        <CvesList severity="critical" limit={10} hidePager hideSeverityChips />
      </section>
    </div>
  );
}
