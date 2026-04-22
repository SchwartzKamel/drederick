import { useState } from "react";
import { Swords } from "lucide-react";
import { useRuns } from "@/api/hooks/useRuns";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { tatumisms } from "@/lib/tatumisms";
import { RunsStartForm } from "./RunsStartForm";
import { RunsTable } from "./RunsTable";

export function RunsPage() {
  const [formOpen, setFormOpen] = useState(false);
  const runs = useRuns();

  return (
    <ErrorBoundary>
      <div className="space-y-6">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h1 className="font-mono text-2xl font-bold tracking-tight">
              The Ring
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              {tatumisms.banner.tagline}
            </p>
          </div>
          <Button onClick={() => setFormOpen((v) => !v)}>
            <Swords className="mr-1 h-4 w-4" aria-hidden />
            {formOpen ? "Close weigh-in" : "Start a bout"}
          </Button>
        </header>

        {formOpen ? (
          <RunsStartForm
            onCancel={() => setFormOpen(false)}
            onSubmitted={() => setFormOpen(false)}
          />
        ) : null}

        <Card>
          <CardHeader>
            <h2 className="font-mono text-sm font-semibold">The card</h2>
          </CardHeader>
          <CardContent>
            <RunsTable runs={runs.data} isLoading={runs.isLoading} />
          </CardContent>
        </Card>
      </div>
    </ErrorBoundary>
  );
}
