import { Link, useParams } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useCancelRun, useRun } from "@/api/hooks/useRuns";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { formatRelative, formatTimestamp } from "@/lib/formatters";
import { toast } from "@/lib/toast";
import { RunEventsStream } from "./RunEventsStream";
import { StatusBadge } from "./RunsTable";

export function RunDetail() {
  const { run_id } = useParams({ strict: false }) as { run_id: string };
  const { data: run, isLoading, isError } = useRun(run_id);
  const cancel = useCancelRun();

  const onCancel = async () => {
    try {
      await cancel.mutateAsync(run_id);
      toast.success("Bout called.", { description: `run ${run_id}` });
    } catch {
      toast.fromTatum("server");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Button asChild variant="ghost" size="sm">
          <Link to="/runs">
            <ArrowLeft className="mr-1 h-4 w-4" aria-hidden />
            Back to the card
          </Link>
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <CardTitle className="font-mono text-lg">
                run · {run_id}
              </CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                Under review by the sanctioning body.
              </p>
            </div>
            {run &&
            (run.status === "running" || run.status === "pending") ? (
              <Button
                variant="destructive"
                size="sm"
                disabled={cancel.isPending}
                onClick={onCancel}
              >
                Cancel run
              </Button>
            ) : null}
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <LoadingSkeleton rows={3} columns={3} />
          ) : isError || !run ? (
            <EmptyState
              kind="no_runs"
              title="No such contender on the card."
              body="This run_id is not recognized by the registry."
            />
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 text-sm md:grid-cols-4">
              <Meta label="status">
                <StatusBadge status={run.status} />
              </Meta>
              <Meta label="started">
                <span title={run.started_at}>
                  {formatRelative(run.started_at)}
                </span>
                <span className="block font-mono text-[10px] text-muted-foreground">
                  {formatTimestamp(run.started_at)}
                </span>
              </Meta>
              <Meta label="finished">
                {run.finished_at ? (
                  <>
                    <span title={run.finished_at}>
                      {formatRelative(run.finished_at)}
                    </span>
                    <span className="block font-mono text-[10px] text-muted-foreground">
                      {formatTimestamp(run.finished_at)}
                    </span>
                  </>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </Meta>
              <Meta label="targets">
                <span className="font-mono">{run.target_count}</span>
              </Meta>
              <Meta label="findings">
                <span className="font-mono">{run.finding_count}</span>
              </Meta>
              {run.error ? (
                <div className="col-span-full">
                  <span className="text-xs font-semibold uppercase tracking-wider text-destructive">
                    error
                  </span>
                  <p className="mt-1 rounded bg-destructive/10 p-2 font-mono text-xs text-destructive">
                    {run.error}
                  </p>
                </div>
              ) : null}
            </dl>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-sm">Round-by-round</CardTitle>
        </CardHeader>
        <CardContent>
          <RunEventsStream runId={run_id} />
        </CardContent>
      </Card>
    </div>
  );
}

function Meta({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </dt>
      <dd className="mt-1">{children}</dd>
    </div>
  );
}
