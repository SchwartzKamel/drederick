import { useState } from "react";
import { AlertTriangle, FileText, Lock } from "lucide-react";
import { useScope } from "@/api/hooks/useScope";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScopeEntriesTable } from "./ScopeEntriesTable";
import { ScopeValidator } from "./ScopeValidator";

/**
 * Scope page — READ-ONLY viewer and dry-run validator.
 *
 * Invariant: @invariant-id:scope-file-read-only. This page never issues a
 * POST/PUT/DELETE that would mutate the scope file. The only POST it
 * issues (to /api/scope/validate) is itself a read-only dry run on the
 * backend.
 */
export function ScopePage() {
  const [pathInput, setPathInput] = useState("scope.txt");
  const [loadedPath, setLoadedPath] = useState<string | null>(null);
  const scope = useScope(loadedPath);

  function load() {
    const trimmed = pathInput.trim();
    if (trimmed.length === 0) return;
    setLoadedPath(trimmed);
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2 font-mono text-xl">
                The Sanctioned Allow-List
                <Badge
                  variant="outline"
                  className="gap-1 font-mono text-[10px] uppercase"
                >
                  <Lock className="h-3 w-3" aria-hidden />
                  read-only
                </Badge>
              </CardTitle>
              <CardDescription className="mt-1 max-w-2xl">
                The governing body authored these rules. No in-browser edits.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="flex items-start gap-2 text-xs text-muted-foreground">
            <FileText className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
            <span>
              This view reads <code className="font-mono">scope.txt</code>.
              Edits are not possible via the web UI — open the file in your
              editor.
            </span>
          </p>

          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 min-w-[16rem]">
              <label
                htmlFor="scope-path"
                className="mb-1 block font-mono text-xs uppercase tracking-wide text-muted-foreground"
              >
                Scope file path
              </label>
              <input
                id="scope-path"
                type="text"
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                placeholder="scope.txt"
                className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                onKeyDown={(e) => {
                  if (e.key === "Enter") load();
                }}
              />
            </div>
            <Button onClick={load} disabled={pathInput.trim().length === 0}>
              Load
            </Button>
          </div>

          {scope.isError ? (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
              The corner could not read that file. Confirm the path is
              relative to the backend&rsquo;s working directory.
            </div>
          ) : null}

          {scope.data && scope.data.warnings.length > 0 ? (
            <div
              role="alert"
              className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-sm"
            >
              <div className="mb-1 flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-wide text-amber-400">
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                The judges have concerns
              </div>
              <ul className="list-inside list-disc space-y-1 text-amber-200/90">
                {scope.data.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {scope.isLoading && loadedPath ? (
            <p className="text-sm text-muted-foreground">
              Summoning the allow-list…
            </p>
          ) : null}

          {scope.data ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="font-mono">
                  {scope.data.entries.length} entr
                  {scope.data.entries.length === 1 ? "y" : "ies"} · mode{" "}
                  <span className="text-foreground">{scope.data.mode}</span>
                </span>
                <span className="truncate font-mono" title={scope.data.path}>
                  {scope.data.path}
                </span>
              </div>
              <ScopeEntriesTable
                entries={scope.data.entries}
                path={scope.data.path}
              />
            </div>
          ) : !loadedPath ? (
            <p className="text-sm text-muted-foreground">
              Load a scope file to review the sanctioned targets.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <ScopeValidator
        path={loadedPath ?? pathInput.trim()}
        disabled={!scope.data}
      />
    </div>
  );
}
