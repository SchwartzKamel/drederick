import { useState } from "react";
import { Check, ShieldAlert, X } from "lucide-react";
import { useValidateScope } from "@/api/hooks/useScope";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export interface ScopeValidatorProps {
  path: string;
  /** Disabled if the scope file has not been loaded yet. */
  disabled?: boolean;
}

/**
 * READ-ONLY validator. Delegates to POST /api/scope/validate, which itself
 * only reads the scope file and runs `Scope.Require` against each proposed
 * target. No mutation path exists.
 */
export function ScopeValidator({ path, disabled }: ScopeValidatorProps) {
  const [text, setText] = useState("");
  const validate = useValidateScope();

  function submit() {
    const targets = text
      .split(/\r?\n/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);
    if (targets.length === 0) return;
    validate.mutate({ path, proposed_targets: targets });
  }

  const result = validate.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-mono text-base">
          <ShieldAlert className="h-4 w-4" aria-hidden />
          Proposed targets — dry-run before the bell
        </CardTitle>
        <CardDescription>
          One target per line. The governing body will rule on each. Nothing
          is scanned. Nothing is written.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          disabled={disabled || validate.isPending}
          rows={6}
          placeholder="10.0.0.5&#10;10.0.1.0/24&#10;2001:db8::/48"
          className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50"
          aria-label="Proposed targets, one per line"
        />

        <div className="flex items-center gap-2">
          <Button
            onClick={submit}
            disabled={disabled || validate.isPending || text.trim().length === 0}
          >
            {validate.isPending ? "Consulting the judges…" : "Validate"}
          </Button>
          {validate.isError ? (
            <span className="text-xs text-destructive">
              The referee refused the request.
            </span>
          ) : null}
        </div>

        {result ? (
          <div className="grid gap-4 md:grid-cols-2">
            <section
              className="rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-4"
              aria-labelledby="scope-accepted-heading"
            >
              <h3
                id="scope-accepted-heading"
                className="mb-2 font-mono text-sm font-semibold text-emerald-400"
              >
                Sanctioned.
              </h3>
              {result.accepted.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No targets cleared the allow-list.
                </p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {result.accepted.map((t) => (
                    <li
                      key={t}
                      className="flex items-center gap-2 font-mono text-foreground"
                    >
                      <Check
                        className="h-3.5 w-3.5 text-emerald-400"
                        aria-hidden
                      />
                      <span>{t}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section
              className="rounded-lg border border-destructive/40 bg-destructive/5 p-4"
              aria-labelledby="scope-rejected-heading"
            >
              <h3
                id="scope-rejected-heading"
                className="mb-2 font-mono text-sm font-semibold text-destructive"
              >
                Wild. Not sanctioned.
              </h3>
              {result.rejected.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  Every proposed target cleared the allow-list.
                </p>
              ) : (
                <ul className="space-y-2 text-sm">
                  {result.rejected.map((r) => (
                    <li
                      key={`${r.target}-${r.reason}`}
                      className="flex items-start gap-2"
                    >
                      <X
                        className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive"
                        aria-hidden
                      />
                      <div>
                        <div className="font-mono text-foreground">
                          {r.target || <em className="italic">(empty)</em>}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {r.reason}
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
