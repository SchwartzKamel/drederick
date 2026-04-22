import { useState } from "react";
import { Check, Copy, Terminal } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { tatumisms } from "@/lib/tatumisms";
import { cn } from "@/lib/utils";

/**
 * Displayed when the notes REST endpoint is absent. Offers a copyable
 * CLI one-liner so the operator can populate the notebook from the
 * terminal. When `NotesEndpoints.cs` lands, swap this file for a real
 * list rendering and delete the hint card.
 */
export function NotesList() {
  const [copied, setCopied] = useState(false);
  const hint =
    "drederick note --host <h> --kind observation --body 'lo-fi'";

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(hint);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable — silent
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="font-mono text-sm">
          Jot from the terminal
        </CardTitle>
        <CardDescription>
          Notes land in <code className="font-mono">findings.db</code>. This
          view is read-only by design — the notebook is written in the
          corner, not in the browser.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 rounded-md border border-border bg-muted/40 p-2">
          <Terminal className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
          <code className="flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-foreground">
            {hint}
          </code>
          <button
            type="button"
            onClick={onCopy}
            className={cn(
              "inline-flex h-7 shrink-0 items-center gap-1 rounded border border-border bg-background px-2 text-xs",
              "hover:bg-accent",
            )}
            aria-label={copied ? tatumisms.actions.copied : tatumisms.actions.copy}
          >
            {copied ? (
              <>
                <Check className="h-3 w-3" aria-hidden />
                <span>{tatumisms.actions.copied}</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" aria-hidden />
                <span>{tatumisms.actions.copy}</span>
              </>
            )}
          </button>
        </div>
      </CardContent>
    </Card>
  );
}
