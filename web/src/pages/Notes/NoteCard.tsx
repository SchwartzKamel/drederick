import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

/**
 * Placeholder card describing the CLI-only notes surface. Rendered from
 * NotesPage when no REST endpoint is present. Kept in its own file so
 * that, when a backend agent lands `/api/notes`, this component can be
 * swapped for a real list without touching NotesPage wiring.
 */
export function NoteCard() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="font-mono text-sm">From the corner</CardTitle>
          <Badge variant="outline" className="font-mono text-[0.65rem]">
            CLI-authored
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-muted-foreground">
        <p>
          Notes are entered at the terminal and stored in{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            findings.db
          </code>
          . The SPA will surface them read-only once the backend lands the
          notes endpoint. The governing body keeps the record — not the
          browser.
        </p>
      </CardContent>
    </Card>
  );
}
