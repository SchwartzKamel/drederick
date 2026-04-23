import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { NotesList } from "./NotesList";
import { NoteCreateForm } from "./NoteCreateForm";

/**
 * Operator notebook page. Real data — `/api/notes` backs the list
 * and create form. The CLI path (`drederick note`) writes to the same
 * table in `findings.db`, so jottings from either path show up here.
 */
export function NotesPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-xl">Match Notes</CardTitle>
          <CardDescription>
            From the corner. Terse observations, kept for the record.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <p>
            Notes persist to <code className="font-mono">findings.db</code>.
            Drop a line here, or stay in the terminal with{" "}
            <code className="font-mono">drederick note add</code>. The
            governing body reads the same table either way.
          </p>
        </CardContent>
      </Card>

      <ErrorBoundary>
        <NoteCreateForm />
      </ErrorBoundary>

      <ErrorBoundary>
        <NotesList />
      </ErrorBoundary>
    </div>
  );
}
