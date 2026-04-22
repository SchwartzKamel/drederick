import { Notebook } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";
import { NotesList } from "./NotesList";
import { NoteCard } from "./NoteCard";

/**
 * Notes surface.
 *
 * Backend state (verified during Phase 3b):
 *   - No NotesEndpoints.cs in src/Drederick.Web/Endpoints/
 *   - No useNotes.ts in web/src/api/hooks/
 *   - NoteCommand.cs is CLI-only, writes to a SQLite notes DB
 *     (typically alongside findings.db under {out}/).
 *
 * When a backend agent lands `/api/notes`, replace this file's body
 * with a filterable list (host / kind), rendering NoteCard per row and
 * a click-through modal. Keep the surface read-only — notes are
 * CLI-authored. See the zone brief for Phase 3b.
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
            Notes surface is coming. Use <code className="font-mono">drederick note</code>{" "}
            in the meantime — the governing body reads the database the
            same way the SPA will.
          </p>
        </CardContent>
      </Card>

      <NotesList />
      <NoteCard />

      <EmptyState
        kind="no_notes"
        icon={<Notebook className="h-6 w-6" aria-hidden />}
        title="No notes from the corner yet."
      />
    </div>
  );
}
