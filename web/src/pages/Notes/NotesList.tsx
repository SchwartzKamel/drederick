import { Notebook, Trash2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/EmptyState";
import { LoadingSkeleton } from "@/components/LoadingSkeleton";
import { isNoDatabase } from "@/api/types";
import { useDeleteNote, useNotes } from "@/api/hooks/useNotes";
import { toast } from "@/lib/toast";

/**
 * Renders the operator's notebook. Talks to `/api/notes`; when
 * findings.db is absent the empty-state card surfaces instead. Each
 * note shows host/tag metadata and the body verbatim — notes are
 * operator prose, not loot, so no redaction happens here.
 */
export function NotesList() {
  const { data, isLoading, isError, error } = useNotes();
  const del = useDeleteNote();

  if (isLoading) {
    return <LoadingSkeleton rows={3} columns={1} cellClassName="h-20" />;
  }
  if (isError) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="font-mono text-sm">Notebook unavailable</CardTitle>
          <CardDescription>
            {(error as Error)?.message ?? "Unknown error loading notes."}
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }
  if (!data || isNoDatabase(data)) {
    return (
      <EmptyState
        kind="no_notes"
        icon={<Notebook className="h-6 w-6" aria-hidden />}
      />
    );
  }

  const notes = data.notes;
  if (notes.length === 0) {
    return (
      <EmptyState
        kind="no_notes"
        icon={<Notebook className="h-6 w-6" aria-hidden />}
      />
    );
  }

  const onDelete = async (id: number) => {
    try {
      await del.mutateAsync(id);
      toast.success("Note stricken from the record.");
    } catch (e) {
      toast.error("Could not delete note.", {
        description: e instanceof Error ? e.message : undefined,
      });
    }
  };

  return (
    <div className="space-y-2">
      {notes.map((n) => (
        <Card key={n.id} data-testid="note-card">
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <CardTitle className="font-mono text-sm">
                #{n.id} — {n.title}
              </CardTitle>
              <div className="flex items-center gap-1">
                {n.host ? (
                  <Badge variant="outline" className="font-mono text-[0.65rem]">
                    {n.host}
                  </Badge>
                ) : null}
                {n.tag ? (
                  <Badge variant="outline" className="font-mono text-[0.65rem]">
                    {n.tag}
                  </Badge>
                ) : null}
              </div>
            </div>
            <CardDescription className="font-mono text-[0.65rem]">
              {n.created_at}
            </CardDescription>
          </CardHeader>
          {n.body ? (
            <CardContent className="space-y-2">
              <pre className="whitespace-pre-wrap font-mono text-xs text-foreground">
                {n.body}
              </pre>
              <div className="flex justify-end">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => onDelete(n.id)}
                  aria-label={`Delete note ${n.id}`}
                  data-testid={`delete-note-${n.id}`}
                >
                  <Trash2 className="h-3 w-3" aria-hidden />
                  <span className="ml-1 text-xs">Delete</span>
                </Button>
              </div>
            </CardContent>
          ) : null}
        </Card>
      ))}
    </div>
  );
}
