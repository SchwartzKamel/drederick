import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useCreateNote } from "@/api/hooks/useNotes";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

/**
 * Create-note form. Tatum-voiced placeholders. Submits to
 * `/api/notes` via `useCreateNote`; on success the notes list query is
 * invalidated so the new jotting surfaces immediately.
 */
export function NoteCreateForm() {
  const [host, setHost] = useState("");
  const [tag, setTag] = useState("");
  const [body, setBody] = useState("");
  const create = useCreateNote();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = body.trim();
    if (!trimmed) {
      toast.error("Nothing to write down.");
      return;
    }
    try {
      await create.mutateAsync({
        host: host.trim() || null,
        tag: tag.trim() || null,
        body: trimmed,
      });
      toast.success("Noted for the record.");
      setHost("");
      setTag("");
      setBody("");
    } catch (e) {
      toast.error("Could not save note.", {
        description: e instanceof Error ? e.message : undefined,
      });
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="font-mono text-sm">Jot a note</CardTitle>
        <CardDescription>
          Terse observations from the corner. Kept local, kept permanent.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="space-y-3" onSubmit={submit} data-testid="note-create-form">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="space-y-1 text-xs">
              <span className="font-mono font-semibold uppercase tracking-wider text-muted-foreground">
                Host
              </span>
              <input
                type="text"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="10.0.0.1 (optional)"
                className={inputCls}
                data-testid="note-host"
              />
            </label>
            <label className="space-y-1 text-xs">
              <span className="font-mono font-semibold uppercase tracking-wider text-muted-foreground">
                Tag
              </span>
              <input
                type="text"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
                placeholder="intel, flag, credential… (optional)"
                className={inputCls}
                data-testid="note-tag"
              />
            </label>
          </div>
          <label className="block space-y-1 text-xs">
            <span className="font-mono font-semibold uppercase tracking-wider text-muted-foreground">
              Body
            </span>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="What did I learn in the ring?"
              rows={4}
              className={cn(inputCls, "resize-y font-mono text-xs")}
              data-testid="note-body"
            />
          </label>
          <div className="flex items-center justify-end gap-2">
            <Button
              type="submit"
              disabled={create.isPending || body.trim() === ""}
              data-testid="note-submit"
            >
              {create.isPending ? "Writing…" : "Save note"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

const inputCls =
  "block w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring";
