import { useMemo, useState } from "react";
import { Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/lib/toast";
import { DrederickApiError } from "@/api/client";
import {
  useJeopardyChallenges,
  usePostJeopardyHint,
} from "@/api/hooks/useJeopardy";
import type { JeopardyHintRequest } from "@/api/types";

export type HintKind = "hint" | "note" | "command" | "nudge";

const KINDS: ReadonlyArray<{ value: HintKind; label: string }> = [
  { value: "hint", label: "hint" },
  { value: "note", label: "note" },
  { value: "command", label: "command" },
  { value: "nudge", label: "nudge" },
];

const MAX_BODY = 2048;

export type HintInjectorProps = {
  sessionId: string;
};

/**
 * Send a hint / note / command / nudge into the corner. "Broadcast"
 * means session-wide; otherwise target a specific challenge.
 */
export function HintInjector({ sessionId }: HintInjectorProps) {
  const { data: challenges } = useJeopardyChallenges(sessionId);
  const [scope, setScope] = useState<"broadcast" | "challenge">("broadcast");
  const [challengeId, setChallengeId] = useState<string>("");
  const [kind, setKind] = useState<HintKind>("hint");
  const [body, setBody] = useState<string>("");
  const mutation = usePostJeopardyHint(sessionId);

  const validChallengeIds = useMemo(
    () => new Set((challenges ?? []).map((c) => c.id)),
    [challenges],
  );

  const disabled =
    mutation.isPending ||
    body.trim().length === 0 ||
    body.length > MAX_BODY ||
    (scope === "challenge" && !validChallengeIds.has(Number(challengeId)));

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (disabled) return;
    const payload: JeopardyHintRequest = {
      kind,
      body,
      challenge_id:
        scope === "challenge" && challengeId !== ""
          ? Number(challengeId)
          : null,
    };
    try {
      await mutation.mutateAsync(payload);
      toast.success("Sent to corner.");
      setBody("");
    } catch (err) {
      if (err instanceof DrederickApiError && err.status === 404) {
        toast.fromTatum("not_found");
      } else if (err instanceof DrederickApiError && err.status === 400) {
        toast.error("The corner refused the slip.", {
          description:
            typeof err.body === "object" && err.body && "message" in err.body
              ? String((err.body as { message?: unknown }).message)
              : "Check your hint body.",
        });
      } else {
        toast.fromTatum("server");
      }
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="flex flex-col gap-3 rounded-lg border border-border bg-card/60 p-3"
    >
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-sm font-semibold">Hint injector</h3>
        <span className="font-mono text-[0.65rem] uppercase tracking-wider text-muted-foreground">
          {body.length}/{MAX_BODY}
        </span>
      </div>

      <div className="flex flex-col gap-1 text-xs">
        <label className="font-mono text-muted-foreground">
          destination
        </label>
        <div className="flex gap-2">
          <select
            value={scope}
            onChange={(e) =>
              setScope(e.target.value === "challenge" ? "challenge" : "broadcast")
            }
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          >
            <option value="broadcast">Broadcast to session</option>
            <option value="challenge">For challenge…</option>
          </select>
          {scope === "challenge" ? (
            <select
              value={challengeId}
              onChange={(e) => setChallengeId(e.target.value)}
              className="flex-1 rounded border border-input bg-background px-2 py-1 font-mono text-xs"
            >
              <option value="">— pick challenge —</option>
              {(challenges ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  #{c.id} [{c.category}] {c.name}
                </option>
              ))}
            </select>
          ) : null}
        </div>
      </div>

      <fieldset className="flex flex-col gap-1 text-xs">
        <legend className="font-mono text-muted-foreground">kind</legend>
        <div className="flex flex-wrap gap-3">
          {KINDS.map((k) => (
            <label
              key={k.value}
              className="inline-flex cursor-pointer items-center gap-1 font-mono"
            >
              <input
                type="radio"
                name="hint-kind"
                value={k.value}
                checked={kind === k.value}
                onChange={() => setKind(k.value)}
                className="accent-primary"
              />
              {k.label}
            </label>
          ))}
        </div>
      </fieldset>

      <label className="flex flex-col gap-1 text-xs">
        <span className="font-mono text-muted-foreground">body</span>
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value.slice(0, MAX_BODY))}
          rows={4}
          placeholder="keep it terse; corner work only."
          className="min-h-[6rem] resize-y rounded border border-input bg-background px-2 py-1 font-mono text-xs"
        />
      </label>

      <Button
        type="submit"
        disabled={disabled}
        size="sm"
        className="self-end"
      >
        <Send className="h-3 w-3" aria-hidden />
        Send to corner
      </Button>
    </form>
  );
}
