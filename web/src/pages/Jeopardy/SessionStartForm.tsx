import { useMemo, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/lib/toast";
import { DrederickApiError } from "@/api/client";
import { useStartJeopardySession } from "@/api/hooks/useJeopardy";
import { useDoctorChecks } from "@/api/hooks/useDoctor";
import type { JeopardyStartRequest, JeopardyStartResponse } from "@/api/types";

const ALL_CATEGORIES = [
  "pwn",
  "rev",
  "crypto",
  "forensics",
  "web",
  "stego",
  "misc",
] as const;

type LlmProvider = "copilot" | "azure" | "llamacpp";

const PROVIDERS: ReadonlyArray<{
  value: LlmProvider;
  label: string;
  envHint: string;
  /** Substring matchers against DoctorCheck.id / name (case-insensitive). */
  probes: ReadonlyArray<string>;
}> = [
  {
    value: "copilot",
    label: "copilot",
    envHint: "GitHub Copilot CLI",
    probes: ["copilot"],
  },
  {
    value: "azure",
    label: "azure",
    envHint: "AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY",
    probes: ["azure"],
  },
  {
    value: "llamacpp",
    label: "llama.cpp",
    envHint: "LLAMACPP_ENDPOINT",
    probes: ["llama", "llamacpp"],
  },
];

export type SessionStartFormProps = {
  onStarted?: (resp: JeopardyStartResponse) => void;
  onCancel?: () => void;
};

function isValidUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function parseChallengeIds(raw: string): { ok: number[]; bad: string[] } {
  const ok: number[] = [];
  const bad: string[] = [];
  for (const line of raw.split(/[\s,]+/)) {
    const t = line.trim();
    if (!t) continue;
    const n = Number.parseInt(t, 10);
    if (Number.isFinite(n) && String(n) === t) {
      ok.push(n);
    } else {
      bad.push(t);
    }
  }
  return { ok, bad };
}

function parseModelsCsv(raw: string): string[] {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Indicator for whether env vars / CLI for the selected provider look
 * healthy. We reuse `/api/doctor/checks` — if nothing matches we fall
 * back to a neutral "status unknown" dot rather than a false red.
 */
function ProviderEnvIndicator({ provider }: { provider: LlmProvider }) {
  const { data, isLoading } = useDoctorChecks();
  const meta = PROVIDERS.find((p) => p.value === provider)!;
  const match = useMemo(() => {
    if (!data?.Checks) return null;
    const hay = data.Checks;
    return (
      hay.find((c) =>
        meta.probes.some(
          (p) =>
            c.id.toLowerCase().includes(p) ||
            c.name.toLowerCase().includes(p),
        ),
      ) ?? null
    );
  }, [data, meta]);

  if (isLoading) {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[0.65rem] text-muted-foreground">
        <ShieldQuestion className="h-3 w-3" aria-hidden /> probing…
      </span>
    );
  }
  if (!match) {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[0.65rem] text-muted-foreground">
        <ShieldQuestion className="h-3 w-3" aria-hidden />
        set {meta.envHint}
      </span>
    );
  }
  if (match.status === "ok") {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-[0.65rem] text-emerald-400">
        <ShieldCheck className="h-3 w-3" aria-hidden /> ready
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-[0.65rem] text-red-400">
      <ShieldAlert className="h-3 w-3" aria-hidden />
      {match.status}: {match.recommendation ?? meta.envHint}
    </span>
  );
}

export function SessionStartForm({ onStarted, onCancel }: SessionStartFormProps) {
  const [ctfdUrl, setCtfdUrl] = useState("");
  const [ctfdToken, setCtfdToken] = useState("");
  const [scopePath, setScopePath] = useState("");
  const [modelsRaw, setModelsRaw] = useState("");
  const [provider, setProvider] = useState<LlmProvider>("copilot");
  const [runBudget, setRunBudget] = useState<number>(100);
  const [challengeBudget, setChallengeBudget] = useState<number>(5);
  const [categories, setCategories] = useState<string[]>([]);
  const [challengeIdsRaw, setChallengeIdsRaw] = useState("");
  const mutation = useStartJeopardySession();

  const models = parseModelsCsv(modelsRaw);
  const { ok: challengeIds, bad: badIds } = parseChallengeIds(challengeIdsRaw);
  const urlOk = ctfdUrl.length === 0 || isValidUrl(ctfdUrl);

  const canSubmit =
    isValidUrl(ctfdUrl) &&
    ctfdToken.length > 0 &&
    scopePath.length > 0 &&
    models.length > 0 &&
    runBudget > 0 &&
    challengeBudget > 0 &&
    badIds.length === 0 &&
    !mutation.isPending;

  function toggleCategory(cat: string) {
    setCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat],
    );
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    const body: JeopardyStartRequest = {
      ctfd_url: ctfdUrl,
      ctfd_token: ctfdToken,
      scope_path: scopePath,
      models,
      llm_provider: provider,
      run_budget_usd: runBudget,
      challenge_budget_usd: challengeBudget,
      categories: categories.length > 0 ? categories : null,
      challenge_ids: challengeIds.length > 0 ? challengeIds : null,
    };
    try {
      const resp = await mutation.mutateAsync(body);
      toast.success("Opening bell rung.", {
        description: `session ${resp.session_id}`,
      });
      setCtfdToken("");
      onStarted?.(resp);
    } catch (err) {
      if (err instanceof DrederickApiError) {
        const body = err.body as { error?: string; message?: string } | null;
        if (
          err.status === 400 &&
          body?.error &&
          (body.error === "out_of_scope" ||
            body.error === "scope_path_rejected" ||
            body.error === "scope_load_failed")
        ) {
          toast.fromTatum("scope_rejected", {
            description: body.message ?? "The CTFd host is not in scope.",
          });
        } else if (err.status === 400) {
          toast.error("The opening bell declined to ring.", {
            description: body?.message ?? "Invalid request.",
          });
        } else if (err.isAuth) {
          toast.fromTatum("auth");
        } else {
          toast.fromTatum("server");
        }
      } else {
        toast.fromTatum("generic");
      }
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="flex flex-col gap-4 rounded-lg border border-border bg-card/60 p-4"
    >
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h3 className="font-mono text-lg font-semibold">Weigh-in</h3>
          <p className="text-xs text-muted-foreground">
            Declare the CTFd arena, models, and purse. The governing body
            (scope) has final say.
          </p>
        </div>
        {onCancel ? (
          <Button type="button" variant="ghost" size="sm" onClick={onCancel}>
            Throw in the towel
          </Button>
        ) : null}
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-mono text-muted-foreground">ctfd_url *</span>
          <input
            type="url"
            required
            value={ctfdUrl}
            onChange={(e) => setCtfdUrl(e.target.value)}
            placeholder="https://ctfd.example.org"
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
          {!urlOk ? (
            <span className="text-red-400">not a valid http(s) URL</span>
          ) : null}
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="font-mono text-muted-foreground">ctfd_token *</span>
          <input
            type="password"
            required
            autoComplete="off"
            value={ctfdToken}
            onChange={(e) => setCtfdToken(e.target.value)}
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
          <span className="text-muted-foreground">
            stays sha256 in audit — never echoed back.
          </span>
        </label>

        <label className="flex flex-col gap-1 text-xs md:col-span-2">
          <span className="font-mono text-muted-foreground">scope_path *</span>
          <input
            type="text"
            required
            value={scopePath}
            onChange={(e) => setScopePath(e.target.value)}
            placeholder="/path/to/scope.yaml"
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs md:col-span-2">
          <span className="font-mono text-muted-foreground">
            models * (one per line or comma-separated)
          </span>
          <textarea
            required
            value={modelsRaw}
            onChange={(e) => setModelsRaw(e.target.value)}
            rows={3}
            placeholder={"gpt-5\nclaude-sonnet-4.5\nclaude-opus-4.6"}
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
          <span className="text-muted-foreground">
            parsed: {models.length} model{models.length === 1 ? "" : "s"}
          </span>
        </label>

        <fieldset className="flex flex-col gap-1 text-xs md:col-span-2">
          <legend className="font-mono text-muted-foreground">llm_provider</legend>
          <div className="flex flex-wrap gap-4">
            {PROVIDERS.map((p) => (
              <label
                key={p.value}
                className="inline-flex cursor-pointer items-center gap-2 font-mono"
              >
                <input
                  type="radio"
                  name="llm-provider"
                  value={p.value}
                  checked={provider === p.value}
                  onChange={() => setProvider(p.value)}
                  className="accent-primary"
                />
                {p.label}
              </label>
            ))}
          </div>
          <div className="mt-1">
            <ProviderEnvIndicator provider={provider} />
          </div>
        </fieldset>

        <label className="flex flex-col gap-1 text-xs">
          <span className="font-mono text-muted-foreground">
            run_budget_usd *
          </span>
          <input
            type="number"
            min={1}
            step={1}
            value={runBudget}
            onChange={(e) => setRunBudget(Number(e.target.value))}
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
        </label>

        <label className="flex flex-col gap-1 text-xs">
          <span className="font-mono text-muted-foreground">
            challenge_budget_usd *
          </span>
          <input
            type="number"
            min={0.5}
            step={0.5}
            value={challengeBudget}
            onChange={(e) => setChallengeBudget(Number(e.target.value))}
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
        </label>

        <fieldset className="flex flex-col gap-1 text-xs md:col-span-2">
          <legend className="font-mono text-muted-foreground">
            categories (empty = all)
          </legend>
          <div className="flex flex-wrap gap-2">
            {ALL_CATEGORIES.map((c) => {
              const on = categories.includes(c);
              return (
                <button
                  type="button"
                  key={c}
                  onClick={() => toggleCategory(c)}
                  className={`rounded border px-2 py-0.5 font-mono text-[0.65rem] uppercase tracking-wider transition-colors ${
                    on
                      ? "border-primary bg-primary/20 text-primary"
                      : "border-border bg-background text-muted-foreground hover:border-primary/40"
                  }`}
                >
                  {c}
                </button>
              );
            })}
          </div>
        </fieldset>

        <label className="flex flex-col gap-1 text-xs md:col-span-2">
          <span className="font-mono text-muted-foreground">
            challenge_ids (optional, one per line)
          </span>
          <textarea
            value={challengeIdsRaw}
            onChange={(e) => setChallengeIdsRaw(e.target.value)}
            rows={2}
            placeholder={"12\n17\n23"}
            className="rounded border border-input bg-background px-2 py-1 font-mono text-xs"
          />
          <span className="text-muted-foreground">
            parsed: {challengeIds.length}
            {badIds.length > 0 ? (
              <span className="ml-2 text-red-400">
                rejected: {badIds.join(", ")}
              </span>
            ) : null}
          </span>
        </label>
      </div>

      <div className="flex items-center justify-end gap-2">
        <Button type="submit" disabled={!canSubmit}>
          {mutation.isPending ? "Ringing…" : "Ring the opening bell"}
        </Button>
      </div>
    </form>
  );
}
