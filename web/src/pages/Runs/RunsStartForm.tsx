import { useMemo, useState } from "react";
import { DrederickApiError } from "@/api/client";
import { useStartRun } from "@/api/hooks/useRuns";
import type { RunsError, StartRunRequest } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { tatumisms } from "@/lib/tatumisms";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

type RunMode = "lab" | "strict";

type CategoryKey =
  | "recon"
  | "exec-pocs"
  | "cred-attacks"
  | "payloads"
  | "destructive"
  | "dos";

type CategoryDef = {
  key: CategoryKey;
  label: string;
  serverFlag: string;
  alwaysOn?: boolean;
};

const CATEGORIES: CategoryDef[] = [
  { key: "recon", label: "recon", serverFlag: "--allow-recon", alwaysOn: true },
  { key: "exec-pocs", label: "exec-pocs", serverFlag: "--allow-exec-pocs" },
  { key: "cred-attacks", label: "cred-attacks", serverFlag: "--allow-cred-attacks" },
  { key: "payloads", label: "payloads", serverFlag: "--allow-payloads" },
  { key: "destructive", label: "destructive", serverFlag: "--allow-destructive" },
  { key: "dos", label: "dos", serverFlag: "--allow-dos" },
];

export type RunsStartFormProps = {
  serverGrants?: ReadonlyArray<CategoryKey>;
  onSubmitted?: (runId: string) => void;
  onCancel?: () => void;
};

export function RunsStartForm({
  serverGrants,
  onSubmitted,
  onCancel,
}: RunsStartFormProps) {
  const [scopePath, setScopePath] = useState("scope.txt");
  const [targetsRaw, setTargetsRaw] = useState("");
  const [mode, setMode] = useState<RunMode>("lab");
  const [outDir, setOutDir] = useState("");
  const [selected, setSelected] = useState<Set<CategoryKey>>(
    () => new Set<CategoryKey>(["recon"]),
  );
  const [rejected, setRejected] = useState<ReadonlyArray<string>>([]);

  const start = useStartRun();

  const isGranted = useMemo(() => {
    if (!serverGrants) return () => true;
    const s = new Set(serverGrants);
    return (k: CategoryKey) => k === "recon" || s.has(k);
  }, [serverGrants]);

  const toggle = (k: CategoryKey) => {
    if (k === "recon") return;
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setRejected([]);
    const targets = targetsRaw
      .split(/\r?\n/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (targets.length === 0) {
      toast.error("No contenders named.", {
        description: "Enter at least one target on its own line.",
      });
      return;
    }
    const body: StartRunRequest = {
      scope_path: scopePath.trim(),
      targets,
      mode,
      categories: Array.from(selected),
      out_dir: outDir.trim() ? outDir.trim() : null,
    };
    try {
      const res = await start.mutateAsync(body);
      toast.success("Bout enqueued.", { description: `run_id ${res.run_id}` });
      onSubmitted?.(res.run_id);
    } catch (err) {
      if (err instanceof DrederickApiError && err.status === 400) {
        const payload = err.body as RunsError | null;
        const list = payload?.rejected_targets ?? [];
        if (list.length > 0) {
          setRejected(list);
          toast.fromTatum("scope_rejected");
          return;
        }
      }
      if (err instanceof DrederickApiError && err.isAuth) {
        toast.fromTatum("auth");
        return;
      }
      toast.fromTatum("server");
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="space-y-4 rounded-lg border border-border bg-card/60 p-4"
    >
      <div className="flex items-baseline justify-between">
        <h3 className="font-mono text-sm font-semibold">Weigh-in</h3>
        <span className="text-xs text-muted-foreground">
          {tatumisms.banner.billing}
        </span>
      </div>

      <Field label="scope_path">
        <input
          type="text"
          value={scopePath}
          onChange={(e) => setScopePath(e.target.value)}
          placeholder="scope.txt"
          className={inputCls}
          required
        />
      </Field>

      <Field label="targets">
        <textarea
          value={targetsRaw}
          onChange={(e) => setTargetsRaw(e.target.value)}
          placeholder={"10.0.0.42\n10.0.0.43"}
          rows={5}
          className={cn(inputCls, "resize-y font-mono text-xs")}
          required
        />
        <p className="mt-1 text-xs text-muted-foreground">
          One contender per line.
        </p>
      </Field>

      <fieldset className="space-y-1">
        <legend className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          mode
        </legend>
        <div className="flex gap-4">
          {(["lab", "strict"] as const).map((m) => (
            <label
              key={m}
              className="flex cursor-pointer items-center gap-2 text-sm"
            >
              <input
                type="radio"
                name="mode"
                value={m}
                checked={mode === m}
                onChange={() => setMode(m)}
              />
              <span className="font-mono">{m}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="space-y-2">
        <legend className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          categories
        </legend>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-3">
          {CATEGORIES.map((c) => {
            const granted = isGranted(c.key);
            const disabled = c.alwaysOn || !granted;
            const checked = c.alwaysOn || selected.has(c.key);
            return (
              <label
                key={c.key}
                title={
                  c.alwaysOn
                    ? "Recon always runs."
                    : granted
                      ? undefined
                      : `Server was not started with ${c.serverFlag}`
                }
                className={cn(
                  "flex items-center gap-2 rounded border border-border bg-background px-2 py-1.5 text-sm",
                  disabled && "opacity-60",
                )}
              >
                <input
                  type="checkbox"
                  disabled={disabled}
                  checked={checked}
                  onChange={() => toggle(c.key)}
                />
                <span className="font-mono text-xs">{c.label}</span>
                {c.alwaysOn ? (
                  <Badge variant="outline" className="ml-auto text-[10px]">
                    required
                  </Badge>
                ) : !granted ? (
                  <Badge variant="outline" className="ml-auto text-[10px]">
                    ungranted
                  </Badge>
                ) : null}
              </label>
            );
          })}
        </div>
      </fieldset>

      <Field label="out_dir (optional)">
        <input
          type="text"
          value={outDir}
          onChange={(e) => setOutDir(e.target.value)}
          placeholder="out/"
          className={inputCls}
        />
      </Field>

      {rejected.length > 0 ? (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm">
          <p className="font-mono font-semibold text-destructive">
            {tatumisms.errors.scope_rejected.title}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {tatumisms.errors.scope_rejected.body}
          </p>
          <ul className="mt-2 space-y-1 font-mono text-xs">
            {rejected.map((t) => (
              <li key={t} className="text-destructive">
                {t}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="flex items-center justify-end gap-2">
        {onCancel ? (
          <Button type="button" variant="ghost" onClick={onCancel}>
            {tatumisms.actions.dismiss}
          </Button>
        ) : null}
        <Button type="submit" disabled={start.isPending}>
          {start.isPending ? "Enqueueing…" : "Start a bout"}
        </Button>
      </div>
    </form>
  );
}

const inputCls =
  "block w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}
