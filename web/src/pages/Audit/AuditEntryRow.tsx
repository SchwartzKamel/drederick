import { useMemo, useState } from "react";
import { ChevronRight, Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatRelative, formatTimestamp } from "@/lib/formatters";
import { RedactedValue } from "@/components/RedactedValue";
import {
  type AuditEntry,
  type AuditRawEntry,
  type AuditRedactedEntry,
  isRedactedAudit,
} from "@/api/types";
import { tatumisms } from "@/lib/tatumisms";

export type AuditEntryRowProps = {
  entry: AuditEntry;
  flash?: boolean;
};

// Color-code chip backgrounds by event-type prefix.
const PREFIX_CLASS: Readonly<Record<string, string>> = {
  web: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  jeopardy: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  scope: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  exploit: "bg-red-500/15 text-red-300 border-red-500/30",
  recon: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
};

const DEFAULT_CHIP = "bg-muted text-muted-foreground border-border";

function chipClass(eventType: string): string {
  const prefix = eventType.split(".")[0] ?? "";
  return PREFIX_CLASS[prefix] ?? DEFAULT_CHIP;
}

// Key names that carry sha256 / digest values — routed through RedactedValue.
const DIGEST_KEY_REGEX = /sha256|digest/i;

function extractEventType(e: AuditEntry): string {
  const ev = (e as AuditRawEntry).event ?? (e as AuditRedactedEntry).event;
  return typeof ev === "string" && ev.length > 0 ? ev : "(unknown)";
}

function extractTs(e: AuditEntry): string | null {
  const ts = (e as AuditRawEntry).ts ?? (e as AuditRedactedEntry).ts;
  return typeof ts === "string" ? ts : null;
}
function summarize(e: AuditEntry): string {
  if (isRedactedAudit(e)) {
    return `redacted — ${e.reason}`;
  }
  const parts: string[] = [];
  for (const [k, v] of Object.entries(e)) {
    if (k === "ts" || k === "event") continue;
    if (v === null || v === undefined) continue;
    if (typeof v === "object") {
      parts.push(`${k}=${JSON.stringify(v)}`);
    } else {
      parts.push(`${k}=${String(v)}`);
    }
  }
  const joined = parts.join(" ");
  return joined.length > 120 ? `${joined.slice(0, 119)}…` : joined;
}

export function AuditEntryRow({ entry, flash }: AuditEntryRowProps) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const redacted = isRedactedAudit(entry);
  const eventType = extractEventType(entry);
  const ts = extractTs(entry);
  const summary = useMemo(() => summarize(entry), [entry]);

  const prettyJson = useMemo(() => JSON.stringify(entry, null, 2), [entry]);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(prettyJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable — silent fail
    }
  };

  return (
    <div
      className={cn(
        "rounded-md border border-border bg-card/40 transition-colors",
        flash && "animate-pulse border-primary/60 bg-primary/5",
        redacted && "border-amber-500/30 bg-amber-500/5",
      )}
    >
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        className="flex w-full items-start gap-3 px-3 py-2 text-left hover:bg-accent/30"
      >
        <ChevronRight
          className={cn(
            "mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform",
            expanded && "rotate-90",
          )}
          aria-hidden
        />
        <div className="flex w-40 shrink-0 flex-col">
          <span
            className="font-mono text-xs text-muted-foreground"
            title={ts ? formatTimestamp(ts) : "no timestamp"}
          >
            {ts ? formatRelative(ts) : "—"}
          </span>
          {ts ? (
            <span className="font-mono text-[0.65rem] text-muted-foreground/60">
              {formatTimestamp(ts)}
            </span>
          ) : null}
        </div>
        <span
          className={cn(
            "shrink-0 rounded border px-1.5 py-0.5 font-mono text-[0.7rem]",
            chipClass(eventType),
          )}
        >
          {eventType}
        </span>
        <span className="flex-1 truncate font-mono text-xs text-muted-foreground">
          {summary || <span className="italic opacity-60">(no fields)</span>}
        </span>
      </button>

      {expanded ? (
        <div className="border-t border-border/60 bg-background/40 p-3">
          <div className="mb-2 flex items-center justify-between">
            <DigestBreakdown entry={entry} />
            <button
              type="button"
              onClick={onCopy}
              className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-0.5 text-xs text-muted-foreground hover:bg-accent"
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
          <pre className="overflow-x-auto rounded bg-muted/40 p-2 font-mono text-[0.7rem] leading-relaxed text-foreground">
            {prettyJson}
          </pre>
        </div>
      ) : null}
    </div>
  );
}

/**
 * Scan an entry for digest-shaped keys and surface each via RedactedValue.
 * Invariant: this never renders plaintext candidate fields — only values
 * whose key matches DIGEST_KEY_REGEX and whose value is a string.
 */
function DigestBreakdown({ entry }: { entry: AuditEntry }) {
  const digests = useMemo(() => {
    if (isRedactedAudit(entry)) return [];
    const out: Array<{ key: string; value: string }> = [];
    for (const [k, v] of Object.entries(entry)) {
      if (typeof v !== "string") continue;
      if (!DIGEST_KEY_REGEX.test(k)) continue;
      out.push({ key: k, value: v });
    }
    return out;
  }, [entry]);

  if (digests.length === 0) return <span />;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <span className="text-[0.65rem] font-mono uppercase tracking-wider text-muted-foreground">
        digests
      </span>
      {digests.map((d) => (
        <RedactedValue key={d.key} sha256={d.value} label={d.key} />
      ))}
    </div>
  );
}



