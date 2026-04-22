import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { tatumisms } from "@/lib/tatumisms";
import { truncateSha256 } from "@/lib/formatters";
import { cn } from "@/lib/utils";

/**
 * Display a sha256 digest with a copy-to-clipboard button.
 *
 * Invariant: this component's props deliberately do NOT include a
 * plaintext field. Attempting to pass one is a compile error. See
 * `@invariant-id:no-plaintext-secrets` — plaintext secrets never reach
 * the client and never reach this component.
 */
export type RedactedValueProps = {
  sha256: string;
  label?: string;
  className?: string;
};

export function RedactedValue({ sha256, label = "sha256", className }: RedactedValueProps) {
  const [copied, setCopied] = useState(false);
  const short = truncateSha256(sha256);
  const fullValue = sha256.startsWith("sha256:") ? sha256 : `sha256:${sha256}`;

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(fullValue);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be blocked (no HTTPS, permissions). Fail silently.
    }
  };

  return (
    <span
      title={fullValue}
      className={cn(
        "inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground",
        className,
      )}
    >
      <span className="text-[0.65rem] uppercase tracking-wider opacity-70">{label}</span>
      <span>{short}</span>
      <button
        type="button"
        onClick={onCopy}
        aria-label={copied ? tatumisms.actions.copied : tatumisms.actions.copy}
        className="ml-1 inline-flex h-4 w-4 items-center justify-center rounded opacity-60 hover:opacity-100"
      >
        {copied ? (
          <Check className="h-3 w-3" aria-hidden />
        ) : (
          <Copy className="h-3 w-3" aria-hidden />
        )}
      </button>
    </span>
  );
}
