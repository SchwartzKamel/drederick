import { cn } from "@/lib/utils";

export interface RedactedDigestProps {
  value: string;
  className?: string;
  label?: string;
}

/**
 * Displays a digest (SHA-256 hex) in a redaction-safe way. Never accepts
 * plaintext secrets. Phase 3 audit view will use this as the only surface
 * for attempted credentials and captured loot.
 */
export function RedactedDigest({ value, className, label = "sha256" }: RedactedDigestProps) {
  const short = value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-8)}` : value;
  return (
    <span
      title={value}
      className={cn(
        "inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground",
        className,
      )}
    >
      <span className="text-[0.65rem] uppercase tracking-wider opacity-70">{label}</span>
      <span>{short}</span>
    </span>
  );
}
