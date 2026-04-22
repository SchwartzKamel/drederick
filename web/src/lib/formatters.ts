/**
 * Shared display formatters. Deliberately dependency-free (no date-fns,
 * no intl beyond the stdlib) so pages can share these without coupling
 * to a particular locale pack.
 */

/**
 * Format an ISO-8601 timestamp as a short local time + date. Falls back
 * to the input on parse failure so bad server data is visible rather
 * than silently dropped.
 */
export function formatTimestamp(
  iso: string | null | undefined,
  opts?: Intl.DateTimeFormatOptions,
): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    ...opts,
  });
}

export function formatRelative(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const delta = Math.round((then - now) / 1000);
  const abs = Math.abs(delta);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (abs < 60) return rtf.format(delta, "second");
  if (abs < 3600) return rtf.format(Math.round(delta / 60), "minute");
  if (abs < 86_400) return rtf.format(Math.round(delta / 3600), "hour");
  if (abs < 86_400 * 30) return rtf.format(Math.round(delta / 86_400), "day");
  return formatTimestamp(iso);
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || Number.isNaN(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"] as const;
  let n = bytes / 1024;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(n >= 10 ? 0 : 1)} ${units[i]}`;
}

/**
 * Shorten a sha256 hex digest to `abc1…def9`. Input may be bare hex or
 * prefixed with `sha256:`. Output is display-only — never parse it back.
 */
export function truncateSha256(digest: string, head = 4, tail = 4): string {
  const clean = digest.startsWith("sha256:") ? digest.slice("sha256:".length) : digest;
  if (clean.length <= head + tail + 1) return clean;
  return `${clean.slice(0, head)}…${clean.slice(-tail)}`;
}

export function formatUsd(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return "—";
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 4,
  }).format(v);
}

export function formatCount(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return new Intl.NumberFormat().format(n);
}
