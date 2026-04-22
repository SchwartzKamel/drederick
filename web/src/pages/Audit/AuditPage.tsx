import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, ScrollText } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/EmptyState";
import { useAuditCategories, useAuditTail } from "@/api/hooks/useAudit";
import type { AuditEntry } from "@/api/types";
import {
  AuditEntryRow,
} from "./AuditEntryRow";
import { AuditFilters, type SinceWindow } from "./AuditFilters";
import { AuditLiveToggle } from "./AuditLiveToggle";
import type { AuditRawEntry, AuditRedactedEntry } from "@/api/types";

/** Cap on rendered rows. Virtualization dep is not present; we cap
 *  hard rather than melt the DOM. See zone brief. */
const MAX_RENDERED = 1000;

/** Live poll cadence when the toggle is on. */
const LIVE_POLL_MS = 2_000;

// Duplicated from AuditEntryRow to keep the row file a "components only"
// export (react-refresh rule). If this grows, promote to a shared helper
// in web/src/lib (outside this zone).
function extractEventType(e: AuditEntry): string {
  const ev = (e as AuditRawEntry).event ?? (e as AuditRedactedEntry).event;
  return typeof ev === "string" && ev.length > 0 ? ev : "(unknown)";
}

function extractTs(e: AuditEntry): string | null {
  const ts = (e as AuditRawEntry).ts ?? (e as AuditRedactedEntry).ts;
  return typeof ts === "string" ? ts : null;
}

function sinceToIso(window: SinceWindow): string | undefined {
  const now = Date.now();
  switch (window) {
    case "5m":
      return new Date(now - 5 * 60_000).toISOString();
    case "1h":
      return new Date(now - 60 * 60_000).toISOString();
    case "24h":
      return new Date(now - 24 * 60 * 60_000).toISOString();
    case "all":
    default:
      return undefined;
  }
}

function prefixOf(entry: AuditEntry): string {
  const ev = extractEventType(entry);
  return ev.split(".")[0] ?? "";
}

function entryToSearchText(entry: AuditEntry): string {
  try {
    return JSON.stringify(entry).toLowerCase();
  } catch {
    return "";
  }
}

function entryKey(entry: AuditEntry, index: number): string {
  const ts = extractTs(entry) ?? "";
  const ev = extractEventType(entry);
  return `${ts}:${ev}:${index}`;
}

export function AuditPage() {
  const [selectedPrefixes, setSelectedPrefixes] = useState<ReadonlySet<string>>(
    () => new Set(),
  );
  const [search, setSearch] = useState("");
  const [since, setSince] = useState<SinceWindow>("1h");
  const [live, setLive] = useState(true);
  const [flashKeys, setFlashKeys] = useState<ReadonlySet<string>>(new Set());
  const prevTopTsRef = useRef<string | null>(null);

  const sinceIso = useMemo(() => sinceToIso(since), [since]);

  const tail = useAuditTail(
    sinceIso ? { since: sinceIso, limit: MAX_RENDERED } : { limit: MAX_RENDERED },
  );
  const categories = useAuditCategories();

  // Honor live toggle: when off, stop background refetching.
  const { refetch } = tail;
  useEffect(() => {
    if (!live) return;
    const id = window.setInterval(() => {
      void refetch();
    }, LIVE_POLL_MS);
    return () => window.clearInterval(id);
  }, [live, refetch]);

  const entries = useMemo<AuditEntry[]>(
    () => tail.data?.entries ?? [],
    [tail.data],
  );

  // Flash rows whose timestamps are newer than the last observed top.
  useEffect(() => {
    if (entries.length === 0) return;
    const first = entries[0];
    if (!first) return;
    const top = extractTs(first);
    if (!top) return;
    const prev = prevTopTsRef.current;
    if (prev && top > prev && live) {
      const fresh = new Set<string>();
      for (let i = 0; i < entries.length; i++) {
        const e = entries[i];
        if (!e) break;
        const ts = extractTs(e);
        if (!ts || ts <= prev) break;
        fresh.add(entryKey(e, i));
      }
      if (fresh.size > 0) {
        setFlashKeys(fresh);
        const timer = window.setTimeout(() => setFlashKeys(new Set()), 1_500);
        return () => window.clearTimeout(timer);
      }
    }
    prevTopTsRef.current = top;
  }, [entries, live]);

  // When paused, count entries newer than the snapshot taken at pause.
  const pausedSnapshotRef = useRef<string | null>(null);
  useEffect(() => {
    if (!live) {
      const first = entries[0];
      pausedSnapshotRef.current = first ? extractTs(first) : null;
    } else {
      pausedSnapshotRef.current = null;
    }
    // We deliberately key on `live` only; snapshot captures at transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const pendingCount = useMemo(() => {
    if (live) return 0;
    const snap = pausedSnapshotRef.current;
    if (!snap) return 0;
    let n = 0;
    for (const e of entries) {
      const ts = extractTs(e);
      if (ts && ts > snap) n++;
      else break;
    }
    return n;
  }, [entries, live]);

  const onCatchUp = () => {
    const first = entries[0];
    pausedSnapshotRef.current = first ? extractTs(first) : null;
    setLive(true);
  };

  const prefixCounts = useMemo<Record<string, number>>(() => {
    const counts: Record<string, number> = {};
    for (const e of entries) {
      const p = prefixOf(e);
      counts[p] = (counts[p] ?? 0) + 1;
    }
    return counts;
  }, [entries]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const out: AuditEntry[] = [];
    for (const e of entries) {
      if (selectedPrefixes.size > 0 && !selectedPrefixes.has(prefixOf(e))) {
        continue;
      }
      if (needle.length > 0 && !entryToSearchText(e).includes(needle)) {
        continue;
      }
      out.push(e);
      if (out.length >= MAX_RENDERED) break;
    }
    return out;
  }, [entries, selectedPrefixes, search]);

  const togglePrefix = (p: string) => {
    setSelectedPrefixes((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  };

  const redactedCount = tail.data?.redacted ?? 0;
  const totalCount = tail.data?.count ?? 0;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-4">
            <div>
              <CardTitle className="font-mono text-xl">The Official Record</CardTitle>
              <CardDescription>
                Every punch, timestamped. The governing body does not forget.
              </CardDescription>
            </div>
            <AuditLiveToggle
              live={live}
              pendingCount={pendingCount}
              onToggle={setLive}
              onCatchUp={onCatchUp}
            />
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <AuditFilters
            categories={categories.data}
            selectedPrefixes={selectedPrefixes}
            onTogglePrefix={togglePrefix}
            search={search}
            onSearchChange={setSearch}
            since={since}
            onSinceChange={setSince}
            prefixCounts={prefixCounts}
          />
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span className="font-mono">
              showing {filtered.length} of {totalCount} on tape
              {filtered.length >= MAX_RENDERED ? " (capped)" : ""}
            </span>
            {tail.isFetching ? (
              <span className="italic">announcing the next round…</span>
            ) : null}
          </div>
        </CardContent>
      </Card>

      {redactedCount > 0 ? (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <p>
            The log scanner redacted <strong>{redactedCount}</strong>{" "}
            {redactedCount === 1 ? "entry" : "entries"} that appeared to
            contain plaintext secrets. The raw file retains the original;
            this view is conservative.
          </p>
        </div>
      ) : null}

      {tail.isError ? (
        <Card>
          <CardContent className="p-6 text-sm text-destructive">
            The corner has lost communication. {String(tail.error)}
          </CardContent>
        </Card>
      ) : filtered.length === 0 ? (
        <EmptyState
          kind="no_audit_yet"
          icon={<ScrollText className="h-6 w-6" aria-hidden />}
        />
      ) : (
        <div className="space-y-1">
          {filtered.map((e, i) => {
            const key = entryKey(e, i);
            return (
              <AuditEntryRow
                key={key}
                entry={e}
                flash={flashKeys.has(key)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
