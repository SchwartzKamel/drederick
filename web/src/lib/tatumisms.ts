/**
 * Tatum-voiced microcopy library. Canonical source for SPA branding.
 *
 * Voice rules (see docs/tatum_voice.md):
 *   - Formal grammar on violent verbs.
 *   - Ring-announcer cadence; short sentences.
 *   - Rule-worship — scope/audit framed as "the governing body".
 *   - Acknowledged mercenary streak — "purse", "weigh-in", "pre-fight".
 *   - No profanity, no script-kiddie voice.
 *
 * All text lives here so copy edits stay in one file and every page
 * renders the same billing.
 */

export type TatumCopy = {
  readonly title: string;
  readonly body: string;
};

export const tatumisms = {
  empty: {
    no_hosts: {
      title: "No opponents weighed in.",
      body: "Load a scope and enqueue a run. We're not in the ring yet.",
    },
    no_findings: {
      title: "Pre-fight analysis pending.",
      body: "Run recon to populate the scorecard.",
    },
    no_services: {
      title: "No services on the tape.",
      body: "The opponent has not yet presented a ring card.",
    },
    no_cves: {
      title: "No CVEs on file for this bout.",
      body: "Either enrichment has not run, or the opponent is clean.",
    },
    no_poc_refs: {
      title: "No proof-of-concept in the corner.",
      body: "The PoC aggregator has returned empty. We fight with what we have.",
    },
    no_exploit_runs: {
      title: "No rounds contested.",
      body: "Nothing has been thrown in anger yet.",
    },
    no_sessions: {
      title: "The CTFd arena is quiet.",
      body: "Start a Jeopardy session to ring the opening bell.",
    },
    no_loot: {
      title: "The purse is empty.",
      body: "Loot will appear here as the match progresses.",
    },
    no_runs: {
      title: "No bouts scheduled.",
      body: "POST /api/runs to start one.",
    },
    no_audit_yet: {
      title: "The governing body has no report on this match.",
      body: "Activity will appear here as it happens.",
    },
    no_database: {
      title: "findings.db has not yet been assembled.",
      body: "Your next run will build it.",
    },
    no_doctor_checks: {
      title: "No pre-fight physical on record.",
      body: "The doctor has not been summoned for this corner.",
    },
    no_notes: {
      title: "The notebook is blank.",
      body: "Operator notes land here. Keep them terse.",
    },
    no_scope: {
      title: "No sanctioning body has weighed in.",
      body: "Load a scope file before stepping into the ring.",
    },
    no_events: {
      title: "The ring is silent.",
      body: "Live events will announce themselves here.",
    },
  },
  errors: {
    network: {
      title: "The corner has lost communication.",
      body: "Check the backend is running on the expected port.",
    },
    auth: {
      title: "You are not sanctioned by any governing body.",
      body: "Your bearer token was rejected.",
    },
    scope_rejected: {
      title: "That target is wild.",
      body: "It's not in the authorized allow-list.",
    },
    not_found: {
      title: "No such contender on the card.",
      body: "The resource you asked for isn't here.",
    },
    server: {
      title: "The referee has called a timeout.",
      body: "The server returned an unexpected error.",
    },
    boundary: {
      title: "Dear God, why are we fighting?",
      body: "A component has thrown. The match is paused.",
    },
    generic: {
      title: "Dear God, why are we fighting?",
      body: "An unexpected error occurred.",
    },
  },
  banner: {
    tagline: "A fair fight is one you didn't prepare well enough for.",
    billing: "I'm heavyweight champ, Drederick Tatum.",
  },
  actions: {
    retry: "Step back in.",
    reload: "Reset the round.",
    dismiss: "Throw in the towel.",
    copy: "Copy to corner.",
    copied: "In the corner.",
  },
} as const;

export type TatumEmptyKind = keyof typeof tatumisms.empty;
export type TatumErrorKind = keyof typeof tatumisms.errors;
