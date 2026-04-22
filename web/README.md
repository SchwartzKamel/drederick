# drederick-web

Operator SPA for the drederick harness. React 18 + Vite 6 + TanStack
Router/Query + shadcn/ui on Tailwind.

## Dev

```
pnpm install
pnpm dev          # http://localhost:5173 (proxies /api + /hubs to 127.0.0.1:7070)
pnpm build        # outputs to ../src/Drederick.Web/wwwroot/
pnpm typecheck
pnpm lint
pnpm generate:api # regenerate src/api/schema.d.ts from running backend
```

## Layout

- `src/App.tsx` — top nav, sidebar, footer, health indicator.
- `src/pages/*` — one page per sidebar entry (Phase 3 fills them).
- `src/api/client.ts` — `openapi-fetch` typed REST client.
- `src/api/signalr.ts` — `@microsoft/signalr` hub helper + `useSignalREvents`.
- `src/components/ui/*` — vendored shadcn primitives.
- `src/components/RedactedDigest.tsx` — SHA-256 display helper. **Never
  render plaintext flags / credentials.** Audit view will use this
  exclusively.

## Invariants

- No telemetry, analytics, or CDN fonts.
- No remote API calls at build or run time — same-origin `/api` + `/hubs`
  only.
- `schema.d.ts` is regenerated from the live backend; do not hand-edit
  beyond the scaffold stub.
