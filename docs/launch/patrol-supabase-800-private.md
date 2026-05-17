# Patrol — Supabase service-role exposure (PRIVATE)

**Scanned at:** 2026-05-17 09:55 UTC
**Disclosure status:** PRIVATE — 30-day window starts at first outreach.

## Confirmed service_role JWT in client-likely path (3)

Meerkat: draft personalized outreach for each. Open file, verify it's actually exposed (not in a server-only context that just happens to live under src/), then send. Use the standard template from docs/launch/lictor-scan-and-patrol-v0.1.md.

| Repo | Path | Risk | Owner | Stars | Pushed | File |
|---|---|---|---|---|---|---|

| `alejandrosanchez1/backup` | `app/AdminView.tsx` | **client** | alejandrosanchez1 (User) | 1 | 2026-05-04 | [link](https://github.com/alejandrosanchez1/backup/blob/b1c94cda79c2f9637a8fb87827ade1041308bec9/app/AdminView.tsx) |
| `sahilaa1719-ops/medspa-opus` | `src/lib/supabaseAdmin.ts` | **ambiguous** | sahilaa1719-ops (User) | 0 | 2025-12-18 | [link](https://github.com/sahilaa1719-ops/medspa-opus/blob/23830af85694cbe288ddea42df90bca0f867e69b/src/lib/supabaseAdmin.ts) |
| `logistiga/PG1` | `vitest.config.ts` | **ambiguous** | logistiga (User) | 0 | 2025-03-16 | [link](https://github.com/logistiga/PG1/blob/b0989b54ae6a31f0bbe8f87a7c6de90e1c3153c9/vitest.config.ts) |

## Server-only context (no outreach needed)
