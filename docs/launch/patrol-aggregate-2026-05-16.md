# Patrol — service-role exposure scan (aggregate stats)

**Run:** 2026-05-17 15:41 UTC
**Method:** GitHub Code Search for `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` in TypeScript files, filtered to repos pushed in the last N days, with file fetched and JWT verified by decoding payload role.

## Findings

- Total candidate files inspected: **3**
- Files with a confirmed `service_role` JWT decoded: **0**
- Of those, in client-likely paths (the actual bug): **0**
- In server-only paths (legitimate use, no concern): **0**

## Methodology + ethics

- Individual repos are not named in this aggregate report.
- Each owner with a likely-exposed key is contacted privately within 24h.
- 30-day private disclosure window before any individual scorecard goes public.
- One-click opt-out at the founder's request, no questions.
- Full methodology: [`docs/launch/lictor-scan-and-patrol-v0.1.md`](./lictor-scan-and-patrol-v0.1.md)