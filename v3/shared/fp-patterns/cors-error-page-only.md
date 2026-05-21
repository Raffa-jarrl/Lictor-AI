# FP class — CORS reflect-with-creds on error pages only

**Discovered:** 2026-05-21 (the "v0.2 near-miss")
**Filter responsibility:** Owl (critic)
**Otter requirement:** must include `secondary_200_probe`

## The pattern

Enterprise CDNs (Akamai, CloudFront with Lambda@Edge, Fastly with VCL) sometimes apply a "permissive default" CORS template to ERROR responses (4xx) while the application's real 200-OK responses have STRICT/pinned CORS. The result:

- `https://example.com/api/user` → 404 + `access-control-allow-origin: <attacker>` + `access-control-allow-credentials: true`
- `https://example.com/` → 200 + NO CORS headers (or pinned to a trusted origin)

A scanner that only looks at the 4xx response will flag this as a CORS misconfig. Submitting that report = the triager runs a curl against the REAL data endpoint (which is what they'd test for impact), sees no CORS issue, marks the report **Informational** or **Not Applicable**. That's signal damage.

## How to discriminate

**Otter's responsibility:** when probing a target and seeing CORS reflect-with-creds on a 4xx response, MUST also probe a known-good 200 endpoint (the apex `/`, `/robots.txt`, `/health` if available) with the same attacker-Origin header and include that response in the JSONL output as `secondary_200_probe`.

**Owl's responsibility:** when reviewing a probe with CORS reflect-with-creds + 4xx primary AND secondary_200_probe present, compare:

| primary (4xx) ACAO | secondary (200) ACAO | Decision |
|---|---|---|
| `<reflected attacker>` | `<reflected attacker>` (same) | **PASS — real gateway-level CORS misconfig** |
| `<reflected attacker>` | (no header) | **REJECT — error-page-only FP** |
| `<reflected attacker>` | pinned to trusted origin (e.g., `https://example.com`) | **REJECT — error-page-only FP, app does CORS right on 200** |
| `<reflected attacker>` | `<reflected attacker>` BUT no ACAC | **REJECT — credentials only on error page, no impact** |

If secondary_200_probe is missing → Owl creates a task for Otter to re-probe before deciding.

## Proven examples (2026-05-21)

### Confirmed FP (error-page-only)
- `amazon.nl/api/user` 404 with reflect+creds; `amazon.nl/` 200 with NO CORS → FP
- `radware.com/api/user` 302 with reflect+creds; `radware.com/` 200 with NO CORS → FP
- `jfrog.com/api/user` 404 with reflect+creds; `jfrog.com/` 200 with `acao=jfrog.com` (pinned) → FP
- `api.kroger.com/api/user` 404 with reflect+creds; same path 404 with NO acao on 200 fallback → FP
- `auth.spacex.com/api/v1/users/me` 404 with reflect+creds; `.well-known/openid-configuration` 200 with reflect+creds → BORDERLINE (public OIDC discovery data is meant to be public; low severity)

### Confirmed REAL (gateway-level, passes the filter)
- `auth.mongodb.com/.well-known/openid-configuration` 200 with reflect+creds AND `/oauth2/v1/userinfo` 401 with reflect+creds → REAL (gateway-level, applies to userinfo when authenticated)
- `api.au.frontegg.com/.well-known/openid-configuration` 401 with reflect+creds AND `/identity/resources/users/v3/me` 401 with reflect+creds → REAL
- `app.rewire.to/` 200 with reflect+creds (no 4xx variant needed — direct 200 confirms) → REAL
- `de.jbl.com/` 403 (Datadome WAF) with reflect+creds AND scanner notes apply on real-browser 200 → REAL (with Datadome caveat in submission)

## Implementation status

- [ ] Otter implements secondary_200_probe (v3 build)
- [ ] Owl implements the comparison logic (v3 build)
- [ ] Regression test set: 5 known FPs + 4 known reals (v3 build)
- [ ] When stable, port the filter back to v0.2 patrol script as a v0.3 patch
