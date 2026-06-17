# Lictor Security Check — coverage manifest

**Baseline version:** 2.2.1 · **Last reviewed:** 2026-06-17 · **License:** Apache-2.0 · **Cost:** free

This is the canonical list of what `/lictor-security-check` covers. The goal is
**complete coverage of every externally-observable, ethically-confirmable security
risk** in any project — AI-built or hand-written, web or mobile — explained in plain
English with near-zero false positives. The set maps onto the full **OWASP Top 10
for Web, API, Mobile, and GenAI/LLM**, plus the **CWE Top 25**.

## The 48 checks

| # | Module | Class | Top severity |
|---|--------|-------|--------------|
| 1 | `secrets.md` | Hardcoded API keys / passwords / DB strings | 🔴 |
| 2 | `ai-keys.md` | Leaked AI-provider keys (OpenAI/Anthropic/Gemini/…) | 🔴 |
| 3 | `env-files.md` | Exposed `.env` / `.git` / config files | 🔴 |
| 4 | `cloud-storage.md` | Public S3/GCS/Azure/Firebase/Supabase storage | 🔴 |
| 5 | `logging-pii.md` | Secrets / PII in logs & error responses | 🟠 |
| 6 | `api-auth.md` | Unprotected user-data routes | 🔴 |
| 7 | `authn-session.md` | Broken auth, JWT, sessions, default creds | 🔴 |
| 8 | `idor.md` | Broken object-level authorization | 🔴 |
| 9 | `admin-paths.md` | "Painted lock" admin pages | 🟠 |
| 10 | `db-exposure.md` | Open Supabase/Firebase (no rules) | 🔴 |
| 11 | `injection.md` | SQL / XSS / command / template injection | 🔴 |
| 12 | `ssrf.md` | Server-side request forgery (+ AI agents) | 🟠 |
| 13 | `file-upload.md` | Insecure file upload | 🟠 |
| 14 | `cors.md` | Over-permissive CORS | 🔴 |
| 15 | `security-headers.md` | Missing CSP/HSTS/cookie flags | 🟡 |
| 16 | `webhooks-csrf.md` | Unverified webhooks + missing CSRF | 🟠 |
| 17 | `rate-limiting.md` | No rate limit (brute-force + AI cost-bombing) | 🟠 |
| 18 | `open-services.md` | Exposed debug/admin surfaces in prod | 🔴 |
| 19 | `dependencies.md` | Vulnerable / typosquatted / confusable deps | 🟠 |
| 20 | `ai-agent.md` | Prompt injection / tool-call abuse | 🔴 |
| 21 | `mobile.md` | Mobile leaks (keys/cleartext/storage/exports) | 🔴 |
| 22 | `open-redirect.md` | User-controlled redirects (phishing / token leak) | 🟡 |
| 23 | `cicd-pipeline-integrity.md` | Unpinned CI Actions, `curl\|bash`, unsigned auto-update | 🟠 |
| 24 | `business-flow-automation.md` | Value flow with no bot gate (free-tier farming / scalping / referral fraud / vote-stuffing) | 🟡 |
| 25 | `mass-assignment.md` | Property-level over-binding + over-return (privilege/PII via extra JSON fields) | 🟠 |
| 26 | `mobile-auth-local.md` | Client-side-only mobile auth/authz (biometric-as-decision / client role gate / deep-link grants access) | 🟠 |
| 27 | `mobile-supply-chain.md` | Mobile dep hygiene (floating/unpinned SDK versions, uncommitted lockfile, git-branch deps, abandoned/malicious ad-analytics SDKs) | 🟠 |
| 28 | `indirect-prompt-injection.md` | Untrusted external content (RAG docs / fetched pages / emails / DB rows / tool output) into the prompt with no provenance tagging or data/instruction separation | 🔴 |
| 29 | `system-prompt-secrets.md` | Secrets (keys/tokens/DB strings/internal URLs) or load-bearing authorization/pricing/eligibility rules baked into the system prompt — prompt treated as a trust boundary (OWASP LLM07) | 🟠 |
| 30 | `llm-output-sink.md` | LLM/model output flowing unsanitized into a dangerous sink (HTML render / eval / SQL-shell-path concat / executable response) — the output-side mirror of injection (OWASP LLM05) | 🟠 |
| 31 | `mobile-data-storage.md` | Mobile insecure data-at-rest (unencrypted SQLite/Realm/Core Data, world-readable/external/`.none`-protected files, secrets in device logs) — OWASP M9 | 🔴 |
| 32 | `vector-store-isolation.md` | RAG/vector-DB query with no per-tenant namespace/metadata filter (cross-tenant document retrieval) + client-reachable/committed index credentials — OWASP LLM08 | 🔴 |
| 33 | `model-artifact-provenance.md` | Untrusted model/weights artifacts + unsafe model loading (`torch.load`/`pickle` on hub checkpoints, `trust_remote_code=True` on third-party repos, unpinned model revisions, unverified weight downloads) — OWASP LLM03 | 🔴 |
| 34 | `ungrounded-output-trust.md` | Trusting model output as ground truth: slopsquatting (model-suggested package installed unverified) + ungrounded authority (raw LLM answer as sole decider in auth/eligibility/pricing/medical/legal) — OWASP LLM09 | 🟡 |
| 35 | `weak-crypto.md` | Broken/weak cryptography — MD5/SHA1 for passwords, ECB mode, hardcoded IV/salt, `Math.random()` for tokens, deprecated TLS (CWE-327/328/330/916) | 🟠 |
| 36 | `unsafe-deserialization.md` | Untrusted input into `pickle`/`yaml.load`/PHP `unserialize`/Java `readObject`/`Marshal.load` (CWE-502) | 🔴 |
| 37 | `path-traversal.md` | User-controlled path in file read/serve/include — `../` escape to arbitrary file read (CWE-22/23/36) | 🔴 |
| 38 | `resource-amplification.md` | Unrestricted resource consumption — uncapped page size / request body / GraphQL depth / batch size (OWASP API4) | 🟠 |
| 39 | `audit-logging-gaps.md` | No record of security-relevant events (login, authz change, payment, deletion) — can't detect or investigate a breach (OWASP A09 / API9) | 🟡 |
| 40 | `api-inventory.md` | Shadow/zombie API surface — undocumented, deprecated, debug, or `/v1` endpoints still live (OWASP API9) | 🟡 |
| 41 | `third-party-consumption.md` | Trusting external-API responses blindly — no validation, redirect-following, or timeout on upstream calls (OWASP API10) | 🟡 |
| 42 | `llm-context-overscope.md` | Feeding the model more data than the end user is allowed to see — model becomes a confused-deputy data-leak channel (OWASP LLM02/LLM06) | 🟠 |
| 43 | `agent-tool-permissions.md` | AI agent wired to over-powerful tools (shell, raw SQL, file write, money-moving APIs) with no allowlist/human-in-the-loop (OWASP LLM06) | 🔴 |
| 44 | `rag-ingestion-trust.md` | Poisonable knowledge-base ingestion — any user/source can write documents the RAG later treats as trusted instructions (OWASP LLM04/LLM01) | 🟠 |
| 45 | `mobile-cert-pinning.md` | Mobile TLS trust-all override / missing cert pinning — empty `checkServerTrusted`, always-true hostname verifier, unconditional iOS server trust, Flutter `badCertificateCallback` returning true (HIGH); + unfinished pinning on a money/health app (MEDIUM). Cleartext/`http://` stays in `mobile.md` + `security-headers.md` (OWASP M5) | 🟠 |
| 46 | `mobile-binary-protections.md` | Missing binary hardening — no obfuscation, root/jailbreak detection, debugger/tamper checks (OWASP M7/M8) | 🟡 |
| 47 | `mobile-input-validation.md` | Unvalidated mobile input/output channels — deep links, custom URL schemes, WebView JS bridges, exported IPC (OWASP M4/M7) | 🔴 |
| 48 | `mobile-privacy-controls.md` | Over-broad permissions, undisclosed tracking SDKs, clipboard/pasteboard leakage, sensitive data in screenshots/backups (OWASP M6) | 🟡 |

## How this stays current (the "updated all the time" loop)

1. **Lictor scans the real internet** (the Patrol pillar) for what founders are
   *actually* shipping broken — leaked AI keys, open buckets, exposed admin panels,
   credentialed CORS, dangling-subdomain takeovers.
2. **When a class shows up at volume**, it graduates into a check module here, with
   real-world patterns and false-positive guards learned from live findings.
3. **Bump the baseline version + date above** when modules are added/changed, and
   note it in the repo `CHANGELOG.md`.

So the audit reflects today's exploited classes, not a frozen list. New AI-provider
key formats, new framework default-open configs, and new takeover fingerprints land
here as they emerge in the wild.

## Coverage philosophy (what's in / out)

- **In:** anything confirmable by *reading the code or observing what's public* —
  no exploitation needed. That's the whole map of pre-ship risk.
- **Out (by design):** findings that can only be proven by *attacking* a live system
  (blind RCE, time-based SQLi exploitation). Those belong to authorized pentests, not
  a free pre-ship self-audit — and Lictor never tells a user to attack anything.
- **Near-zero false positives:** every module carries a "What NOT to flag" section.
  Crying wolf is worse than a missed nit for a non-security founder.
