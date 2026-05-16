# Lictor audits Lictor — 5 findings, 1 critical, all shipped

> **Published:** lictorai.com/blog/lictor-audits-lictor — Tuesday Aug 25, 2026
> **Author:** Raffa [last name], founder
> **Audience:** vibe-coders, indie founders, security-curious devs, anyone deciding whether to trust Lictor before launch
> **Read time:** ~10 minutes
> **Note for the team:** this is the August content artifact per `year-plan-2026-2027.md`. Findings below are placeholders sketched in the shape Mongoose's actual output will take. Before publish, swap any `[FINDING_SPECIFIC]` token plus the five finding bodies for whatever Mongoose actually returns when the audit runs the week of Aug 18. Don't soften the headline if the real audit comes back lighter than this draft — adjust the count, keep the honesty.

---

# Lictor audits Lictor — 5 findings, 1 critical, all shipped

We audited Lictor with Lictor. The audit found 5 things wrong. The most-embarrassing one was a critical IDOR in Guardian's compliance-evidence endpoint — any authenticated user could pull every other user's SOC 2 evidence by changing a number in the URL.

We shipped fixes for all 5 in the 72 hours after the audit ran. This post walks through every one of them, with the broken code, the fix that went to main, and what every other builder should check in their own project this week.

We're six weeks from the public launch. The reason we ran this audit now — and the reason we're publishing it now instead of "after we cleaned things up" — is that a security tool that hides its own bugs is selling a thing it doesn't believe in. Lictor's whole pitch is that founders should run it on their app *before* shipping. We did the same. Here's what fell out.

---

## How the audit ran

We checked out a clean copy of the `Raffa-jarrl/Lictor-AI` monorepo on a fresh Mac, opened Claude Code, and ran one slash command:

```
/lictor-security-check
```

Same skill anyone can run on their own project today. Free, open source, Apache 2.0. No special flags, no internal mode, no team-only checks. The audit you'd get if you cloned us tomorrow is the audit we got on ourselves.

The 11-agent crew split the work the way they would on any teardown:

- **Wolf** owned the calendar and the briefing
- **Hawk** picked the scope — the full monorepo, including the four shipped products and the skill files themselves
- **Mongoose** ran the 7 checks across `lictor-core/`, `sentinel/`, `shield/`, `guardian/`, and `skills/`
- **Owl** scored each finding for severity + reproducibility and cut anything below "real bug, real impact"
- **Mantis** reviewed Mongoose's output against past teardowns to flag anything inconsistent — and caught one thing Mongoose missed
- **Lyrebird** wrote what you're reading

Total time: 14 minutes against roughly 38,000 lines of TypeScript, Rust, and Python.

Five findings made it past Owl. One critical, one high, one medium, two low. We've shipped fixes for all of them. The check definitions Mongoose used now flag this same pattern in everyone else's code — so if any of these bugs are hiding in *your* project, the next time you run `/lictor-security-check` it will catch them.

What this proves, mostly: Lictor is auditable. Anyone can rerun the audit. The findings are reproducible from a clean checkout. We didn't cherry-pick. We didn't fix-then-publish — we published the dates of disclosure and the dates of fix, and the gap between them is in the changelog.

What it doesn't prove: that we're done finding bugs in Lictor. We aren't. We'll find more. So will you. The section at the end of this post explains what happens when you do.

---

## Finding #1 — 🔴 Critical — Guardian's compliance-evidence endpoint returned everyone's data to anyone authenticated

**File:** `guardian/api/routes/compliance/evidence.ts`
**Severity:** 🔴 Critical
**Found by:** Mantis's weekly review of audit logs spotted the access pattern
**Disclosed internally:** 2026-08-18
**Fix shipped to main:** 2026-08-19

### The pattern

Guardian is the hosted dashboard layer of Lictor — the one teams use to pull SOC 2 / GDPR / EU AI Act evidence about what their AI agents did and what got blocked. Different roles have different views: a `compliance_admin` should see the full evidence export; a regular `member` should see incidents tied to their own account.

The evidence-export endpoint forgot the role check.

Any user with a logged-in session token could call `GET /api/compliance/evidence/:tenant_id` with another tenant's ID in the URL and get the full export back. The endpoint authenticated you. It didn't authorize you.

### The code

The broken handler looked roughly like this:

```typescript
// guardian/api/routes/compliance/evidence.ts
export async function handler(req: Request) {
  const session = await getSession(req)
  if (!session) return new Response("Unauthorized", { status: 401 })

  const tenantId = req.params.tenant_id
  const evidence = await db.query(
    "SELECT * FROM compliance_evidence WHERE tenant_id = $1",
    [tenantId]
  )

  return Response.json(evidence)
}
```

You see it. The handler reads a session (you must be logged in), reads the tenant ID from the URL (you control that), and queries on it directly. There's no "does this session belong to a user who has `compliance_admin` on this tenant" step.

### Why this matters

If you sell a hosted security dashboard and a customer's compliance officer asks "show me you didn't leak our SOC 2 evidence to other customers," the answer needs to be "here's the role check, here's the audit log, here's the test that proves it." We didn't have any of the three.

In production, this would have been a breach we'd have had to disclose. Our own incident-response plan calls for a 72-hour disclosure to affected tenants. We'd be on the hook for our own breach playbook.

### The fix

```typescript
// guardian/api/routes/compliance/evidence.ts
export async function handler(req: Request) {
  const session = await getSession(req)
  if (!session) return new Response("Unauthorized", { status: 401 })

  const tenantId = req.params.tenant_id

  const allowed = await db.query(
    `SELECT 1 FROM tenant_roles
     WHERE user_id = $1 AND tenant_id = $2 AND role = 'compliance_admin'`,
    [session.user_id, tenantId]
  )

  if (allowed.rowCount === 0) {
    await auditLog.record({
      event: "compliance_evidence_access_denied",
      user_id: session.user_id,
      tenant_id: tenantId,
    })
    return new Response("Forbidden", { status: 403 })
  }

  await auditLog.record({
    event: "compliance_evidence_access_granted",
    user_id: session.user_id,
    tenant_id: tenantId,
  })

  const evidence = await db.query(
    "SELECT * FROM compliance_evidence WHERE tenant_id = $1",
    [tenantId]
  )

  return Response.json(evidence)
}
```

Three changes. One: the role check. Two: a `Forbidden` instead of leaking that the tenant exists. Three: an audit-log entry on both branches — so the next time someone tries this, we have a record.

We also added a regression test that calls the endpoint with three different role combos (compliance_admin on the right tenant, compliance_admin on a different tenant, member on the right tenant) and asserts the three different outcomes. That test now blocks any future regression.

### What this teaches

If your app has roles, the role check belongs in the same function that does the work. Not in middleware that might or might not be wired up. Not in the frontend that anyone can bypass. **In the handler.** Right above the database query.

Run a grep across your routes for any handler that reads a URL parameter and queries on it without a role check above the query. Every one of those is an IDOR candidate. The plain-English description is: *users can see other users' data by changing the number in the URL.* If a query parameter controls what data comes back and there's no check tying that parameter to the logged-in user, you have this bug.

---

## Finding #2 — 🟠 High — The Lictor skill could be tricked into writing audit findings outside its own folder

**File:** `skills/lictor-security-check/SKILL.md` (Step 3 — writing the report)
**Severity:** 🟠 High
**Found by:** Mongoose, running Lictor recursively on Lictor's own skill files
**Disclosed internally:** 2026-08-18
**Fix shipped to main:** 2026-08-19

### The pattern

The `/lictor-security-check` skill writes its output to a per-project file. Until this week, that path was constructed from the project's directory name without any sanitization.

If you ran the audit on a project named `../../etc/lictor-evil`, the skill would try to write `~/Lictor/findings/../../etc/lictor-evil/audit.json`. On macOS and Linux, that resolves outside the intended findings directory.

This is path traversal. The classic version of the bug. Lictor is supposed to catch this in *your* code. It had a version of it in its own skill.

### The code

Roughly what the skill was doing under the hood:

```typescript
// skills/lictor-security-check/write-findings.ts (before)
import path from "node:path"
import fs from "node:fs/promises"

const HOME = process.env.HOME!
const FINDINGS_ROOT = path.join(HOME, "Lictor", "findings")

export async function writeFindings(projectName: string, findings: object) {
  const targetDir = path.join(FINDINGS_ROOT, projectName)
  await fs.mkdir(targetDir, { recursive: true })
  await fs.writeFile(
    path.join(targetDir, "audit.json"),
    JSON.stringify(findings, null, 2)
  )
}
```

`projectName` comes from the directory the user invoked the skill from. If you cloned a malicious repo named `../../etc/something` and ran the audit, the skill would happily write outside the findings root.

The blast radius is bounded by file-system permissions — the skill runs as the user, so it can't escalate to root. But "the security audit tool wrote a file your IDE wasn't expecting" is still a finding we'd flag in any other audit, so we're flagging it in ours.

### Why this matters

Mongoose found this by doing something obvious: it ran Lictor on Lictor. The recursive case — *what does our own tool do when pointed at our own code?* — is the kind of check that catches bugs no other audit does. We're going to make it part of every release going forward.

### The fix

Eight new lines on `write-findings.ts`:

```typescript
// skills/lictor-security-check/write-findings.ts (after)
import path from "node:path"
import fs from "node:fs/promises"

const HOME = process.env.HOME!
const FINDINGS_ROOT = path.join(HOME, "Lictor", "findings")

function safeName(projectName: string): string {
  return projectName.replace(/[^a-zA-Z0-9._-]/g, "_")
}

export async function writeFindings(projectName: string, findings: object) {
  const targetDir = path.resolve(FINDINGS_ROOT, safeName(projectName))
  if (!targetDir.startsWith(FINDINGS_ROOT + path.sep)) {
    throw new Error(`refused to write outside ${FINDINGS_ROOT}`)
  }
  await fs.mkdir(targetDir, { recursive: true })
  await fs.writeFile(
    path.join(targetDir, "audit.json"),
    JSON.stringify(findings, null, 2)
  )
}
```

Two defenses, both cheap: sanitize the name to a known-good character set, then canonicalize the full path and refuse to write if the canonical form escapes the findings root. Belt and suspenders. The check definitions for `path-traversal` now look for this exact pattern in every project Lictor audits.

### What this teaches

Anywhere a user-controlled value lands in `path.join` or its equivalent in your stack, you have this question to answer: what happens if the value is `../`? Or `/etc/passwd`? Or a 4,000-character UTF-8 string with embedded null bytes?

The fix is always the same. Canonicalize the path, then verify the canonical form is still inside the directory you intended. If your language's path library doesn't have `realpath` / `resolve` / canonicalize, that's its own finding.

---

## Finding #3 — 🟡 Medium — Sentinel's `wrap()` accepted any config object, including malformed ones

**File:** `sentinel/src/wrap.ts`
**Severity:** 🟡 Medium
**Found by:** Owl, flagging an inconsistency between Sentinel's docstring and its actual behavior
**Disclosed internally:** 2026-08-18
**Fix shipped to main:** 2026-08-20

### The pattern

Sentinel is the runtime defense SDK. You wrap your OpenAI or Anthropic client with one line:

```javascript
const client = wrap(new OpenAI(), {
  preflight: ["prompt-injection", "secrets-in-input"],
  postflight: ["pii-leak"],
})
```

The config object on the right is what tells Sentinel which checks to run at which stage. Until this week, Sentinel did exactly zero validation on that object. If you passed `{ preflight: "prompt-injection" }` (string instead of array), Sentinel silently skipped the preflight stage. If you passed `{ preflght: ["prompt-injection"] }` (typo on the key), same thing — silently skipped.

A runtime defense library that doesn't defend against a malformed config is, in a tidy little way, the joke that writes itself. We were the punchline.

### The code

The original `wrap()` body was forgiving to a fault:

```typescript
// sentinel/src/wrap.ts (before)
export function wrap<T>(client: T, config: WrapConfig = {}): T {
  const preflight = Array.isArray(config.preflight) ? config.preflight : []
  const postflight = Array.isArray(config.postflight) ? config.postflight : []

  // ... rest of the wrapping logic uses `preflight` and `postflight`
}
```

The `Array.isArray` checks were defensive in the wrong direction — they prevented crashes but masked bugs. If a developer made a typo or passed the wrong shape, Sentinel would happily run with no checks at all and never tell them.

### Why this matters

The mode of failure here is the worst one in a defense library: silent. You think Sentinel is running prompt-injection checks. Sentinel thinks you didn't ask for any. Production traffic flows. Nothing logs. Nothing alerts. Nothing breaks until something does.

### The fix

We added JSON schema validation on `wrap()` and made the failure mode loud:

```typescript
// sentinel/src/wrap.ts (after)
import { z } from "zod"

const WrapConfigSchema = z
  .object({
    preflight: z.array(z.enum(KNOWN_CHECKS)).optional().default([]),
    postflight: z.array(z.enum(KNOWN_CHECKS)).optional().default([]),
    onBlock: z.function().optional(),
    telemetry: z.boolean().optional().default(false),
  })
  .strict()

export function wrap<T>(client: T, config: unknown = {}): T {
  const parsed = WrapConfigSchema.safeParse(config)
  if (!parsed.success) {
    throw new SentinelConfigError(
      `Sentinel: bad config. ${parsed.error.issues.map(i => i.message).join("; ")}`
    )
  }
  const { preflight, postflight } = parsed.data
  // ... rest of the wrapping logic
}
```

Three changes. One: a schema with the known checks as a closed enum (typos throw). Two: `.strict()` so unknown keys throw (catches `preflght`). Three: a real exception with the parser's error messages, so the developer sees exactly what went wrong instead of silently getting no protection.

### What this teaches

Every library that takes a config object should validate it. Especially security libraries. Especially security libraries where the failure mode is "silently does nothing." If your `wrap()` or `init()` or `configure()` function accepts a plain object today, ask yourself: what happens if a typo lands in production? If the answer is "nothing visible," that's the bug.

---

## Finding #4 — 🔵 Low — Test fixtures shipped in the published npm package

**File:** `sentinel/package.json` (npm publish config)
**Severity:** 🔵 Low
**Found by:** Hawk, sweeping the published `@lictor/sentinel` tarball after the last alpha release
**Disclosed internally:** 2026-08-19
**Fix shipped to main:** 2026-08-19

### The pattern

The `@lictor/sentinel` test fixtures include a corpus of known prompt-injection strings — that's how we verify the detector catches them. The fixtures are useful in development. They have no business shipping to production.

But ship they did. The published npm tarball for `@lictor/sentinel@0.1.0-alpha.4` contained the full `test/fixtures/` directory, including a file called `known-injections.json` with about 240 attack strings. Anyone who installed Sentinel got a free copy of every prompt-injection signature Sentinel scans for.

Two problems with that. The small one: it bloats the package by about 380 KB. The bigger one: a creative attacker could use that file as a known-attack signature to evade Sentinel itself. *"I'll just craft a payload that doesn't match any line in `known-injections.json`."* That's not how the detector works — it uses families of patterns, not literal strings — but the principle stands. Don't hand out your detection corpus.

### The code

The fix lives in two files. A new `.npmignore`:

```
test/
tests/
fixtures/
coverage/
*.test.ts
*.spec.ts
benchmarks/
```

And the `files` array in `package.json` got tightened from `["dist", "src"]` (which inadvertently included some test data) to:

```json
{
  "files": [
    "dist",
    "README.md",
    "LICENSE"
  ]
}
```

We re-ran `npm pack --dry-run` on the new build and confirmed the tarball dropped from 1.1 MB to 720 KB. No fixtures inside.

### Why this matters

This one isn't a security vulnerability in the strict sense. It's a category of bug that's easy to miss because it doesn't trip any test. The tests pass. The library works. The fixtures just happen to ride along. The kind of thing you only notice when you go look.

### What this teaches

Run `npm pack --dry-run` on your package before you publish. Look at the file list. Anything in there that isn't code your users will execute is a file you're shipping for free to anyone who installs you. Some of it is junk. Some of it is signature material an attacker would love to have.

The Python equivalent is `python -m build` + checking the `.tar.gz` contents. Same idea. Same one-minute fix.

---

## Finding #5 — 🔵 Low — Mission Control's proxy leaked the name of the gating env-var in a 503 error

**File:** `mission-control/proxy.ts`
**Severity:** 🔵 Low
**Found by:** a private beta tester running Lictor for the first time, who got the 503 and forwarded a screenshot
**Disclosed internally:** 2026-08-22
**Fix shipped to main:** 2026-08-22

### The pattern

Mission Control is the agent dispatcher. On a fresh install, before you set the `MISSION_CONTROL_TOKEN` env-var, the first call to the proxy returns a 503. Helpful. The body of the 503, until this week, said:

```
503 Service Unavailable
Mission Control proxy not configured. Set MISSION_CONTROL_TOKEN.
```

That last sentence is the bug. It tells anyone hitting the endpoint the exact name of the env-var that gates access. An attacker probing the surface gets a free piece of intel — *"if I ever land code execution on this host, I know what variable to grab."*

### The code

The handler had a literal string in it:

```typescript
// mission-control/proxy.ts (before)
if (!process.env.MISSION_CONTROL_TOKEN) {
  return new Response(
    "Mission Control proxy not configured. Set MISSION_CONTROL_TOKEN.",
    { status: 503 }
  )
}
```

Fixed by stripping the hint:

```typescript
// mission-control/proxy.ts (after)
if (!process.env.MISSION_CONTROL_TOKEN) {
  console.error("Mission Control: gating env-var not set; refusing to start")
  return new Response("Service unavailable", { status: 503 })
}
```

Two things moved. The operator-facing hint (the env-var name) goes to `console.error` where the operator can see it on first boot. The user-facing 503 body becomes generic. The operator gets the help. The attacker gets nothing.

### Why this matters

Credit on this one goes to a private beta tester who noticed the error during their first install and wrote in: *"is it intentional that the error tells me the env-var name?"* It wasn't. The community catches things the audit doesn't. This will keep happening, and we will keep crediting it.

### What this teaches

Every error message your service returns to an unauthenticated caller is intel. The principle is: log helpfully to the operator, return generically to the world. *"The database is at db-internal-staging-3.cluster.internal and the connection timed out"* is great in logs and terrible in a 500 response. Run a grep across your error handlers for anything that names an env-var, a hostname, a path, or a config key. Those go in logs, not in responses.

---

## What we changed in the 72 hours after the audit

Five fixes shipped to `main` between Aug 19 and Aug 22:

- **L0001** — Guardian compliance-evidence endpoint: role check + audit-log entries on both branches + regression test
- **L0002** — Skill report writer: name sanitization + canonical-path verification
- **L0003** — Sentinel `wrap()` config validation with `zod`, strict mode, real exceptions on bad config
- **L0004** — `.npmignore` + tightened `package.json` files array; tarball cut from 1.1 MB to 720 KB
- **L0005** — Generic 503 body in Mission Control proxy; env-var hint moved to operator logs

Three changes that aren't on that list but matter just as much:

**The check definitions Mongoose used got updated.** The IDOR pattern (Finding #1), the path-traversal pattern (Finding #2), and the unvalidated-config pattern (Finding #3) are now in the public check files at `skills/lictor-security-check/checks/`. Next time you run `/lictor-security-check` on any project, those three patterns are part of the scan. We caught them in ourselves; they're caught for everyone now.

**A self-audit fixture corpus.** We added anonymized versions of all 5 findings to the test corpus that runs in CI on every push. If anyone — us, a contributor, future-Raffa at 2am — reintroduces any of these patterns, the build fails. The corpus lives at `tests/regressions/self-teardown-2026-08/`.

**`SECURITY.md` updated.** The Reporting section now references this teardown as the canonical example of how Lictor handles its own findings. The audit-our-own-audit protocol applies to us first.

The full changelog entries for L0001–L0005 are in `CHANGELOG.md` with the dates of disclosure, dates of fix, and the contributor credit on Finding #5. No silent fixes. No batched omissions.

---

## What this means about Lictor

A few things we want on the record now, before the launch.

We shipped bugs. Every security team does. The interesting part is that our own tool caught most of them, the recursive case caught one more, and a private beta tester caught the fifth. Three different surfaces, three different categories of bug, three working detection mechanisms. That's the shape of a system that works — not one that's perfect.

We will find more. Every audit Lictor runs across the next year is going to surface patterns we haven't yet learned to catch. When you run `/lictor-security-check` on your project and you find something Lictor missed — a real bug, in production code, that the audit walked past — please file an issue on `Raffa-jarrl/Lictor-AI` with the `false-negative` label. The audit-our-own-audit protocol explains exactly what happens next: regression test, new rule, public credit, sometimes a bug bounty payment.

Credibility comes from receipts, not claims. We never say "Lictor is 99% accurate." We say "Lictor caught the bugs in this post, missed the one a beta tester caught, and we'll publish the next round of findings the same way." That's the standing claim. It's falsifiable. The receipts compound in `CHANGELOG.md` and at `lictorai.com/audit-report`.

If a security tool tells you it's perfect, you're being sold marketing. We told you we shipped a critical IDOR. The next time someone asks why they should trust Lictor over the closed-source incumbents, point them at this post.

---

## Run it on your own code

Three things you can do this week:

**Run `/lictor-security-check` on your project.** It's a Claude Code skill, free, Apache 2.0, no signup, no telemetry. It will write a `SECURITY-AUDIT.md` file in your project root with the same kind of findings you read above. Install instructions: [lictorai.com/install](https://lictorai.com/install).

**If you find a bug in Lictor itself, file an issue.** We mean any bug — false positive (we flagged something safe), false negative (we missed something real), or voice-bug (the language was unclear). The labels are already in the GitHub issue template. High-severity false-negative reports tied to real incidents qualify for the bug bounty.

**Subscribe to the newsletter.** The first public weekly teardown ships Tuesday Oct 6, 2026 — same day as the public launch. Then one every Tuesday after that, forever. Sign up at [lictorai.com](https://lictorai.com).

That's it. No upsell, no pricing page on the way out, no "talk to sales." Run the audit on your stuff. File the bugs you find on ours. See you Oct 6.

— Raffa
[lictorai.com](https://lictorai.com) · [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI)

---

# Companion content

## Twitter thread (8 tweets)

**Tweet 1**
We audited Lictor with Lictor.

Found 5 bugs. One was a critical IDOR in our compliance dashboard — any logged-in user could pull every other tenant's SOC 2 evidence by changing a number in the URL.

We shipped fixes for all 5 in 72 hours. Here's the writeup. 🧵

**Tweet 2**
1/ 🔴 Critical — Guardian's compliance-evidence endpoint authenticated you, but didn't authorize you.

`GET /api/compliance/evidence/:tenant_id` — pass anyone's tenant ID, get their data back.

Fix: role check in the handler, audit-log on both branches, regression test.

**Tweet 3**
2/ 🟠 High — Our own skill could be tricked into writing audit findings outside its findings folder.

If you cloned a repo named `../../etc/something` and ran `/lictor-security-check`, Lictor would happily write outside the intended dir.

Fix: 8-line canonical-path check.

**Tweet 4**
3/ 🟡 Medium — Sentinel's `wrap()` accepted any config object. Typo the key? Silent skip. Wrong shape? Silent skip.

A runtime defense library that silently defends nothing is the joke that writes itself.

Fix: zod schema, strict mode, real exception on bad config.

**Tweet 5**
4/ 🔵 Low — `@lictor/sentinel` shipped its test fixtures (240 known prompt-injection strings) inside the published npm tarball.

Not a vuln per se, but free intel for attackers.

Fix: `.npmignore` + tightened `files` array. Tarball dropped from 1.1 MB to 720 KB.

**Tweet 6**
5/ 🔵 Low — Mission Control's 503 leaked the name of the gating env-var.

`Set MISSION_CONTROL_TOKEN` in the error body = a free clue for anyone probing the surface.

Caught by a private beta tester, not the audit. Credit where due.

Fix: generic 503, hint goes to operator logs.

**Tweet 7**
Every fix shipped to main between Aug 19 and Aug 22. Every check definition got updated so Lictor catches these patterns in everyone else's code now too.

Full writeup with the broken code + the diffs:
lictorai.com/blog/lictor-audits-lictor

**Tweet 8**
Run `/lictor-security-check` on your own project today.

If you find a bug in Lictor itself, file an issue — high-severity false-negatives qualify for the bug bounty.

Apache 2.0. No signup. No telemetry.

github.com/Raffa-jarrl/Lictor-AI

---

## LinkedIn post (~400 words)

**Title:** Why we audited our own security tool before launching it

Six weeks before the public launch of Lictor — the open-source AI security suite I've been building solo — we ran our own audit against our own codebase. The audit found 5 things wrong. The most serious one was a critical IDOR vulnerability in the hosted dashboard's compliance-evidence endpoint: any authenticated user could pull every other tenant's SOC 2 evidence by changing a tenant ID in the URL.

We shipped fixes for all 5 in 72 hours. And we're publishing the writeup before the launch, not after.

Most security vendors do this in reverse. They polish, they certify, they launch with a clean story. Then, quietly, in a SOC 2 audit two years later, the bugs come out. That model only works if the buyer never finds out about the gap between the marketing and the code.

Lictor's whole pitch is that founders should run our audit on their app before shipping. We did the same. The result is on the blog now: every finding, with the broken code, the diff that went to main, and the lesson for every builder who might have the same bug in their own project.

Three patterns from the audit are worth flagging here, because they're common across every B2B SaaS I've reviewed in 20 years of security engineering:

**1. The IDOR pattern.** If your handler reads a URL parameter and queries on it without a role check in the same function, you have this bug. Middleware is not enough. The check belongs above the database query.

**2. The path-traversal pattern.** Anywhere user input lands in a file path, canonicalize and verify the result stays inside the intended directory. Two-line fix. Ships in production unchecked across most of the SaaS codebases I've reviewed in the last five years.

**3. The "silent defense" pattern.** Security libraries that accept malformed configs and silently do nothing are worse than libraries that crash on bad input. The crash is loud and gets fixed; the silence is invisible and ships to production undetected.

If your team buys security tools, ask the vendor: when was the last time you ran your own product against your own code, and where is the public writeup? If the answer is "we don't publish that," you're being sold marketing.

The Lictor writeup: [lictorai.com/blog/lictor-audits-lictor](https://lictorai.com/blog/lictor-audits-lictor)
The repo (Apache 2.0): [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI)

#AppSec #InfoSec #OpenSource #AISecurity #SOC2

---

## Hacker News submission

**Title:** Show HN: Lictor (security tool) audits itself, finds 5 bugs, ships fixes

**Body:**

I've been building Lictor — an open-source AI security audit suite — solo for the last several months. Public launch is Oct 6.

Before the launch, I ran Lictor's own `/lictor-security-check` skill against the Lictor monorepo. It found 5 issues. The worst one was a critical IDOR in the hosted Guardian dashboard: any authenticated user could request another tenant's compliance evidence by passing their tenant ID in the URL. Authentication was checked. Authorization wasn't.

Other findings: a path-traversal in the skill's own report-writing logic (running Lictor on Lictor caught it), a Sentinel SDK that accepted malformed config objects silently, test fixtures shipping inside the published npm tarball, and a Mission Control 503 that leaked the name of the gating env-var in the error body.

All five shipped fixes to main between Aug 19 and Aug 22. The detection rules now flag these patterns in any project Lictor audits, so if you run it on your own code today, the patterns we found in ourselves are part of the scan.

Posting this here because (a) HN's brutal feedback is the point — if there's a sixth bug I missed, please file an issue, and (b) I want to challenge the convention that security vendors clean up *before* publishing. The opposite is more useful.

Writeup with the broken code + diffs: [lictorai.com/blog/lictor-audits-lictor](https://lictorai.com/blog/lictor-audits-lictor)
Repo (Apache 2.0): [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI)

— Raffa

---

# Distribution plan

**Publish date:** Tue Aug 25, 2026 — per `year-plan-2026-2027.md` Month 3 (August: engine testing). 09:00 PT cross-post window matches the eventual teardown cadence.

**Pre-publish checks:**
- Lawyer review of the IDOR finding's language. "Critical IDOR" is a technical claim and the writeup describes it concretely. Low risk because (a) the bug was in our code, (b) the fix shipped before publish, (c) no customer data was actually exposed in production (Guardian wasn't yet GA). Confirm with counsel anyway. Budget: ~$250 of the outside-lawyer retainer.
- Diff every code snippet against `main` to confirm the "before" snippets accurately represent the pre-fix state. Mongoose's actual output should drive this — placeholder code in the draft becomes real code after the audit runs the week of Aug 18.
- Verify every CHANGELOG entry (L0001–L0005) is present and dated correctly before the post links to it.

**Channels (Aug 25, in order):**
- 09:00 PT — Lictor blog (canonical URL)
- 09:01 PT — Twitter thread (8 tweets) from `@lictor_ai`
- 09:05 PT — LinkedIn post from Raffa's personal account
- 09:10 PT — Hacker News submission as "Show HN"
- 09:30 PT — Reddit r/programming + r/devops
- 10:00 PT — Substack newsletter auto-send to the list
- 11:00 PT — YouTube short (Cuttlefish storyboards, Raffa records over the weekend before)
- All week — Bee builds a `lictorai.com/blog/lictor-audits-lictor` landing variant for SEO around "Lictor self audit" / "security tool audits itself"

**Day-of response plan:**
- Raffa available to respond to HN comments within 1 hour of submission until 10pm PT
- Meerkat agent monitors Twitter mentions and routes substantive technical questions to Raffa; Meerkat handles light triage (welcome, link to writeup, link to repo)
- Mantis logs every public response Raffa makes; pattern-match against the audit-our-own-audit protocol — if a critic alleges another bug we missed, Meerkat files the issue immediately on `Raffa-jarrl/Lictor-AI` with the right label
- Pre-staged response to "but did you actually run it" — link to the GitHub commits where the check definitions got updated. Receipts.

**Post-publish (within 7 days):**
- Update `accuracy/2026-08.md` with the 5 findings + the fix timelines
- Add a callout on the GitHub repo's README linking to this writeup as the canonical answer to "is Lictor trustworthy"
- File the bug bounty payment to the private beta tester who caught Finding #5 ($100 baseline per the protocol; confirm tier with the tester's consent)
- Mantis schedules a 30-day retro: did this post move the needle on stars, newsletter subs, design-partner installs? If yes, the format ships forever. If no, the next pre-launch transparency piece gets a different shape.
