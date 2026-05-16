# Audit-our-own-audit protocol

> How Lictor handles community reports that we got something wrong.
> Status: live. This protocol runs forever.
> Owner: Mantis agent. Escalation owner: Raffa.
> Last updated: 2026-05-15

---

## 1. The strategic thesis

Snyk's roadmap is closed. Lictor's is open. That's not a tagline — it's the operating commitment that makes the rest of the brand legible. The same logic applies to mistakes. Every security tool gets findings wrong. Most hide it. Lictor publishes it.

The only people who can tell us where Lictor is wrong are the people running it on real code. A false-negative — Lictor missed a real bug — is the most valuable signal we will ever receive. A false-positive that burned a user's afternoon ranks second. Everything we learn about accuracy and rule gaps comes from these two flows. We are not smart enough to find them on our own.

Every honest acknowledgment of an error compounds trust. Every quiet silent-fix erodes it. Vibe-coders have been burned by enterprise vendors who claim 99% accuracy and ship marketing instead of fixes. Lictor's position only works if our error-handling is louder and more visible than our success-claims.

The promise is falsifiable: **we audit our audit, in public.** Every FP, FN, and voice-bug in the changelog. Every reporter credited (with consent). Every monthly accuracy delta published in a file in the repo.

If we ever start handling errors quietly, the brand is over. This protocol is the discipline that keeps the promise running when nobody's watching.

---

## 2. The three report types

### Type A — False positive (`false-positive` label)

Lictor flagged code as a finding; the user is confident the code is safe. The rule misfired.

> Example: Lictor flagged `process.env.STRIPE_SECRET_KEY` in a Next.js API route as "secret in code." The user points out Next.js API routes are server-only — the secret never reaches the client.

**Difference in handling:** The fix is almost always a rule tightening — an exclusion pattern, a context check, or a confidence threshold. Low-risk to fix, fast turnaround.

### Type B — False negative (`false-negative` label)

Lictor missed a real bug. The user found it themselves, sometimes after a real incident.

> Example: A user's Lovable app got breached. Attacker exploited an exposed Supabase Edge Function. Lictor's audit had run clean. The function pattern wasn't in any of Lictor's 7 checks.

**Difference in handling:** Highest-value report Lictor receives. Fix requires a new check, a regression test, and re-running the audit suite against the teardown corpus so the new rule doesn't introduce FPs elsewhere. Slower, more rigorous. May include a bug bounty payment.

### Type C — Voice-bug (`voice-bug` label)

The finding is correct, but the language is wrong — too jargony, too alarmist, too vague to act on.

> Example: Lictor said *"Insufficient input validation on /api/users endpoint"* instead of *"Anyone can pass ?role=admin to your /api/users endpoint and get admin access."*

**Difference in handling:** No detection-rule change. Lyrebird agent rewrites the finding text. Docs/skill PR, not a check change. Goes through Friday voice calibration.

All three types use the same intake flow. They diverge at the investigation step.

---

## 3. The intake flow

**Where reports land.** GitHub issues on `Raffa-jarrl/Lictor-AI`, using one of three labels: `false-positive`, `false-negative`, `voice-bug`. These labels are already documented in the public ROADMAP.

**The issue template asks for:**

1. The exact finding text Lictor produced (copy-paste from `SECURITY-AUDIT.md`)
2. The code involved — the snippet Lictor flagged (FP), or the bug Lictor missed (FN), or the finding that read badly (voice-bug)
3. What the user expected instead
4. Environment: target platform (Lovable / Bolt / v0 / Cursor / Replit / direct prompt), framework, Lictor version
5. Optional: a public-repo URL where the pattern can be reproduced

No CISSP gate. No NDA. No "are you sure?" friction. The template is the contract — fill it out, hit submit.

**First-response SLA.** Meerkat agent owns this.

- **Acknowledge within 4 hours.** Meerkat replies on the issue, confirms the report type, asks any clarifying questions, applies labels.
- **Triage to Mantis within 24 hours.** Meerkat tags the report with severity, agent-of-origin if known (which of the 11 agents produced the finding), target platform, and routes to Mantis agent's queue.
- **Escalate to Raffa within 48 hours** if the report is a critical false negative (see section 6) or a high-visibility critic post.

**Labels applied during triage:**

- One of: `false-positive`, `false-negative`, `voice-bug`
- Severity: `severity:critical`, `severity:high`, `severity:medium`, `severity:low`
- Agent-of-origin: `agent:radar`, `agent:probe`, `agent:quill`, etc. — whichever produced the finding
- Platform: `platform:lovable`, `platform:bolt`, `platform:v0`, `platform:cursor`, `platform:replit`, `platform:other`

These labels feed the monthly accuracy report. They are not optional.

---

## 4. The investigation and fix flow

### For false positives

1. **Mantis agent reproduces locally.** Pulls the user's snippet (or repo), runs the audit, confirms the misfire.
2. **Identifies which check + which agent produced the finding.** Logs the agent-of-origin label if Meerkat didn't already.
3. **Determines the rule's actual intent vs the user's case.** Did the rule intend to catch this and the user is mistaken? Or did the rule overreach? The answer is in writing, on the issue.
4. **Proposes one of four fixes:**
   - Tighten the rule (narrow the pattern)
   - Add an exclusion (specific context where the rule should not fire)
   - Add a confidence threshold (downgrade severity to INFO when context is ambiguous)
   - Accept the rule as overly cautious and document the rationale on the issue
5. **Ships in a PR labeled `false-positive-fix-LXXXX`** (LXXXX = the finding ID format from the audit report).
6. **Reporter credit.** CHANGELOG entry: `Reported by @username on YYYY-MM-DD.` Only with consent — Meerkat asks during triage.

### For false negatives

1. **Mantis + Hawk collaborate.** The user has handed us real code that should have been caught. This is gold.
2. **Write a regression test** that fails today (because the rule doesn't exist) and will pass once the rule lands. Lives in `tests/regressions/false-negative-LXXXX.test.ts`.
3. **Write the new rule** (or extend an existing one) until the regression passes.
4. **Verify no new false positives.** Mongoose agent re-runs the full audit suite against the 30+ teardown corpus. Any new findings get human-reviewed before merge. This step is non-negotiable — a fix that catches one missed bug but starts flagging legitimate code in five other projects is a net loss.
5. **Ships in a PR labeled `false-negative-fix-LXXXX`.**
6. **Reporter credit + reward.** CHANGELOG mention. Public spotlight in the next weekly newsletter (with consent). For high-severity catches — patterns that were actively exploited in a real production incident — a bug bounty payment from the Lictor Foundation budget. **Tier suggestion (Raffa to confirm): $100 baseline, $500 for high-severity catches, $1,000 for critical catches tied to a real incident.** Paid via GitHub Sponsors or direct transfer. No invoice gymnastics.
7. **The pattern becomes a permanent check.** Once shipped, every future audit runs it.

### For voice-bugs

1. **Lyrebird agent rewrites the finding text.** Same finding ID, new copy.
2. **Ships in a PR labeled `voice-bug-fix-LXXXX`.** Touches the check file's report-text template, not the detection logic.
3. **Goes through Friday calibration.** Mantis reviews the rewrite on the next weekly review pass — same loop the rest of Lictor's voice work goes through. If Mantis flags drift, the rewrite gets revised before shipping.
4. **Reporter credit** in the CHANGELOG.

---

## 5. The transparency communication

**Where the public sees this work.**

- **CHANGELOG entries.** Every fix — FP, FN, voice-bug — goes in the changelog with the reporter credited (with consent) and a one-line description of what changed. No exceptions, no batched omissions.
- **Weekly newsletter.** Lyrebird's user-spotlight section can feature a specific fix: *"This week, @username caught a Stripe webhook signature check we missed. Here's the test that now catches it."* One spotlight per newsletter when there's a worthy one. Don't manufacture them.
- **The `lictorai.com/audit-report` page.** A public dashboard rebuilt monthly: open issues, fixed-this-month count, new patterns added, median time-to-fix. Generated from labels + CHANGELOG, not hand-maintained.
- **Twitter.** Explicit "we got this wrong, here's what we shipped to fix it" posts. Not buried in a thread, not framed as marketing. Surfaced. Pinned for a day when the fix is meaningful.
- **The accuracy claim.** Lictor never claims "100% accurate," "99% accurate," or any unfalsifiable number. The standing claim is: *"We get things wrong sometimes. Here's how we fix it. Here's the public log of every error and its resolution."* That sentence is on the landing page, in the README, and in the issue template.

**The strategic principle: errors are content.** Every FP is a teaching moment for the next user. Every FN becomes a new check that protects everyone. Every voice-bug makes the next thousand reports clearer. A security tool that publishes its mistakes louder than its wins is doing something incumbents structurally cannot do. That asymmetry is the moat.

---

## 6. Escalation thresholds

Most reports are routine: a misfire, a missed pattern, a clumsy sentence. These run through Mantis's queue and ship in days. A small number of reports are not routine. These get Raffa.

- **Critical false negative.** Lictor missed a vulnerability that was actively exploited in a real production incident. Escalation: Raffa responds personally within 24 hours. Public security advisory published in the GitHub Security tab. Transparent post-mortem published within 7 days — what we missed, why we missed it, what we shipped to catch it, what we changed in our process. **Raffa to confirm:** is 7 days the right post-mortem SLA, or should it be 14?
- **Pattern of false positives in one category.** More than 3 false-positive reports against the same rule within 30 days. Escalation: that rule is auto-disabled until fixed. Users get notified via the next newsletter and a pinned issue. Root cause posted on the issue thread. **Raffa to confirm:** is the threshold 3 in 30 days, or should it be more sensitive (2 in 14 days) given low total volume in year one?
- **A critic posts publicly without filing a report.** Someone on Twitter / HN / LinkedIn calls out Lictor's accuracy without opening a GitHub issue. Meerkat escalates to Raffa. Raffa responds publicly, on-thread: thank them for the signal, ask for the specific case, invite a GitHub issue, link to this protocol. Never get defensive. Never argue accuracy in a quote-tweet. Move the conversation to where fixes happen.

---

## 7. Metrics that matter

Tracked monthly. Published in `accuracy/YYYY-MM.md` in the public repo. Generated from issue labels and CHANGELOG entries — not hand-curated.

- Total findings shipped across all audits (volume baseline)
- Total FP reports received
- Total FN reports received
- Median time-to-fix, FP and FN tracked separately
- New patterns added per month (from FN fixes)
- **Audit accuracy delta** — change in FP rate quarter-over-quarter. Public and falsifiable. If FP rate is rising, we say so.

These files compound into a public record. Anyone running Lictor a year from now can see whether the protocol actually ran or quietly went dark.

---

## 8. What we explicitly don't do

- **We don't argue with users about whether their report is valid.** We investigate and respond with findings. Not opinions, not credentials checks.
- **We don't silent-fix.** Every fix is in the CHANGELOG. If a fix slipped in without an entry, that's a bug in the protocol — file an issue.
- **We don't make accuracy claims we can't substantiate.** *"Lictor catches 99% of bugs"* is unprovable and we will never say it. *"Lictor caught X bugs across Y audits in April 2026, of which Z were verified as real"* is provable and we will publish it.
- **We don't penalize false-positive reporters.** Some users report 10+ FPs over a month. That's a feature. Those users are doing free QA on rule quality. Some of them deserve maintainer status; offer it.
- **We don't gatekeep.** No CISSP, no NDA, no minimum-experience filter on who can file a report. The vibe-coder who built a Lovable app on Saturday is the user this tool exists for. Their report is as valid as anyone else's.

---

## Notes for Raffa

This protocol is ready to run from launch day. Three calls before it goes live:

1. **Bug bounty tiers.** Suggested $100 / $500 / $1,000 — confirm or adjust before the first FN ships.
2. **Critical FN post-mortem SLA.** Suggested 7 days — confirm or adjust to 14.
3. **FP pattern threshold for auto-disable.** Suggested 3 in 30 days — confirm or tighten to 2 in 14.

Everything else is mechanical and runs without further input.
