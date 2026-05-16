# Getting help with Lictor

> Lictor is open source. The support model is community-first + maintainer-second. We respond to issues honestly and openly. We never have a "premium support" tier that gates real answers.

## Where to get help

| You want to… | Best path |
|---|---|
| Report a bug | [GitHub issue](https://github.com/Raffa-jarrl/Lictor-AI/issues/new?template=bug.md) |
| Tell us a finding Lictor missed (false-negative) | [GitHub issue with `false-negative` label](https://github.com/Raffa-jarrl/Lictor-AI/issues/new?template=false-negative.md) — these are our highest-value reports |
| Tell us a finding Lictor got wrong (false-positive) | [GitHub issue with `false-positive` label](https://github.com/Raffa-jarrl/Lictor-AI/issues/new?template=false-positive.md) |
| Tell us a finding sounded too jargony | [GitHub issue with `voice-bug` label](https://github.com/Raffa-jarrl/Lictor-AI/issues/new?template=voice-bug.md) — voice is the product |
| Request a feature or new pattern | [GitHub issue with `feature-request` or `pattern-request`](https://github.com/Raffa-jarrl/Lictor-AI/issues/new/choose) |
| Ask "how do I…?" | [GitHub Discussions](https://github.com/Raffa-jarrl/Lictor-AI/discussions) (or the Lictor Discord if you've already joined) |
| Ask about a specific Lictor finding | Use the `/lictor-explain` skill in Claude Code — it's the official explanation channel |
| Report a security issue in Lictor itself | Email `security@lictorai.com` — see [SECURITY.md](SECURITY.md) for our policy |
| Discuss strategic partnership | Email `hello@lictorai.com` |
| Press inquiry | Email `press@lictorai.com` (live by Sep 2026) |
| Compliance / vendor risk questionnaire | Email `compliance@lictorai.com` |

## Response times we aim for

These are aspirations, not contracts. We're a small team. We answer in good faith.

| Type | Target |
|---|---|
| Security disclosure | 48 hours (acknowledgment); see [SECURITY.md](SECURITY.md) for the full SLA |
| GitHub issue (bug / FP / FN / voice-bug) | 4 hours (auto-acknowledgment from the Meerkat agent), 48 hours (real triage), 7 days (proposed fix or honest "won't fix and why") |
| GitHub Discussion question | Best-effort — usually within a few days |
| Email to `hello@` / `press@` | 48–72 hours |
| Pull Request | First review within 7 days; merge cadence depends on size + clarity |

If you don't hear back in 2× the target, ping us by mentioning `@lictor-maintainers` on the original issue. We're a small team — sometimes things slip.

## What we'll never do

- Charge for support of the OSS core
- Gate documentation behind a paywall
- Auto-close stale issues without an honest read
- Respond to issues with "use the docs" — if the docs are unclear, that's our bug
- Make you sign an NDA to file a security finding
- Penalize users who report false-positives (those are valuable signals, not noise)

## What you can do to help us help you

When filing an issue:
- Tell us which Lictor product (skill / Shield / Sentinel / Guardian / Studio)
- Tell us which platform the target app was on (Lovable / Bolt / v0 / Cursor / Replit / custom)
- Paste the actual finding output (or the absence of a finding)
- Tell us what you expected
- If it's reproducible, give us the smallest possible repro

Vague reports are hard to action. Specific reports get fixed.

## Paid offerings (when those exist)

Lictor for Teams launches December 15, 2026 at $19/mo flat-rate (unlimited seats). That tier includes:
- Priority issue triage (24-hour acknowledgment)
- Email support for integration questions
- A Slack channel with maintainers (small team scale only)

Audit-as-a-Service (Q1 2027) and Enterprise (Q2 2027) include their own support contracts.

The OSS core is always free. Paid tiers don't gate features the OSS users need — they add value on top.

## How we communicate with the community

| Channel | Update frequency | Purpose |
|---|---|---|
| Weekly newsletter | Fridays | Teardown recap + agent crew updates + product news |
| `lictorai.com/teardowns` | Tuesdays | Weekly audit teardown of a real vibe-coded app |
| `lictorai.com/changelog` | Per release | What shipped in each version |
| GitHub Discussions | As things happen | Major decisions, roadmap updates, RFCs |
| Twitter / X | Daily | Real-time updates, teardown announcements |
| Discord (joining soon) | Real-time | Community support + casual conversation |

## The honest version

Lictor is built by one cybersecurity engineer + a crew of AI agents. We aim to be the most-responsive OSS security project in the AI tooling space. We will sometimes fail at that. When we do, we say so on the issue.

If something about the support experience disappoints you, file an issue with the `concerns` label. We respond to every one.
