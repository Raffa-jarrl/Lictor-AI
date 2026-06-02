# Lictor AI Sandbox — Business Model

**Product:** "AI Sandbox" = **Airlock** (free, self-install agent) + **Guardian**
(paid cloud control plane). The agent contains what AI does on each machine; the
control plane is where teams pay to see and govern it across a fleet.

> The flagship revenue product. Timing (2026: everyone's deploying AI agents and
> terrified they'll touch prod), recurring revenue, **zero human per customer**.

---

## The model: open-core (free agent, paid control plane)

This is how a free OSS tool becomes a business — the same model as GitLab,
HashiCorp, Sentry, Grafana.

- **Free forever (Airlock OSS, Apache-2.0):** the local agent. Observe + enforce,
  plain-English audit log, all five rule classes, runs on the developer's machine.
  *This is the funnel, not the product.* It spreads, it's trusted, it costs us nothing.
- **Paid (Guardian cloud):** the moment a *team* needs to see all their agents in
  one place — fleet dashboard, alerts, retention, compliance reports — they pay.
  Airlock already ships telemetry to Guardian (`shipToGuardian` — built + tested).
  The technical funnel exists; this doc defines the commercial one.

**Why this works:** a solo dev runs free Airlock locally. The day their company
has 5+ people using AI agents and a CISO/auditor asks "prove AI didn't touch
prod," the local logs aren't enough — they upgrade to Guardian. The free tool
*creates* the paid need.

---

## Pricing tiers

| Tier | Who | Price | What they get |
|---|---|---|---|
| **Free** | Solo dev / OSS | **$0** | Airlock agent: observe+enforce, local audit log, all rules. Self-host. |
| **Team** | 5–50 person co. | **~$25 / agent-seat / mo** | Guardian cloud: fleet dashboard, plain-English incident feed, alerting, 90-day retention, multi-dev view |
| **Business** | regulated SMB | **~$1,500 / mo** (up to 50 seats) | + **compliance reports** (SOC 2 / ISO 27001 / Israeli Privacy Law), SSO, premium policy packs, audit export, SLA |
| **Enterprise** | larger / on-prem | **custom** | self-hosted Guardian, custom policies, support, MSSP/white-label |

Anchors: dev-tool seats run $10–50/mo (Copilot $19, security tools $20–50). The
**compliance report** is what unlocks the Business tier — that's the artifact a
regulated company *must* have and will pay for.

---

## Why it's a better business than the pentest

| | AI Sandbox | Automated Pentest |
|---|---|---|
| Revenue shape | **Recurring** (runtime, per-seat) | One-time-ish |
| Human in delivery | **None** | Some (the 20%) |
| Market | **New, forming now** | Crowded (Pentera, Horizon3) |
| Core already built | **Airlock ✓ + Guardian ✓** | lan-pentest v0.1 |
| Trigger to buy | "prove AI didn't touch prod" (every CISO, now) | annual compliance |

---

## Go-to-market

1. **Distribution (free):** ship Airlock to npm; integrate with the AI runtimes devs
   already use (Cursor, Claude Code, **OpenClaw**, MCP servers). Every install is a
   future Guardian lead.
2. **The trigger:** when an org grows past local logs, the compliance/fleet need
   converts them to Guardian.
3. **Israel first:** SMBs adopting AI with no security team — the exact buyer. Pair
   with the WAN findings (the 667) as the door-opener: "you have external exposure
   *and* unguarded AI agents — here's both."
4. **Larger firms:** OEM/white-label Guardian for MSSPs who manage many clients'
   AI fleets.

---

## What's left to make it sellable (build order)

1. **Publish Airlock to npm** — it builds + passes 23 tests; flip alpha → public so
   `npm i -g @lictor/airlock` actually works. *(Removes the "build from source" blocker.)*
2. **Guardian: the paid surface** — fleet dashboard + the compliance-report generator
   (the Business-tier unlock). Guardian core is already booted (PG + ingest + export).
3. **Billing** — Stripe subscription + license key that gates Guardian cloud features.
4. **Runtime integrations** — one-line wraps for Cursor / Claude Code / OpenClaw so
   install is 60 seconds.
5. **The landing page** — "Let your team use AI without it nuking prod. Free agent,
   paid fleet view." Free download + Guardian upgrade CTA.

_The product is built. This turns it into a business: free agent for reach, Guardian
subscription for revenue, compliance report as the thing regulated SMBs must buy._
