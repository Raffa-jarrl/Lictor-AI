# Lictor Domain Guard

> **Part of [Lictor for Business](../README.md#-lictor-for-business--secure-the-company--202627-roadmap).** Identity & Active Directory posture for SMBs — the security a 250-person company needs but can't staff a team for.
>
> **Status: 🗺️ roadmap (2026–27).** Spec only — no code here yet. Gated on the AI pillar's Oct 6 launch landing first.

## What it is

Most SMBs run Microsoft 365 / Entra ID or a small on-prem Active Directory, and nobody is watching it. They're priced out of Tenable / CrowdStrike Identity / Silverfort, and BloodHound is a pentester's tool, not an owner's. Domain Guard is the **"is my identity layer a mess?"** check — deployed on a domain-joined machine, run on a schedule, reported in plain English.

It's the defensive, SMB-priced answer to the identity questions that actually get companies breached.

## MVP scope (v0.1)

- **Stale-password audit** — accounts that haven't rotated in N days; never-expire flags
- **Privileged-account inventory** — who's in Domain Admins / Enterprise Admins / Schema Admins, and when they last logged in
- **Over-privileged service accounts** — SPN-bearing accounts, age, permission scope (Kerberoasting candidates)
- **Open-share detection** — SMB shares readable by Everyone / Authenticated Users, flagged for sensitive content
- **MFA-gap report** — admin accounts without MFA enforced
- **Compliance mapping** — each finding mapped to a SOC 2 / ISO 27001 / HIPAA control

## How it fits the suite

- Reports into **[Guardian](../guardian/)** like every other product — one audit trail, one dashboard.
- Emits the shared **AUDIT.json** format (see [`core/`](../core/)).
- Where **Airlock** guards *what an AI agent does at runtime*, Domain Guard answers *is the identity ground it stands on sound* — the human + machine accounts around it.

## Deliberately NOT in scope

- No password **cracking** (dual-use; we decline cleanly).
- No live exploitation / lateral-movement *execution* — detect-and-report only.
- Not an EDR/ITDR. v0.1 is posture audit; streaming behavioral detection (ITDR) is a far-future bet, not a v0.1 promise.

## Build notes

Likely a small cross-platform agent (Rust, reusing [`core/`](../core/)) that reads AD/Entra via LDAP / Microsoft Graph with read-only delegated creds, plus a one-line installer for a domain-joined box. Effort: ~1–2 engineers × 4 months. Do **not** start before the AI pillar ships and has paying Teams customers.
