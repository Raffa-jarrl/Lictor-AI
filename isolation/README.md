<p align="center">
  <a href="https://lictor-ai.com"><img src="https://raw.githubusercontent.com/Raffa-jarrl/Lictor-AI/main/brand/lictor-badge-256.png" alt="Lictor AI" width="120"></a>
</p>

# Lictor Isolation — the red/black AI sandbox

> **Part of [Lictor for Business](../README.md#-lictor-for-business--secure-the-company--202627-roadmap).** A pre-isolated machine to run and test AI agents *off* your real network — no environment-building required.
>
> **Status: 🗺️ roadmap (2026–27).** Spec only — no code here yet. The boldest and heaviest build in the suite (it's an appliance/VM image, not just a package).

## The problem

The #1 reason SMBs won't adopt AI agents: *"I'm not letting that thing near production."* They're right to be scared — a hijacked agent (promptware) can read the prod DB, exfiltrate customer data, or `rm -rf` something. But the honest fix — stand up a separate, network-isolated test environment — is weeks of work an SMB can't do.

**Isolation gives them that environment as a turnkey box.**

## Red / black, explained

Borrowed from signals security (TEMPEST), where "red" carries sensitive plaintext and "black" carries safe/encrypted traffic, and the two are physically separated:

- **🔴 Red zone** — the AI sandbox. Assume the agent is compromised. It runs here against **synthetic / test data**, on a segregated network segment with an egress allowlist.
- **⚫ Black zone** — your real business network, identities, and prod data. The agent can never reach it.

The product *is* the boundary: enough isolation that a hijacked agent can't hurt you, enough access that the agent is still useful. Drawing that line automatically — so the SMB doesn't have to — is the whole value.

## MVP shape (v0.1)

- A **VM image / appliance config** (e.g. a hardened Linux VM, or a cheap dedicated mini-PC recipe) that boots into the red zone pre-configured.
- **[Airlock](../airlock/) baked in, in enforce mode** — every shell + MCP action the agent takes is brokered and the dangerous ones blocked, with the full audit trail.
- **Synthetic-data seeding** — realistic-but-fake customers / transactions / tickets so the agent has something to work on without touching real PII.
- **Egress allowlist** — the red zone can reach the model provider and nothing else by default.
- **One-page report** into **[Guardian](../guardian/)**: "here's everything the AI did in the sandbox this week, here's what we blocked" — the artifact you show your auditor.

## How it fits the suite

This is where the pillars converge: **Airlock** (action enforcement) + **Guardian** (audit) + synthetic data, packaged as a physical/virtual safe room. It's the productized answer to the fear the whole **Lictor for AI** pillar addresses piecemeal — for the customer who wants a box, not an SDK.

## Build notes

Heaviest lift in the portfolio: it's infra (VM image, network config, provisioning) more than application code. Sequence it **after** Airlock v2 (enforce) is battle-tested on real installs, so the enforce ruleset is derived from observed data. Likely a Year-2 flagship.
