# Lictor — Compliance & Regulatory Posture

> Where Lictor fits in the SOC 2 / GDPR / EU AI Act landscape. Pre-built answers to the questions that show up in enterprise RFPs.
>
> **Status:** Phase 1 reference. The lictorai.com/compliance landing page (W19) is generated from this doc. When a Zapier-tier procurement team asks "how does Lictor satisfy our [framework] requirements," this is what we hand them.

---

## What this document is — and isn't

**Is:** a reference for how Lictor's products map onto the controls and articles enterprise customers need to satisfy. Authored by a cybersecurity engineer with 20 years of audit and advisory experience.

**Is NOT:** a claim that Lictor itself is SOC 2 Type II certified, GDPR-compliant on your behalf, or pre-approved by any regulator. Compliance is a property of an entire system, not a single tool. Lictor is a *control* in your compliance program, not the program itself.

If you need SOC 2 Type II attestation for Lictor as a vendor: that's planned for Q2 2027 (see [`STRATEGY.md`](../docs/projects/lictor/STRATEGY.md) Phase 4 milestone in the GenerationAI repo). Until then, vendor risk should be assessed against the public source code, this document, and our public Trust Center page (when published).

---

## SOC 2 Trust Services Criteria

Lictor's products contribute evidence to the following [SOC 2 TSC](https://www.aicpa.org/) Common Criteria categories. The mapping below is what to put in your control matrix.

### CC6 — Logical and Physical Access Controls

| Control | How Lictor contributes |
|---|---|
| **CC6.1** Logical access controls restrict access to authorized users | Sentinel SDK enforces input-side access controls on prompts; Guardian's audit log records every access to incident data. |
| **CC6.6** Vulnerabilities are identified and addressed | Lictor Shield audits AI-built apps in real time and flags secrets / database / auth / CORS / AI-agent-surface issues. Findings ship with severity + remediation. |
| **CC6.7** Restricts and monitors transmission of data | Sentinel pre-flight checks block secrets-in-input from being transmitted to AI providers; post-flight checks block PII-leak in model outputs. |
| **CC6.8** Prevents or detects malicious software | Sentinel detects prompt-injection patterns at the AI agent boundary. Shield detects insecure AI-built sites users would otherwise trust. |

### CC7 — System Operations

| Control | How Lictor contributes |
|---|---|
| **CC7.1** Detects security events | Sentinel emits an `IncidentEvent` for every check trip. Guardian aggregates these per-org. |
| **CC7.2** Analyzes detected events for impact | Guardian's incident timeline provides chronological grouping; severity ranking is per `lictor-core` rules. |
| **CC7.3** Responds to identified events | Sentinel `onTrip: 'block'` action provides automated response (request termination); Guardian Slack webhook provides notification routing. |
| **CC7.4** Recovers from incidents | Sentinel's response is read-only with respect to user data; recovery is a function of the wrapping application, not Lictor. |
| **CC7.5** Communicates incidents | Guardian's audit log export (CSV/JSON) provides the evidence for incident communications. |

### CC8 — Change Management

The Lictor source code is open (Apache 2.0 for OSS components; source-available for Guardian). Every change is tracked in Git with cryptographic signatures from CI. Customers self-verifying our change controls should reference our public commit history at [github.com/Raffa-jarrl/Lictor-AI](https://github.com/Raffa-jarrl/Lictor-AI).

### CC9 — Risk Mitigation

Sentinel + Shield + Guardian are *defensive* controls. They do not create new attack surface (Sentinel is an in-process middleware; Shield is a read-only browser extension; Guardian is an isolated SaaS). The wire-format privacy invariants ([`docs/specs/wire-format.md`](./specs/wire-format.md) §4) ensure Lictor never accumulates the data it would need to be a high-value target itself.

---

## GDPR — Article 32 (Security of processing)

Article 32 requires data controllers and processors to implement *"appropriate technical and organisational measures to ensure a level of security appropriate to the risk."* Lictor's products map onto specific Article 32(1) measures:

### 32(1)(a) — Pseudonymisation and encryption

- **Sentinel never transmits raw user content to Guardian.** All telemetry uses 16-character SHA-256 fingerprints (`docs/specs/wire-format.md` §4). This is a strong form of pseudonymisation by construction.
- All Sentinel↔Guardian transit is HTTPS (TLS 1.2+).
- Guardian-hosted ingest tokens are stored bcrypted in the `magic_links` table; raw tokens never persist server-side.

### 32(1)(b) — Confidentiality, integrity, availability, resilience

- Confidentiality: bearer-token authentication on every ingest call; no cross-account read paths in Guardian's query layer.
- Integrity: append-only audit log enforced via Postgres trigger (`migrations/0001_initial.sql` lines 102–115). UPDATE and DELETE on `audit_log` raise a SQL exception.
- Availability: Guardian is a stateless web layer over Postgres; failover is a database-level concern.
- Resilience: documented incident-response runbook (Phase 4 deliverable; tracked in `LAUNCH_PLAN.md`).

### 32(1)(c) — Restoration of availability

- Guardian's data model is fully reconstructable from Postgres dumps. Sentinel's events are append-only and idempotent on the wire (events have stable `ts` + `agent_id` + content, so retries don't double-count).

### 32(1)(d) — Regular testing

- Lictor's test suite covers the privacy invariants. The fingerprint round-trip is verified ([`sentinel/tests/wrap.test.ts`](../sentinel/tests/wrap.test.ts)). The wire-format schema is enforced in code ([`guardian/src/lib/wire-format.ts`](../guardian/src/lib/wire-format.ts)).
- Public CI runs the full test suite on every commit. Test failures block merges.

### 32(2) — Risks of accidental loss, alteration, disclosure

The wire-format privacy invariants make accidental disclosure of user content categorically impossible — the data Lictor collects cannot be reversed into the data it represents. This is design-level mitigation, not policy-level.

### Data subject rights (Articles 15–22)

Right to erasure is implemented via cascading foreign keys: deleting an account row removes every related row (incidents, audit_log, sessions, magic_links). One DELETE statement satisfies Article 17 for a Lictor account.

---

## EU AI Act — relevant articles

The [EU AI Act](https://artificialintelligenceact.eu/) is in phased enforcement through 2026–2027. Lictor's products are most relevant to providers and deployers of *high-risk* AI systems (Annex III categories) and to *general-purpose AI* providers.

### Article 9 — Risk management system

Article 9 requires high-risk AI providers to *"establish, implement, document and maintain a risk management system."* Lictor's role:

- **9(2)(a) Identification and analysis of known and reasonably foreseeable risks** — Sentinel's check catalog provides a starting taxonomy of AI-specific risks (prompt injection, data exfil, unsafe tool calls, PII leakage). Guardian's incident timeline tracks observed instances per deployment.
- **9(2)(b) Estimation and evaluation of risks** — Sentinel events carry severity (`critical`/`high`/`medium`/`low`/`info`); Guardian aggregates by severity for trend analysis.
- **9(2)(c) Evaluation of risks based on data from post-market monitoring** — Guardian *is* a post-market monitoring system. Audit log export satisfies the documentation requirement.
- **9(2)(d) Risk-management measures** — Sentinel's `onTrip: 'block'` and `'redact'` actions are technical risk-management measures applied at the runtime boundary.

### Article 12 — Record-keeping

Article 12 requires automatic logging of events relevant to the operation of high-risk AI systems. Guardian's incident store + audit_log together provide a *technical* record of the system's risk-relevant events. Retention is configurable per account.

### Article 14 — Human oversight

Sentinel's blocking and redaction modes are designed to provide *automated detection*, but the human-oversight requirement is a property of the deploying organization. Lictor enables — but does not satisfy — Article 14.

### Article 26 — Obligations of deployers

Deployers must *"monitor the operation of the high-risk AI system."* Guardian provides the monitoring substrate; the Slack webhook + audit log + per-incident drill-down provide the *practical* monitoring tools.

### Article 50 — Transparency obligations

For deployers using AI to interact with humans, Article 50 requires that humans be *"informed that they are interacting with an AI system."* Lictor Shield can detect AI-agent surfaces on websites and inform end-users; this is one of the few consumer-side products in the AI security category that addresses Article 50 directly.

---

## NIST AI RMF — alignment

The [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) maps cleanly onto Lictor's product surfaces:

| NIST AI RMF Function | Lictor product |
|---|---|
| **Govern** | Documentation: this file, our specs, our SLAs |
| **Map** | Sentinel's check catalog identifies AI-specific risk classes |
| **Measure** | Guardian's incident store quantifies instances per check, per agent, per time window |
| **Manage** | Sentinel's `onTrip` actions + Guardian's alerting close the loop |

---

## ISO/IEC 42001 (AI Management Systems)

ISO/IEC 42001 (published 2023) is the first AI-specific management-system standard. Lictor contributes evidence to the following clauses:

- **8.2 (Operational planning and control)** — Sentinel's runtime checks
- **8.3 (Risk treatment)** — Sentinel's blocking / redaction modes
- **9.1 (Monitoring, measurement, analysis)** — Guardian's dashboard
- **9.2 (Internal audit)** — Guardian's audit log export

ISO/IEC 42001 certification for the Lictor company itself is a Q3 2027 target, contingent on revenue.

---

## What Lictor itself does for compliance

We're a security company. Walking the talk:

- **Open source where it doesn't conflict with the business model.** Apache 2.0 on `core/`, `shield/`, `sentinel/`, `sentinel-py/`. The patent grant in Apache 2.0 is what enterprise legal teams want to see.
- **Source-available where the product IS the operations.** `guardian/` is published for review but licensed for hosted use only.
- **Privacy-by-design wire format.** No raw user content ever crosses the Sentinel→Guardian boundary; the architecture prevents data accumulation that would itself become a high-value target.
- **CI enforced on every commit.** `cargo fmt --check`, clippy with `-D warnings`, full test suite, both native and WASM targets. See `.github/workflows/ci.yml`.
- **Append-only audit logs.** Database triggers prevent tampering, even by a privileged operator.
- **Coordinated disclosure policy.** See `SECURITY.md`.

---

## Trust Center (planned, Q1 2027)

Once Guardian has paying customers, the public Trust Center at lictorai.com/trust will publish:

- Real-time uptime / SLA metrics
- Vendor list (sub-processors)
- SOC 2 Type II attestation report (under NDA)
- Pen-test results (under NDA)
- Security questionnaire (CAIQ) pre-filled

If you need any of the above for vendor risk review and Lictor doesn't yet have them: tell us. We prioritize Trust Center maturity by which deal it unblocks.

---

## Questions / contact

- Vendor risk reviews: `compliance@lictorai.com` (channel opens at launch)
- Security disclosures: `security@lictorai.com` (see [`SECURITY.md`](../SECURITY.md))
- Self-hosting requests for Guardian (regulated industries, sovereign cloud): `hello@lictorai.com`
