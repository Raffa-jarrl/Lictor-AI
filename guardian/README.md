# Lictor Guardian

> Hosted enterprise platform. Real-time AI security monitoring across an organization. SOC 2 / GDPR / EU AI Act reporting. Incident response.

## Status

Placeholder. Lands in **Phase 3** (weeks 9–12 of the build plan).

## What Guardian is

The third tier of the Lictor suite. Where Shield is consumer-side and Sentinel runs in-process inside developer applications, **Guardian is the hosted service that aggregates Sentinel telemetry across an entire organization** and turns it into the artifacts an enterprise actually needs to operate AI in production:

- **Real-time incident view** — every prompt-injection attempt, every blocked tool call, every flagged AI output across every service
- **Audit log export** — SOC 2 Type II auditors increasingly require logs of AI agent activity. Guardian exports them in standard formats.
- **Compliance report templates** — pre-built templates for SOC 2, GDPR Art. 32, HIPAA, EU AI Act
- **Alerting** — Slack / email / PagerDuty for security incidents
- **SSO/SAML** — enterprise identity from day 1
- **Support SLAs** — what enterprise contracts are actually paying for

## Planned shape

- Next.js dashboard
- Postgres + Redis backend (Node.js / TypeScript)
- Receives ingest from `@lictor/sentinel` clients via a write-only API
- Multi-tenant, single-tenant deployment available for FedRAMP/HIPAA-heavy customers (Year 2)

## Pricing (planned)

| Tier | Price | Audience |
|---|---|---|
| **Self-Serve** | $999/mo per org | SMB, mid-market |
| **Enterprise** | $50K–$500K / year | Custom; SOC 2, SAML, dedicated CSM |

## License

**Source-available, NOT MIT.** The Guardian code lives in this repo for transparency, but is licensed for hosted use through lictor.ai only — not for self-hosting, redistribution, or production deployment elsewhere. See `LICENSE` (root).

This is the same model used by Sentry and Posthog: open monitoring SDKs (Sentinel here), source-available hosted product (Guardian here). The wedge is the suite + the brand, not source-code restriction.
