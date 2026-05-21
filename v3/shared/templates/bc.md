# Bugcrowd submission template (Raven uses this)

## Form fields Raven must populate

| Field | Where it comes from |
|---|---|
| **Target** | finding.program.scope_match (dropdown) |
| **VRT Category** | finding.class → Bugcrowd VRT mapping (see below) |
| **Severity / Priority** | CVSS → P1-P5 mapping (see below) |
| **Title** | Raven generates ≤120 chars |
| **Reproducibility** | "Always" (unless explicitly intermittent) |
| **Description** | The body of this template, filled in |

## Bugcrowd VRT mapping

Bugcrowd uses VRT (Vulnerability Rating Taxonomy):
- `server_security_misconfiguration.cors.misconfig` — CORS issues
- `external_behavior.subdomain_takeover` — subdomain takeover
- `server_security_misconfiguration.graphql.introspection` — GraphQL introspection
- `server_security_misconfiguration.source_map_exposure` — sourcemap
- `sensitive_data_exposure.cloud_storage.publicly_listable` — cloud-blob
- `sensitive_data_exposure.code_disclosure.dev_artifacts` — exposed .git/.env

## CVSS → Bugcrowd Priority

| CVSS Score | Bugcrowd Priority |
|---|---|
| 9.0-10.0 | P1 |
| 7.0-8.9 | P2 |
| 4.0-6.9 | P3 |
| 0.1-3.9 | P4 |
| Info | P5 |

## Description body template

```markdown
## Summary

{2-4 sentence summary}

## Steps to reproduce

1. {first step — exact command}
2. {expected output / actual output}
3. {optional confirmation}

## Impact

{Bugcrowd values business impact phrased in terms of harm:}
- {what specifically can an attacker do}
- {who is affected / how many users}
- {what data is at risk}

## Remediation

{Numbered specific fixes}

1. {fix 1}
2. {fix 2}
3. {audit recommendations}

## References

- {standards link}
- {VRT taxonomy reference}

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security scanner (Apache 2.0).

## Note on scope

Per the {program-name} Bugcrowd program scope, `{asset}` is listed as in-scope under the {scope category}. The reported {hostname/endpoint} is a direct match.

---

Ethical-disclosure note: I have NOT {specific verb}. The exploitation pattern is described to illustrate impact, not executed. All probes used neutral test origins.
```

## Submission URL pattern

`https://bugcrowd.com/{program-slug}/submissions/new`
