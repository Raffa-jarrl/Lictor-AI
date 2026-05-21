# Intigriti submission template (Raven uses this)

## Form fields Raven must populate

| Field | Where it comes from |
|---|---|
| **Asset URL / Endpoint** | finding.program.scope_match (must match scope dropdown) |
| **Type / Category** | finding.class → Intigriti category mapping |
| **Severity** | finding.severity.band (Low / Medium / High / Critical) |
| **CWE** | finding.class → CWE mapping |
| **CVSS Vector** | finding.severity.cvss (CVSS:3.1 vector format) |
| **Title** | Raven generates ≤150 chars |
| **Description** | Body of this template |

## Intigriti category mapping

- `Information Disclosure > Sensitive Data Exposure` — GraphQL introspection, cloud-blob, exposed-file, credential-leak
- `Cross-Origin Resource Sharing (CORS) > Insecure Configuration` — CORS issues
- `Subdomain Takeover` — subdomain takeover
- `Server Security Misconfiguration` — generic catch-all

## CWE quick reference

| Finding class | CWE |
|---|---|
| CORS misconfig | CWE-942 + CWE-352 |
| Subdomain takeover | CWE-1281 + CWE-350 |
| GraphQL introspection | CWE-200 |
| Sourcemap | CWE-200 + CWE-538 |
| Cloud-blob | CWE-200 |
| Exposed .env | CWE-200 + CWE-552 |

## Description body template

```markdown
## Summary

{2-4 sentence summary, slightly more formal English than H1/BC — Intigriti's European triagers appreciate it}

## Steps to reproduce

1. {first step — exact command with full syntax}
2. {expected output / actual output}
3. {optional confirmation step}

## Impact

{Specific impact scenarios — Intigriti triagers reward CHAINED impact (this enables that, which enables that). State the chain explicitly.}

- {direct impact 1}
- {chain step → enables additional impact 2}
- {scope of affected users / data}

## Remediation

{Numbered specific fixes}

1. {fix 1 — specific config / code}
2. {fix 2}
3. {defense in depth / audit}

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security scanner (Apache 2.0).

## Note on scope

Per the {program-name} Intigriti program scope:
  • `{asset}` is listed with impact: {Tier-N / max_severity}
{If multiple assets affected, list each separately}

The reported endpoint is a direct match for the scope item.

## References

- {standards link}
- {OWASP cheat sheet if applicable}

---

Ethical-disclosure note: I have NOT {specific verb}. The exploitation pattern is described to illustrate impact, not executed. All probes used neutral test origins (`attacker.example.com`) without credentials.
```

## Submission URL pattern

`https://app.intigriti.com/programs/{org}/{program-slug}/detail` → click "Submit a vulnerability"
