# AUDIT.json — proposed community standard for security tool output

> **Status:** Draft v0.1 — proposal, not yet adopted
> **Authors:** Lictor AI (initial proposal)
> **Co-author invitations open:** Snyk, Aikido, Semgrep, Trivy, VibeEval, Symbioticsec, anyone running a security scanner
> **License:** CC0 — the spec belongs to nobody

---

## Why this exists

Every security tool ships its findings in its own format. Snyk's JSON looks nothing like Semgrep's, which looks nothing like Trivy's, which looks nothing like npm audit's. A developer running 3 tools gets 3 incompatible outputs and 3 different mental models.

This is the format every tool could emit alongside its native format. Tools that emit `AUDIT.json` interoperate freely:

- Dashboards ingest findings from any tool
- IDE plugins render any tool's output in the same UI
- AI translators (like Lictor's `lictor-explain`) speak one input format
- Aggregators can deduplicate findings across tools
- Compliance exporters can pull from the same shape regardless of source

This is **SARIF for developers** — without the IBM-y enterprise tooling overhead.

---

## The schema (v0.1)

```json
{
  "spec_version": "0.1",
  "tool": {
    "name": "lictor",
    "version": "0.1.0",
    "vendor": "lictor-ai.com"
  },
  "target": {
    "type": "repository",
    "url_or_path": "/Users/dor/projects/my-lovable-app",
    "platform_fingerprint": "lovable",
    "platform_confidence": 0.95
  },
  "audit": {
    "started": "2026-05-15T14:30:00Z",
    "completed": "2026-05-15T14:30:42Z",
    "duration_ms": 42183,
    "checks_run": 7
  },
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 12,
    "info": 3,
    "total": 30
  },
  "findings": [
    {
      "id": "L-2026-0001",
      "severity": "critical",
      "category": "secrets",
      "title": "Supabase service key exposed in client JS bundle",
      "summary": "The SUPABASE_SERVICE_ROLE_KEY is bundled into src/lib/db.ts and shipped to every visitor's browser. Anyone with the URL has full database write access.",
      "evidence": {
        "file_path": "src/lib/db.ts",
        "line": 12,
        "code_snippet": "const supabase = createClient(URL, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...')",
        "url": null
      },
      "fix": {
        "summary": "Move to a server-only route, never bundle in client",
        "diff_or_snippet": "// Move db.ts to app/api/_internal/db.ts so Next.js bundler keeps it server-only.",
        "rotated_secrets_needed": [
          "SUPABASE_SERVICE_ROLE_KEY"
        ]
      },
      "agent": "radar",
      "agent_confidence": 0.98,
      "references": [
        "https://lictor-ai.com/checks/L-secrets-1"
      ],
      "cwe": [
        "CWE-200",
        "CWE-798"
      ]
    }
  ],
  "agent_attributions": [
    {
      "agent": "radar",
      "found_count": 4,
      "scored_count": 0,
      "confidence_avg": 0.92
    },
    {
      "agent": "sieve",
      "found_count": 0,
      "scored_count": 30,
      "confidence_avg": null
    }
  ],
  "notes": []
}
```

---

## Field reference

### Top level

- `spec_version` (required) — semver string. Tools must declare which version they emit.
- `tool` (required) — what produced this report
- `target` (required) — what was audited
- `audit` (required) — timing + scale metadata
- `summary` (required) — counts of findings by severity (must reconcile with `findings.length`)
- `findings` (required) — array of finding objects (may be empty)
- `agent_attributions` (optional) — which AI agents / rules / checks contributed (Lictor uses this; rule-based scanners can leave empty)
- `notes` (optional) — free-text annotations from the tool

### `target.type`

One of:
- `repository` — local or remote source code
- `deployed-site` — a live URL (Shield-style audit)
- `container-image` — a Docker / OCI image
- `package` — a single dependency tarball
- `binary` — a compiled artifact
- `iac` — Infrastructure as Code template (Terraform, CloudFormation, etc.)

### `target.platform_fingerprint`

For AI-built apps specifically, an optional identifier of the build platform:
- `lovable`
- `bolt`
- `v0`
- `cursor`
- `replit`
- `claude-code`
- `windsurf`
- `custom` — manually written or non-AI-built

This field lets downstream tools apply platform-specific rules. Optional but encouraged.

### `findings[].severity`

The 5-level ladder:
- `critical` — immediate exploitation possible, real-world impact
- `high` — exploitable with effort, real impact
- `medium` — exploitable in specific conditions, moderate impact
- `low` — unlikely or low-impact
- `info` — informational only, no action needed

This deliberately matches Lictor's UI ladder (🔴🟠🟡🔵⚪).

### `findings[].category`

Free-form but encouraged values (a reference vocabulary will ship in `vocabulary.json` v0.2):
- `secrets` — credentials in code
- `auth` — authentication / authorization issues
- `database` — direct DB exposure
- `rls` — row-level-security gaps
- `cors` — overly permissive cross-origin
- `prompt-injection` — LLM input vulnerabilities
- `pii-leak` — personal-data exposure
- `dependency` — known CVE in a dependency
- `iac-misconfig` — infrastructure misconfiguration
- `xss` — cross-site scripting
- `csrf` — cross-site request forgery
- `idor` — insecure direct object reference
- `supply-chain` — compromised upstream package
- `secret-in-llm-input` — secrets being passed to an LLM
- `data-exfiltration` — model output leaking sensitive data
- `other`

### `findings[].fix.rotated_secrets_needed`

If the fix involves rotating a credential, list the credential identifier(s) — this lets `/lictor-rotate` (or any other rotation tool) auto-generate the runbook.

---

## Validation

A conforming `AUDIT.json` document must:

1. Validate against the JSON Schema at `/standards/AUDIT.schema.json` (v0.1 in `/Users/raffa/Lictor/docs/standards/AUDIT.schema.json` — TODO: ship this file)
2. Be UTF-8 encoded
3. Use ISO 8601 timestamps with timezone offsets
4. Use semver for all version fields

A conforming **tool** must:

1. Emit `AUDIT.json` as an option (does not need to be the default)
2. Document which subset of fields it uses
3. Declare the spec version it conforms to

---

## How to adopt

If you're a security tool author wanting to emit `AUDIT.json`:

1. Add a `--format audit-json` or equivalent flag to your CLI
2. Document the field coverage in your README
3. Open a PR against this spec adding your tool to the **Adopters** list below
4. (Optional but encouraged) co-sign the spec by adding yourself to `co_authors.md`

If you're a consumer (dashboard, IDE plugin, AI translator):

1. Validate against the schema
2. Be permissive about optional fields
3. Cite the spec version you support
4. Open a PR adding yourself to the **Consumers** list below

---

## Adopters (waiting for first)

| Tool | Emits | Field coverage | Notes |
|---|---|---|---|
| Lictor | ✓ v0.1 | Full | Reference implementation |

## Consumers (waiting for first)

| Tool | Reads | Spec version | Notes |
|---|---|---|---|
| Lictor `/lictor-explain` skill | ✓ | v0.1 | Universal translator across tools that emit this |

---

## Why a vendor's spec is fine

You might reasonably ask: "Why should we adopt a spec proposed by Lictor instead of waiting for an industry consortium?"

Honest answer: **standards born in industry consortia take 5-10 years and end up adopted by 20% of tools.** Standards born from a working implementation and a community proposal — like JSON, like OpenAPI, like RSS — adopt faster because they prove they work first.

This spec is:
- **CC0** — Lictor claims no ownership; it belongs to nobody
- **Versioned** — breaking changes go in v0.2, etc.
- **Forkable** — fork the repo, propose your own version, may the best one win
- **Independent of Lictor's product** — your dashboard or IDE plugin or compliance tool can adopt this without depending on any Lictor code

If a better proposal emerges, we'll adopt it instead. The standard matters more than the authorship.

---

## Open questions for v0.2

These are flagged for discussion before v1.0:

1. **Should `severity` be a string or an int 0-4?** Tools like Trivy use CVSS scores (floats 0.0-10.0). Mapping to the 5-string ladder is lossy. Open issue.
2. **Should findings have a stable `fingerprint` field?** For dedup across tools. Requires defining the hash. Open issue.
3. **Should `agent_attributions` be required for AI-driven tools?** Probably yes. Currently optional.
4. **Should there be a `confidence` field per finding?** Some tools have it (Lictor), some don't (Trivy). Currently optional.
5. **How do we represent partial / incremental scans?** A scan that audited 3 of 100 files vs a scan that audited everything looks the same in this schema. Open issue.

File issues at github.com/Raffa-jarrl/Lictor-AI for any of these.

---

## Spec changes log

- **v0.1 (2026-05-15)** — initial proposal. Lictor reference implementation.

---

## Why this matters strategically

(For internal Lictor reference — not part of the public spec.)

Standards-ownership is one of the most durable moats in software. The companies that wrote OpenAPI, JSON Schema, Markdown, SARIF, and OAuth own influence in their categories *because* they shipped working specs early.

If Snyk / Aikido / Semgrep adopt `AUDIT.json`, Lictor becomes the implicit reference for AI-built app security output. If they don't, Lictor still benefits from being the early mover with the cleanest spec — and the spec lives on for community tools.

Either way, ship it.
