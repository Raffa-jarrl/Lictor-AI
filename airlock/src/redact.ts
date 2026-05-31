/**
 * Secret redaction for the audit trail.
 *
 * Airlock writes a plain-English log of what the AI did. That log must never
 * become a *new* place secrets leak — if the agent ran `export
 * STRIPE_KEY=sk_live_...`, the audit line should show that a key was set, not
 * the key itself.
 *
 * Policy mirrors the Lictor Submission Constitution R2: when a credential is
 * shown at all, show at most a short prefix (≤14 chars) followed by an
 * ellipsis. Most patterns here redact the *value* entirely and keep only the
 * recognizable scheme prefix so a human can still tell WHAT kind of secret it
 * was.
 *
 * Keep the pattern list in loose sync with
 * sentinel/src/checks/secrets-in-input.ts::SECRET_PATTERNS — Airlock cares
 * about the same credential shapes, just for masking rather than blocking.
 */

/** Max characters of any secret ever emitted into an audit line. */
const MAX_PREFIX = 14;

interface RedactPattern {
  re: RegExp;
  /** How many leading chars of the match to preserve before the ellipsis. */
  keep: number;
}

const SECRET_PATTERNS: RedactPattern[] = [
  { re: /AIza[A-Za-z0-9_\-]{35}/g, keep: 8 },
  { re: /sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}/g, keep: 14 },
  { re: /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g, keep: 10 },
  { re: /sk_live_[A-Za-z0-9]{12,}/g, keep: 12 },
  { re: /sk_test_[A-Za-z0-9]{12,}/g, keep: 12 },
  { re: /pk_live_[A-Za-z0-9]{12,}/g, keep: 12 },
  { re: /rk_live_[A-Za-z0-9]{12,}/g, keep: 12 },
  { re: /ghp_[A-Za-z0-9]{36}/g, keep: 8 },
  { re: /ghs_[A-Za-z0-9]{36}/g, keep: 8 },
  { re: /gho_[A-Za-z0-9]{36}/g, keep: 8 },
  { re: /github_pat_[A-Za-z0-9_]{22,}/g, keep: 14 },
  { re: /xox[abprs]-[A-Za-z0-9-]{10,}/g, keep: 10 },
  { re: /AKIA[0-9A-Z]{16}/g, keep: 8 },
  { re: /ASIA[0-9A-Z]{16}/g, keep: 8 },
  // AWS secret access key (40 b64-ish chars) — only when clearly labelled.
  { re: /(?<=aws_secret_access_key\s*[:=]\s*["']?)[A-Za-z0-9/+]{40}/gi, keep: 4 },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, keep: 14 },
  { re: /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}/g, keep: 6 },
  { re: /AC[a-f0-9]{32}/g, keep: 6 }, // Twilio Account SID
  { re: /SK[a-f0-9]{32}/g, keep: 6 }, // Twilio API key
  { re: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|redis|amqps?|mysql):\/\/[^\s"'<>]+/g, keep: 12 },
];

// Generic "NAME=value" pairs where the name looks secret-ish. Catches custom
// secrets the scheme-specific patterns above miss (API_TOKEN=..., PASSWORD=...).
const SECRETISH_ASSIGNMENT =
  /\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|APIKEY|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CREDENTIAL|AUTH)[A-Z0-9_]*)\s*([:=])\s*(["']?)([^\s"'#]{4,})\3/gi;

function mask(matched: string, keep: number): string {
  const k = Math.min(keep, MAX_PREFIX, matched.length);
  if (matched.length <= k) return matched;
  return `${matched.slice(0, k)}…⟨redacted⟩`;
}

/**
 * Redact any secret-shaped substrings in `text`, returning a version safe to
 * write to the audit log or ship to Guardian. Idempotent and allocation-light
 * on the common (no-secret) path.
 */
export function redactSecrets(text: string): string {
  if (!text) return text;
  let out = text;

  for (const { re, keep } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (m) => mask(m, keep));
  }

  SECRETISH_ASSIGNMENT.lastIndex = 0;
  out = out.replace(
    SECRETISH_ASSIGNMENT,
    (_full, name: string, sep: string, _q: string, value: string) =>
      `${name}${sep}${mask(value, 4)}`,
  );

  return out;
}

/** True if `text` appears to contain a recognizable secret. */
export function containsSecret(text: string): boolean {
  if (!text) return false;
  for (const { re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(text)) return true;
  }
  SECRETISH_ASSIGNMENT.lastIndex = 0;
  return SECRETISH_ASSIGNMENT.test(text);
}
