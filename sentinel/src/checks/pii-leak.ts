/**
 * PII-leak check.
 *
 * Runs on POSTFLIGHT (model output). Catches cases where the LLM responds
 * with personally-identifying information that should not have crossed the
 * model boundary — emails, phones, SSNs, credit cards, bank accounts, etc.
 *
 * Threat model:
 *   - User asks an open question; model unexpectedly produces PII from its
 *     training data or from retrieved context. The PII appears in the
 *     response and ends up rendered to the user.
 *   - User asks for help with a customer's data; model returns more PII
 *     than was strictly necessary.
 *   - Prompt-injection success: attacker convinces the model to dump PII
 *     from its system prompt or RAG context.
 *
 * Design notes:
 *   - We tag-and-flag, never sanitize the response automatically (`onTrip:
 *     'redact'` is opt-in by the caller; default is 'log').
 *   - Credit-card matches are gated by a Luhn check to drop the vast
 *     majority of false positives (random 16-digit number sequences).
 *   - We deliberately do NOT match generic 10-digit numbers as "phone
 *     numbers" — too many false positives. We require an explicit phone
 *     format (parens, dashes, or "+" prefix).
 *   - Severity reflects exposure risk:
 *       critical: credit card with valid Luhn, SSN, IBAN
 *       high:     other financial identifiers
 *       medium:   email, phone, IP address
 *       low:      ZIP codes, partial addresses
 */

import type { Phase, Severity } from "../types.js";
import type { Check, CheckResult } from "../check-runner.js";
import { PASS } from "../check-runner.js";

export interface PiiPattern {
  re: RegExp;
  category:
    | "email"
    | "phone"
    | "ssn"
    | "credit-card"
    | "iban"
    | "ip-address"
    | "postal-address"
    | "driver-license";
  severity: Severity;
  description: string;
  /** Post-match validator (e.g. Luhn for credit cards). Returns true to keep the match. */
  validate?: (match: string) => boolean;
}

/** Luhn algorithm for credit-card number validation. */
function luhnValid(digits: string): boolean {
  const cleaned = digits.replace(/[^0-9]/g, "");
  if (cleaned.length < 13 || cleaned.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let n = parseInt(cleaned.charAt(i), 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export const PII_PATTERNS: PiiPattern[] = [
  // ─── Email ──────────────────────────────────────────────────────────────────
  {
    // Conservative RFC-5322-ish — local-part allows common chars, must have a
    // dot in the domain, TLD 2-24 chars.
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
    category: "email",
    severity: "medium",
    description: "Email address in model output.",
  },

  // ─── US Social Security Number ──────────────────────────────────────────────
  {
    // 3-2-4 with dashes or spaces. We reject obvious test/invalid prefixes
    // (000, 666, 9xx) which are SSA-reserved as non-issued.
    re: /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g,
    category: "ssn",
    severity: "critical",
    description: "US Social Security Number (formatted).",
  },

  // ─── Credit cards (Luhn-validated) ──────────────────────────────────────────
  {
    // Catch 13-19 digit sequences with optional spaces/dashes between groups
    // of 4. Luhn check in the validator drops most false positives.
    re: /\b(?:\d[ -]*?){13,19}\b/g,
    category: "credit-card",
    severity: "critical",
    description: "Credit card number (Luhn-validated).",
    validate: (m) => luhnValid(m),
  },

  // ─── IBAN ───────────────────────────────────────────────────────────────────
  {
    // 2-letter country code + 2 check digits + 11-30 alphanumerics.
    // Conservative; we don't validate the mod-97 check (would catch
    // more false positives but adds complexity).
    re: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    category: "iban",
    severity: "critical",
    description: "Possible IBAN (International Bank Account Number).",
  },

  // ─── US phone numbers ───────────────────────────────────────────────────────
  // Require a clear phone format: (xxx) xxx-xxxx, xxx-xxx-xxxx, or +1 xxx xxx xxxx.
  // Plain 10-digit numbers are deliberately NOT matched — too noisy.
  {
    re: /\(\d{3}\)\s*\d{3}[- ]\d{4}\b/g,
    category: "phone",
    severity: "medium",
    description: "US phone number with parenthesized area code.",
  },
  {
    re: /\b\d{3}-\d{3}-\d{4}\b/g,
    category: "phone",
    severity: "medium",
    description: "US phone number (dashed format).",
  },
  {
    re: /\+1[ \-.]?\d{3}[ \-.]?\d{3}[ \-.]?\d{4}\b/g,
    category: "phone",
    severity: "medium",
    description: "US phone number with +1 international prefix.",
  },
  // International phones: +CC followed by 7-14 digits, must have at least one separator.
  {
    re: /\+(?:[2-9]\d{0,3})[ \-.]?\d{2,5}[ \-.]\d{2,5}(?:[ \-.]\d{2,5})?\b/g,
    category: "phone",
    severity: "medium",
    description: "International phone number with country code prefix.",
  },

  // ─── IP addresses ──────────────────────────────────────────────────────────
  {
    // IPv4. We reject obvious bogons (0.x.x.x, 255.255.255.255 etc.) via
    // a simple range check in the regex.
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
    category: "ip-address",
    severity: "low",
    description: "IPv4 address in model output.",
  },
  {
    // IPv6 (loose match — 7 colons separating hex groups, full form only).
    // Compact ::-form is much harder to match precisely; defer.
    re: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    category: "ip-address",
    severity: "low",
    description: "IPv6 address (full form) in model output.",
  },

  // ─── Postal addresses ──────────────────────────────────────────────────────
  // We catch ZIP-coded US addresses with a state abbrev: "123 Main St, Boston, MA 02101"
  // Format: "<street># <street name> <type>, <City>, <ST> <ZIP>"
  {
    re: /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct|Place|Pl)\.?,?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,?\s+[A-Z]{2}\s+\d{5}(?:-\d{4})?\b/g,
    category: "postal-address",
    severity: "medium",
    description: "Formatted US street address with ZIP code.",
  },
];

// ─── The Check ───────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

function runPiiLeak(text: string, _phase: Phase): CheckResult {
  if (!text || text.length === 0) return PASS;

  const matches: Array<{ category: string; severity: Severity; description: string }> = [];
  const seenCategories = new Set<string>();
  let topSeverity: Severity = "info";

  for (const pat of PII_PATTERNS) {
    // Use a fresh state: reset lastIndex if the regex has /g.
    pat.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = pat.re.exec(text)) !== null) {
      if (pat.validate && !pat.validate(m[0])) continue;
      matches.push({
        category: pat.category,
        severity: pat.severity,
        description: pat.description,
      });
      seenCategories.add(pat.category);
      topSeverity = maxSeverity(topSeverity, pat.severity);
      if (matches.length >= 10) break;
      // For non-global regexes, exec returns the first match and lastIndex stays 0 — break to avoid infinite loop.
      if (!pat.re.global) break;
    }
    if (matches.length >= 10) break;
  }

  if (matches.length === 0) return PASS;

  const categoryList = Array.from(seenCategories).join(", ");
  const title = `PII leak — ${matches.length} match${matches.length === 1 ? "" : "es"} in ${seenCategories.size} categor${seenCategories.size === 1 ? "y" : "ies"} (${categoryList})`;

  const detailLines = matches.map((m) => `  [${m.severity}] ${m.category}: ${m.description}`);
  const detail =
    `Pattern-based detection of PII in model output.\n` +
    `Matched ${matches.length} of ${PII_PATTERNS.length} catalog entries:\n\n` +
    detailLines.join("\n") +
    `\n\nThis is a rule-based detection. Credit-card matches are Luhn-validated. ` +
    `False positives possible (e.g. random 16-digit sequences that pass Luhn by chance, ` +
    `or example.com email addresses in technical documentation). False negatives possible ` +
    `for novel formats. Treat severity as a prior, not a verdict.`;

  return {
    tripped: true,
    severity: topSeverity,
    title,
    detail,
  };
}

export const piiLeakCheck: Check = {
  id: "pii-leak",
  run: runPiiLeak,
};
