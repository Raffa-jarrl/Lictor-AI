/**
 * Prompt-injection check.
 *
 * Detects the dominant patterns from OWASP LLM01 (Prompt Injection) and
 * the published prompt-injection literature through 2026.
 *
 * Design principles:
 *
 *   1. **Conservative by default.** False positives kill developer trust
 *      faster than missed detections. Every pattern here requires a
 *      specific injection-relevant noun ("instructions", "system prompt",
 *      a model-control token, etc.) — never a single suspicious word.
 *
 *   2. **Categorized by mechanism.** Each pattern names its attack class
 *      so dashboards can roll up by family and Guardian can show trend
 *      analysis ("you're seeing more jailbreak attempts this week").
 *
 *   3. **Severity reflects exploit confidence.** Critical = model-control
 *      tokens that should NEVER appear in user input. High = clear
 *      adversarial intent. Medium = suspicious phrasing that's
 *      probably-but-not-definitely an attack.
 *
 *   4. **Highest severity wins, all matches listed.** If five patterns
 *      trip, the finding's severity is the max and the detail enumerates
 *      every matched category. Lets the user / dashboard understand the
 *      whole picture without losing the priority signal.
 */

import type { Phase, Severity } from "../types.js";
import type { Check, CheckResult } from "../check-runner.js";
import { PASS } from "../check-runner.js";

/** A single injection pattern, with its provenance. */
export interface InjectionPattern {
  /** The regex. */
  re: RegExp;
  /** Attack family. Used in finding detail and dashboard rollups. */
  category:
    | "direct-override"
    | "authority-impersonation"
    | "jailbreak"
    | "system-prompt-extraction"
    | "delimiter-injection"
    | "goal-hijacking"
    | "suspicious-encoding";
  /** Severity if this pattern alone trips. */
  severity: Severity;
  /** Short description for finding detail. */
  description: string;
}

/**
 * The pattern catalog. Curated; expand carefully — each pattern is a
 * potential false-positive vector.
 *
 * **DO NOT** add a pattern without:
 *   - At least one positive test case (clear adversarial input that trips it)
 *   - At least one negative test case (similar-looking but legitimate input
 *     that must NOT trip it)
 */
export const INJECTION_PATTERNS: InjectionPattern[] = [
  // ─── Direct override: "ignore previous instructions" family ─────────────────
  {
    re: /\b(?:ignore|disregard|forget|skip)\s+(?:all\s+|the\s+|any\s+|every\s+|your\s+)?(?:previous|above|prior|earlier|prior|preceding)\s+(?:instructions?|prompts?|commands?|rules?|directives?|guidelines?|messages?|context)\b/i,
    category: "direct-override",
    severity: "high",
    description: "Tells the model to discard its prior instructions.",
  },
  {
    re: /\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:i\s+(?:said|wrote|told\s+you)|you\s+(?:were\s+)?told|above|that)\b/i,
    category: "direct-override",
    severity: "high",
    description: "Tells the model to discard everything prior.",
  },
  {
    re: /\b(?:new|updated|revised|replacement)\s+(?:instructions?|prompts?|directives?|rules?|guidelines?)\s*:/i,
    category: "direct-override",
    severity: "high",
    description: "Asserts replacement instructions, typically followed by attacker content.",
  },
  {
    re: /\bfrom\s+now\s+on\b[\s,:;]+(?:you|please)\s+(?:will|must|are|should|need\s+to|have\s+to)\b/i,
    category: "direct-override",
    severity: "medium",
    description: "Resets the model's behaviour going forward.",
  },
  {
    re: /\b(?:your|the)\s+(?:real|actual|true|hidden|secret|new)\s+(?:task|goal|mission|objective|purpose|instructions?|prompt)\b/i,
    category: "goal-hijacking",
    severity: "medium",
    description: "Reframes the model's task as the attacker's goal.",
  },
  {
    re: /\binstead\s+of\s+(?:doing\s+that|that|following|your\s+previous)[\s,]+(?:you\s+(?:should|will|must|need\s+to)|please)\b/i,
    category: "goal-hijacking",
    severity: "medium",
    description: "Replaces the current task with the attacker's request.",
  },

  // ─── Authority impersonation: faking system role / admin context ────────────
  {
    re: /(?:^|\n|\.\s+)\s*(?:system|admin|administrator|root|developer)\s*:/i,
    category: "authority-impersonation",
    severity: "high",
    description: "Mimics a system/admin role marker inside user input.",
  },
  {
    re: /\[\s*(?:system|admin|administrator|root|sudo|developer)\s*\]/i,
    category: "authority-impersonation",
    severity: "high",
    description: "Square-bracketed system marker — common attack format.",
  },
  {
    re: /\b(?:admin|administrator|root|sudo|developer)\s+(?:override|mode|access|privileges?|permissions?)\b/i,
    category: "authority-impersonation",
    severity: "high",
    description: "Claims elevated authority over the model.",
  },
  {
    re: /\bdeveloper\s+mode\s+(?:enabled|on|activated|active)\b/i,
    category: "authority-impersonation",
    severity: "high",
    description: "Classic 'developer mode' jailbreak claim.",
  },
  {
    re: /\b(?:bypass|override|disable|turn\s+off)\s+(?:your\s+|the\s+|all\s+)?(?:safety|safeguards?|filters?|guardrails?|restrictions?|limits?|safety\s+rules?|content\s+policy)\b/i,
    category: "authority-impersonation",
    severity: "high",
    description: "Instructs the model to disable its safety controls.",
  },

  // ─── Jailbreak personas: DAN, evil-AI, unrestricted ─────────────────────────
  {
    re: /\bDAN\s+(?:mode|prompt)\b/i,
    category: "jailbreak",
    severity: "high",
    description: "References the 'DAN' (Do Anything Now) jailbreak persona.",
  },
  {
    re: /\bdo\s+anything\s+now\b/i,
    category: "jailbreak",
    severity: "high",
    description: "DAN-style unrestricted-mode invocation.",
  },
  {
    re: /\b(?:act|pretend|behave|respond)\s+as\s+(?:if\s+you\s+(?:have\s+)?(?:no|don'?t\s+have)|an?\s+(?:evil|unrestricted|uncensored|jailbroken|amoral|unfiltered))\b/i,
    category: "jailbreak",
    severity: "high",
    description: "Role-as-evil-AI persona setup.",
  },
  {
    re: /\b(?:pretend|imagine)\s+(?:you\s+(?:are|have))\s+(?:no\s+(?:ethics|morals|restrictions|rules)|been\s+jailbroken|free\s+from)\b/i,
    category: "jailbreak",
    severity: "high",
    description: "Imagine-yourself-unrestricted persona setup.",
  },
  {
    re: /\b(?:evil|unrestricted|uncensored|jailbroken|unfiltered)\s+(?:AI|GPT|model|assistant|chatbot|version)\b/i,
    category: "jailbreak",
    severity: "high",
    description: "References an 'evil/unrestricted' alter-ego model.",
  },
  {
    re: /\byou\s+(?:can|may|will|are\s+allowed\s+to)\s+(?:now\s+)?(?:say|do|generate|produce|output)\s+(?:anything|whatever|any\s+content)\b/i,
    category: "jailbreak",
    severity: "medium",
    description: "Asserts unrestricted output permission.",
  },

  // ─── System prompt extraction: get the model to reveal its instructions ─────
  // Tightened to require either "your" (possessive — asking the MODEL'S
  // rules) or "the system/initial/original" qualifier. Plain "the rules"
  // or "the instructions" is too common in legitimate prompts to flag.
  {
    re: /\b(?:repeat|show|tell\s+me|print|reveal|output|display|share|reproduce)\s+(?:your\s+(?:system\s+)?|the\s+(?:system|initial|original|developer|previous)\s+)(?:prompt|instructions?|guidelines|rules|directives|message|messages)\b/i,
    category: "system-prompt-extraction",
    severity: "medium",
    description: "Asks the model to repeat its system prompt or instructions.",
  },
  {
    re: /\bwhat\s+(?:were|are|is)\s+(?:your|the)\s+(?:previous|original|initial|first|system|developer)\s+(?:instructions?|prompts?|rules?|directives?|guidelines?)\b/i,
    category: "system-prompt-extraction",
    severity: "medium",
    description: "Probes for the model's system prompt.",
  },
  {
    re: /\b(?:repeat|recite|state|print|show|output|dump|display)\s+(?:everything|all)\s+(?:above|before|prior|preceding|that\s+was\s+said|that\s+came\s+before)\b/i,
    category: "system-prompt-extraction",
    severity: "medium",
    description: "Asks the model to dump its context window.",
  },
  {
    re: /\b(?:show|tell)\s+me\s+(?:the|what)\s+(?:rules|instructions?|guidelines|prompts?|directives|orders|constraints)\s+(?:you\s+(?:were\s+)?given|(?:that\s+)?(?:were|are)\s+given\s+to\s+you)\b/i,
    category: "system-prompt-extraction",
    severity: "medium",
    description: "Asks the model what instructions it was given.",
  },
  {
    re: /\boutput\s+(?:your|the)\s+(?:initial|first|system)\s+(?:message|prompt|context)\s+verbatim\b/i,
    category: "system-prompt-extraction",
    severity: "high",
    description: "Specifically requests verbatim system-prompt extraction.",
  },
  {
    re: /\btranslate\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:to|into)\b/i,
    category: "system-prompt-extraction",
    severity: "medium",
    description: "Indirect extraction via translation (a common bypass).",
  },
  {
    re: /\b(?:base64|hex|rot13|encode|encrypt)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)\b/i,
    category: "system-prompt-extraction",
    severity: "high",
    description: "Indirect extraction via encoding (bypasses naive output filters).",
  },

  // ─── Delimiter / model-token injection ──────────────────────────────────────
  // These tokens are NEVER legitimately in user input — they're how providers
  // delimit conversation turns. If you see one, the user is trying to forge a
  // turn boundary. Critical severity.
  {
    re: /<\|im_start\|>|<\|im_end\|>/,
    category: "delimiter-injection",
    severity: "critical",
    description: "ChatML turn-delimiter token in user input.",
  },
  {
    re: /<\|start_header_id\|>|<\|end_header_id\|>|<\|eot_id\|>/,
    category: "delimiter-injection",
    severity: "critical",
    description: "Llama 3 turn-delimiter token in user input.",
  },
  {
    re: /\[\s*\/?\s*INST\s*\]/,
    category: "delimiter-injection",
    severity: "critical",
    description: "Llama [INST] / [/INST] turn-delimiter token in user input.",
  },
  {
    re: /<\/?\s*s\s*>/i,
    category: "delimiter-injection",
    severity: "high",
    description: "BOS/EOS-style `<s>` / `</s>` token in user input.",
  },
  {
    re: /(?:^|\n)\s*(?:Assistant|AI|Human|User)\s*:\s*(?:Sure|Okay|Of\s+course|Yes|Here)/i,
    category: "delimiter-injection",
    severity: "high",
    description: "Fake conversation turn pre-filled with an affirmative reply.",
  },

  // ─── Suspicious encoding ────────────────────────────────────────────────────
  // Long base64 sequences in otherwise-prose input are almost always an
  // encoded instruction (an attempt to slip past keyword filters). We don't
  // try to decode; we flag.
  {
    // 80+ chars of base64 alphabet — high prior of encoded content.
    re: /[A-Za-z0-9+/]{80,}={0,2}/,
    category: "suspicious-encoding",
    severity: "medium",
    description: "Long base64-shaped string in input. Often hides an injected instruction.",
  },
  {
    // Many \x or \u escape sequences — likely encoded ASCII/Unicode strings.
    re: /(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\u[0-9a-fA-F]{4}){8,}/,
    category: "suspicious-encoding",
    severity: "medium",
    description: "Repeated hex/unicode escape sequences. Likely an obfuscated payload.",
  },
  {
    // Excessive zero-width characters (homoglyphs / hidden text)
    re: /(?:[​-‏‪-‮⁠-⁯]){5,}/,
    category: "suspicious-encoding",
    severity: "medium",
    description: "Five or more zero-width / direction-override characters. Likely hiding text.",
  },
];

// ─── The Check implementation ────────────────────────────────────────────────

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

/**
 * Run all patterns against the text. Returns a single CheckResult with:
 *   - severity = max(matched severities)
 *   - title = "Prompt injection — N pattern(s) matched in M category/ies"
 *   - detail = enumerated list of (category, pattern description, severity)
 *
 * If no patterns match, returns PASS.
 *
 * For postflight, we currently apply the same patterns to model output. A
 * prompt-injection attempt that succeeded often produces output containing
 * the very patterns it was trying to inject (DAN persona slipping through).
 */
function runPromptInjection(text: string, _phase: Phase): CheckResult {
  if (!text || text.length === 0) return PASS;

  // Collect matches up to a reasonable cap. A heavily-poisoned input will
  // trigger many; don't enumerate hundreds.
  const matches: Array<{ category: string; description: string; severity: Severity }> = [];
  const seenCategories = new Set<string>();
  let topSeverity: Severity = "info";

  for (const pat of INJECTION_PATTERNS) {
    if (pat.re.test(text)) {
      matches.push({
        category: pat.category,
        description: pat.description,
        severity: pat.severity,
      });
      seenCategories.add(pat.category);
      topSeverity = maxSeverity(topSeverity, pat.severity);
      if (matches.length >= 10) break; // cap detail volume
    }
  }

  if (matches.length === 0) return PASS;

  const categoryList = Array.from(seenCategories).join(", ");
  const title = `Prompt injection — ${matches.length} pattern${matches.length === 1 ? "" : "s"} in ${seenCategories.size} categor${seenCategories.size === 1 ? "y" : "ies"} (${categoryList})`;

  const detailLines = matches.map(
    (m) => `  [${m.severity}] ${m.category}: ${m.description}`,
  );
  const detail =
    `Pattern-based detection of likely prompt injection in user input.\n` +
    `Matched ${matches.length} of ${INJECTION_PATTERNS.length} catalog entries:\n\n` +
    detailLines.join("\n") +
    `\n\nThis is a rule-based detection. False positives are possible if a ` +
    `legitimate prompt happens to use injection-shaped phrasing. False negatives ` +
    `are likely for novel attacks not yet in the catalog. Treat the severity as ` +
    `a prior, not a verdict.`;

  return {
    tripped: true,
    severity: topSeverity,
    title,
    detail,
  };
}

export const promptInjectionCheck: Check = {
  id: "prompt-injection",
  run: runPromptInjection,
};
