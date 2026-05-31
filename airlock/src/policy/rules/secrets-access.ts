/**
 * Rule: secrets-access.
 *
 * Fear #5: "the AI will read my credentials." This rule flags an action
 * *reading* sensitive credential stores — .env files, SSH private keys, cloud
 * credential files, the shell history, keychains. On its own that's a warn
 * (lots of legitimate tooling reads .env). But reading a secret store in the
 * same breath as a network egress is the dangerous combination, so this rule
 * escalates to block when it sees both.
 *
 * This pairs with @lictor/sentinel, which catches secrets crossing the *prompt*
 * boundary. Airlock catches them being touched on the *filesystem*.
 */

import type { Action, Rule, RuleHit } from "../../types.js";
import { matchPatterns, type Pattern } from "../match.js";

/** Files/locations that hold credentials. */
const SECRET_PATH_RE =
  /(?:\.env(?:\.[\w.-]+)?\b|\/\.ssh\/(?:id_\w+|identity)\b|id_rsa\b|id_ed25519\b|\.aws\/credentials\b|\.config\/gcloud\/|\.kube\/config\b|\.docker\/config\.json\b|\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b|secrets?\.(?:json|ya?ml|toml)\b|credentials?\.(?:json|ya?ml)\b)/i;

/** Reading commands. */
const READ_CMD_RE =
  /(?:^|[\s;&|])(?:cat|less|more|head|tail|bat|cp|scp|rsync|tar|zip|base64|strings|xxd|od|grep|rg|awk|sed|source|\.)\s/i;

/** Network egress in the same command. */
const EGRESS_RE =
  /\b(?:curl|wget|nc|ncat|netcat|socat|xh|scp|rsync|ssh)\b|@[\w.-]+:|\|\s*(?:curl|wget|nc)\b/i;

const PATTERNS: Pattern[] = [
  {
    // macOS keychain / Linux secret-tool dumps.
    re: /(?:security\s+(?:find-generic-password|find-internet-password|dump-keychain)|secret-tool\s+(?:lookup|search)|keyring\b)/i,
    decision: "warn",
    severity: "high",
    title: "Reading the OS keychain / secret store",
    reason: "This pulls credentials out of the system keychain — passwords and tokens the user stored for safekeeping.",
    remediation: "Confirm the agent genuinely needs a stored credential and isn't harvesting them.",
  },
  {
    re: /(?:^|[\s;&|])(?:cat|less|more|head|tail|bat|strings)\s+[^\n]*~?\/?\.bash_history|\.zsh_history\b/i,
    decision: "warn",
    severity: "medium",
    title: "Reading shell history",
    reason: "Shell history often contains pasted tokens and one-off passwords. Reading it is a common credential-harvest step.",
    remediation: "Not needed for normal work. Confirm why history is being read.",
  },
];

function evaluate(action: Action): RuleHit[] {
  const hits = matchPatterns(action, PATTERNS, "secrets-access");

  // Dynamic combination: reading a secret file, optionally + network egress.
  const text = action.text;
  const touchesSecretFile = SECRET_PATH_RE.test(text);
  if (touchesSecretFile) {
    SECRET_PATH_RE.lastIndex = 0;
    const reading =
      READ_CMD_RE.test(text) ||
      action.channel === "file-write" ||
      /\bopen\b|\bread\b/i.test(action.tool ?? "");
    const egress = EGRESS_RE.test(text);

    if (reading && egress) {
      hits.push({
        ruleId: "secrets-access",
        decision: "block",
        severity: "critical",
        title: "Credential file read and sent to the network",
        reason:
          "A secrets file (.env / SSH key / cloud credentials) is being read in the same action that talks to the network — the data is on its way out.",
        remediation: "Stop. Credential files should never be piped to a network command.",
        evidence: redactedMatch(text, SECRET_PATH_RE),
      });
    } else if (reading) {
      hits.push({
        ruleId: "secrets-access",
        decision: "warn",
        severity: "high",
        title: "Reading a credential file",
        reason:
          "A secrets file (.env / SSH key / cloud credentials) is being read. Often legitimate, but it's where credential theft starts.",
        remediation: "Confirm the agent needs these values and isn't about to send them anywhere.",
        evidence: redactedMatch(text, SECRET_PATH_RE),
      });
    }
  }

  return hits;
}

/** Pull the matched secret-path substring back out for evidence (already a path, not a value). */
function redactedMatch(text: string, re: RegExp): string {
  re.lastIndex = 0;
  const m = re.exec(text);
  return m ? m[0].slice(0, 80) : "";
}

export const secretsAccessRule: Rule = {
  id: "secrets-access",
  evaluate,
};
