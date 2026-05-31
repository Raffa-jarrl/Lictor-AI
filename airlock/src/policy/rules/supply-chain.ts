/**
 * Rule: supply-chain.
 *
 * Fear #4: "the AI will pull in something malicious and run it." The headline
 * case is the curl|bash pattern — piping a remote script straight into a shell,
 * which runs whatever the server decides to return, unreviewed. Also covers
 * installing packages from registries (typosquat / dependency-confusion risk)
 * and adding untrusted apt repositories.
 *
 * Installing a well-known package is routine, so plain installs are a low/warn,
 * not a block. Piping the internet into a shell is the dangerous one.
 */

import type { Action, Rule, RuleHit } from "../../types.js";
import { matchPatterns, type Pattern } from "../match.js";

const PATTERNS: Pattern[] = [
  {
    // curl/wget ... | sh|bash|python  — remote code execution.
    re: /\b(?:curl|wget|fetch|xh)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python\d?|perl|ruby|node)\b/i,
    decision: "block",
    severity: "critical",
    title: "Pipe-from-web into a shell (curl | bash)",
    reason:
      "This downloads a script and runs it immediately, sight unseen. Whoever controls that URL controls your machine.",
    remediation:
      "Download to a file, read it, then run it: curl -o setup.sh URL && less setup.sh && bash setup.sh.",
  },
  {
    // eval of downloaded content.
    re: /\beval\b[^\n]*\$\((?:\s*(?:curl|wget|fetch))\b/i,
    decision: "block",
    severity: "critical",
    title: "eval of downloaded content",
    reason: "Evaluating the output of a network fetch runs remote, unreviewed code with your privileges.",
    remediation: "Never eval network output. Fetch to a file and inspect it first.",
  },
  {
    // Adding a third-party apt repo / key.
    re: /(?:add-apt-repository\b|apt-key\s+add\b|curl\b[^\n]*\|\s*(?:sudo\s+)?apt-key\b|echo\b[^\n]*>\s*\/etc\/apt\/sources\.list)/i,
    decision: "warn",
    severity: "medium",
    title: "Adding a third-party package source",
    reason: "A new apt repository or signing key means future installs will trust a source you may not have vetted.",
    remediation: "Confirm the repository is the official one for the software you want.",
  },
  {
    // Package installs from a registry — typosquat / dependency-confusion vector.
    re: /(?:^|[\s;&|])(?:npm\s+(?:i|install|add)|pnpm\s+(?:i|install|add)|yarn\s+add|pip3?\s+install|pipx\s+install|gem\s+install|cargo\s+install|go\s+install|brew\s+install)\b/i,
    decision: "warn",
    severity: "low",
    title: "Package install from a registry",
    reason:
      "Installing a package runs its install scripts and adds its code to your project. Typosquatted or hijacked packages slip in here.",
    remediation: "Check the package name and publisher. Pin a known-good version rather than taking latest.",
    // Local/path installs and --dry-run aren't a registry-trust concern.
    guard: (a: Action) =>
      !/--dry-run/i.test(a.text) && !/\b(?:\.\/|\.\.\/|file:|git\+|-e\s+\.)/.test(a.text),
  },
  {
    // npx / pnpm dlx executing a remote package without installing.
    re: /(?:^|[\s;&|])(?:npx|pnpm\s+dlx|bunx)\s+(?!-)/i,
    decision: "warn",
    severity: "low",
    title: "Running a package without installing it (npx/dlx)",
    reason: "npx fetches and executes a package on the fly — convenient, but it runs whatever the current published version contains.",
    remediation: "For anything beyond throwaway use, install a pinned version so you know what's running.",
  },
];

function evaluate(action: Action): RuleHit[] {
  return matchPatterns(action, PATTERNS, "supply-chain");
}

export const supplyChainRule: Rule = {
  id: "supply-chain",
  evaluate,
};
