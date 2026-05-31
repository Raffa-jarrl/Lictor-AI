/**
 * Rule: destructive-command.
 *
 * The #1 fear that keeps IT from letting AI near a real machine: "it'll delete
 * something I can't get back." This rule catches irreversible, data-destroying
 * actions — file wipes, force-pushes, dropped tables, torn-down infrastructure.
 *
 * Precision is the product. A containment tool that screams at every `git
 * reset` gets turned off, and an AI agent with the guard turned off is exactly
 * the thing the customer was afraid of. So: catastrophic + irreversible →
 * block; recoverable-but-surprising → warn; everything else stays silent.
 *
 * The broker escalates any hit here to critical/block when the action also
 * touches a configured production marker (see broker.ts).
 */

import type { Action, Rule, RuleHit } from "../../types.js";
import { matchPatterns, type Pattern } from "../match.js";

const PATTERNS: Pattern[] = [
  // ── Filesystem wipes ────────────────────────────────────────────────────
  {
    // rm -rf / rm -fr / rm -r -f targeting a catastrophic root path.
    re: /\brm\s+(?:-[a-z]*\s+)*-[a-z]*r[a-z]*f|rm\s+(?:-[a-z]*\s+)*-[a-z]*f[a-z]*r/i,
    decision: "block",
    severity: "high",
    title: "Recursive force-delete (rm -rf)",
    reason:
      "This recursively deletes files and folders with no confirmation and no trash — anything it removes is gone for good.",
    remediation:
      "Delete a specific named path, or move it to a backup directory first. Avoid -r -f together unless you are certain.",
  },
  {
    // rm aimed straight at a root/home/wildcard — the truly catastrophic shape.
    re: /\brm\s+(?:-[a-z]+\s+)*(?:\/(?:\s|$|\*)|\/(?:usr|etc|var|bin|lib|boot|root|home|sys|opt)\b|~\/?(?:\s|$|\*)|\$HOME\b|\*\s*$|\.\s*$|--no-preserve-root)/i,
    decision: "block",
    severity: "critical",
    title: "Delete of a root / home / wildcard path",
    reason:
      "This targets a system root, your home directory, or a bare wildcard. It can wipe the whole machine or account.",
    remediation:
      "Never run this. If you meant to clear one project folder, name that folder explicitly.",
  },
  {
    re: /\bfind\b[^\n|]*\s-(?:delete\b|exec\s+rm\b)/i,
    decision: "block",
    severity: "high",
    title: "Bulk delete via find",
    reason:
      "find … -delete (or -exec rm) removes every matching file in one sweep — easy to match far more than intended.",
    remediation:
      "Run the find without -delete first and read the list. Delete deliberately once you've confirmed the matches.",
  },
  {
    re: /(?:^|[\s;&|])(?:mkfs(?:\.\w+)?\b|dd\s+[^\n]*\bof=\/dev\/|>\s*\/dev\/(?:sd|nvme|disk|hd)\w*)/i,
    decision: "block",
    severity: "critical",
    title: "Raw disk overwrite",
    reason:
      "Formatting or writing directly to a block device destroys every partition on it. There is no undo.",
    remediation: "Stop. Disk-level operations should be done by a human at the console.",
  },
  // ── Version control ─────────────────────────────────────────────────────
  {
    re: /\bgit\s+push\b[^\n]*\s(?:-f\b|--force\b)/i,
    decision: "block",
    severity: "high",
    title: "Force-push (git push --force)",
    reason:
      "A force-push can overwrite commits on the remote that other people pushed — their work disappears from the branch.",
    remediation:
      "Use --force-with-lease, which refuses to clobber commits you haven't seen. Better yet, push a new branch and open a PR.",
    // Don't fire when the safer --force-with-lease form is used; a separate
    // (lower) pattern handles that.
    guard: (a: Action) => !/--force-with-lease/i.test(a.text),
  },
  {
    re: /\bgit\s+push\b[^\n]*--force-with-lease/i,
    decision: "warn",
    severity: "medium",
    title: "Force-push with lease",
    reason:
      "--force-with-lease is the safe force-push, but it still rewrites remote history. Worth a glance before it runs.",
  },
  {
    re: /\bgit\s+reset\s+--hard\b/i,
    decision: "warn",
    severity: "medium",
    title: "Hard reset (discards local changes)",
    reason:
      "git reset --hard throws away all uncommitted work in the tree — there's no way to recover it afterward.",
    remediation: "git stash first if there's any chance you want those changes back.",
  },
  {
    re: /\bgit\s+clean\s+-[a-z]*f/i,
    decision: "warn",
    severity: "medium",
    title: "git clean -f (deletes untracked files)",
    reason:
      "git clean -f permanently removes untracked files, which often includes local config and scratch work git never saw.",
    remediation: "Run git clean -n (dry run) first to see exactly what would be deleted.",
  },
  // ── Databases ───────────────────────────────────────────────────────────
  {
    re: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i,
    decision: "block",
    severity: "critical",
    title: "DROP TABLE / DATABASE",
    reason:
      "Dropping a table or database deletes the data and its structure. Unless you have a fresh backup, it's unrecoverable.",
    remediation:
      "Rename to a _deprecated table and keep it for a few days instead of dropping. Confirm backups exist first.",
  },
  {
    re: /\bTRUNCATE\s+(?:TABLE\s+)?\w/i,
    decision: "block",
    severity: "high",
    title: "TRUNCATE TABLE",
    reason: "TRUNCATE empties an entire table instantly and can't be rolled back in most engines.",
    remediation: "If you only need some rows gone, use a scoped DELETE … WHERE inside a transaction.",
  },
  {
    // DELETE / UPDATE with no WHERE clause = whole-table operation.
    re: /\b(DELETE\s+FROM|UPDATE)\s+[\w."`]+(?![^;]*\bWHERE\b)[^;]*(?:;|$)/i,
    decision: "block",
    severity: "high",
    title: "DELETE/UPDATE with no WHERE clause",
    reason:
      "Without a WHERE clause this hits every row in the table — a full wipe or a full overwrite.",
    remediation: "Add a WHERE clause. Test it as a SELECT first to see the row count you'll affect.",
  },
  // ── Infrastructure / cloud ──────────────────────────────────────────────
  {
    re: /\bterraform\s+destroy\b|\bterraform\s+apply\b[^\n]*-destroy/i,
    decision: "block",
    severity: "critical",
    title: "terraform destroy",
    reason:
      "terraform destroy tears down every resource in the state — servers, databases, DNS, the lot. It's the infrastructure kill switch.",
    remediation: "Never let an agent run this unattended. A human should review the destroy plan.",
  },
  {
    re: /\bkubectl\s+delete\b/i,
    decision: "block",
    severity: "high",
    title: "kubectl delete",
    reason:
      "Deleting Kubernetes objects can remove running workloads, data volumes, or whole namespaces from a live cluster.",
    remediation: "Confirm the context (kubectl config current-context) isn't prod before deleting anything.",
    guard: (a: Action) => !/--dry-run/i.test(a.text),
  },
  {
    re: /\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b[^\n]*--recursive|\baws\s+\w[\w-]*\s+delete-[\w-]+/i,
    decision: "block",
    severity: "high",
    title: "AWS delete / bucket removal",
    reason:
      "Removing an S3 bucket or recursively deleting objects (or any aws delete-*) can erase production data and configuration.",
    remediation: "Enable versioning + MFA-delete on buckets. Review the exact target before deleting.",
  },
  {
    re: /\bgcloud\s+[\w-]+(?:\s+[\w-]+)*\s+delete\b|\baz\s+[\w-]+\s+delete\b/i,
    decision: "block",
    severity: "high",
    title: "Cloud resource delete (gcloud / az)",
    reason: "This deletes a cloud resource. Depending on the target it can take a live service offline.",
    remediation: "Double-check the project/subscription and resource name first.",
  },
  {
    re: /\bdocker\s+(?:system\s+prune|volume\s+(?:rm|prune)|builder\s+prune)\b/i,
    decision: "block",
    severity: "high",
    title: "Docker volume / system prune",
    reason:
      "Pruning Docker volumes deletes container data — databases and uploads that live in volumes are gone with them.",
    remediation: "List volumes (docker volume ls) and remove only the ones you know are throwaway.",
  },
  // ── System / availability ───────────────────────────────────────────────
  {
    re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    decision: "block",
    severity: "critical",
    title: "Fork bomb",
    reason: "This is a fork bomb — it spawns processes until the machine locks up.",
    remediation: "Never run this.",
  },
  {
    re: /(?:^|[\s;&|])(?:shutdown|reboot|halt|poweroff|init\s+0)\b/i,
    decision: "block",
    severity: "high",
    title: "Power / shutdown command",
    reason: "This shuts down or reboots the machine, interrupting anything running on it.",
    remediation: "If a restart is really needed, a person should do it knowingly.",
  },
  {
    re: /\bchmod\s+(?:-R\s+)?0?777\b/i,
    decision: "warn",
    severity: "medium",
    title: "chmod 777 (world-writable)",
    reason:
      "777 makes a file or tree readable and writable by everyone on the machine — a common way secrets and code get tampered with.",
    remediation: "Grant the narrowest permission that works (often 644 for files, 755 for dirs).",
  },
  {
    re: /\bcrontab\s+-r\b/i,
    decision: "warn",
    severity: "medium",
    title: "crontab -r (wipes all cron jobs)",
    reason: "crontab -r deletes every scheduled job for the user with no confirmation — easy to fat-finger instead of -e.",
    remediation: "Use crontab -e to edit, or back up with crontab -l > cron.bak first.",
  },
];

/**
 * Verbs in an MCP tool *name* that signal a destructive operation even when no
 * shell command is present (e.g. a server exposing `delete_database`,
 * `drop_collection`, `wipe_index`). Matched against action.tool, not the text,
 * so a todo app's `remove_item` only warns rather than blocks.
 */
const DESTRUCTIVE_TOOL_VERB =
  /^(?:delete|destroy|drop|wipe|purge|truncate|erase|remove|reset|teardown)$/i;

/**
 * Split a tool name into its constituent words across the conventions tool
 * authors actually use: snake_case, kebab-case, dot.case, and camelCase. A
 * plain `\b` boundary fails here because `_` is a word character, so
 * `delete_database` would never match `\bdelete\b`.
 */
function toolNameWords(tool: string): string[] {
  return tool
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2") // camelCase → camel Case
    .split(/[^A-Za-z0-9]+/) // snake_/kebab-/dot. separators
    .filter(Boolean);
}

/** True if any word in the tool name is a destructive verb. */
function toolNameIsDestructive(tool: string): boolean {
  return toolNameWords(tool).some((w) => DESTRUCTIVE_TOOL_VERB.test(w));
}

function evaluate(action: Action): RuleHit[] {
  // Shell + tool channels carry commands; file/network actions can still embed
  // SQL or git text, so we evaluate the normalized text for all channels.
  const hits = matchPatterns(action, PATTERNS, "destructive-command");

  // MCP tool whose name itself implies destruction, with no shell command to
  // match the patterns above. Advisory (warn) — it's a name heuristic, and the
  // operator reviews it in observe mode before deciding to enforce.
  if (
    action.channel === "mcp-tool" &&
    action.tool &&
    toolNameIsDestructive(action.tool) &&
    hits.length === 0
  ) {
    hits.push({
      ruleId: "destructive-command",
      decision: "warn",
      severity: "medium",
      title: `Destructive-sounding tool call (${action.tool})`,
      reason:
        "This tool's name implies it removes or resets data. Worth a look before letting the agent call it unattended.",
      remediation: "Confirm what this tool deletes and whether the target is recoverable.",
      evidence: action.text.slice(0, 120),
    });
  }

  return hits;
}

export const destructiveRule: Rule = {
  id: "destructive-command",
  evaluate,
};
