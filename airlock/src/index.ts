/**
 * @lictor/airlock — public entrypoint.
 *
 * Airlock is the action boundary for AI agents. It watches and (optionally)
 * contains what an agent DOES on a machine — the shell commands it runs and the
 * MCP tool calls it makes — so an SMB can let AI work locally without it being
 * able to delete production, exfiltrate data, or reach across the LAN.
 *
 * Quick start:
 *
 *   import { createAirlock } from "@lictor/airlock";
 *   const airlock = createAirlock({ mode: "observe" }); // breaks nothing
 *   await airlock.guardShell("rm -rf build");           // logged
 *
 *   // when you trust the policy:
 *   const guard = createAirlock({ mode: "enforce" });
 *   await guard.guardShell("rm -rf /");                 // throws AirlockBlockedError
 *
 * MCP integration lives in "@lictor/airlock/mcp".
 */

export { createAirlock, type Airlock } from "./broker.js";
export { shellAction, toolAction, type ActionOptions } from "./actions.js";
export { redactSecrets, containsSecret } from "./redact.js";
export { ALL_RULES, registeredRuleIds, evaluateAction } from "./policy/index.js";
export { summarize, explain, actionPhrase } from "./audit/english.js";
export { defaultAuditPath, toEvent } from "./audit/logger.js";
export { toExitCode, BASH_PREEXEC_HOOK, ZSH_PREEXEC_HOOK } from "./shell/index.js";

export type {
  Severity,
  Decision,
  AirlockMode,
  ActionChannel,
  RuleId,
  Action,
  RuleHit,
  Rule,
  Verdict,
  AirlockEvent,
  GuardianConfig,
  AirlockConfig,
} from "./types.js";
export { AirlockBlockedError } from "./types.js";
export { airlockVersion } from "./version.js";
