/**
 * Action constructors.
 *
 * Rules evaluate a normalized `Action` (see types.ts). These helpers build one
 * from the two channels Airlock intercepts:
 *
 *   - shellAction(cmd)        — a raw shell command line
 *   - toolAction(name, args)  — an MCP tool call (name + structured args)
 *
 * The tricky part is MCP: many tool calls are *themselves* a shell command
 * wrapped in a tool (Claude Code's `bash` tool, an MCP server's
 * `execute_command`, etc.). toolAction() unwraps those so the same shell rules
 * apply, and renders everything else into a single matchable text line.
 */

import type { Action, ActionChannel } from "./types.js";

export interface ActionOptions {
  cwd?: string;
  source?: string;
}

/** Collapse whitespace/newlines so multi-line commands match single-line patterns. */
function normalizeText(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/** Build an Action from a raw shell command line. */
export function shellAction(command: string, opts: ActionOptions = {}): Action {
  const action: Action = {
    channel: "shell",
    command,
    text: normalizeText(command),
  };
  if (opts.cwd !== undefined) action.cwd = opts.cwd;
  if (opts.source !== undefined) action.source = opts.source;
  return action;
}

/** Tool names that are really "run this shell command" wrappers. */
const SHELL_TOOL_NAMES =
  /^(?:bash|sh|shell|exec|execute|execute_command|run|run_command|run_shell|run_terminal_cmd|command|terminal|cmd|system)$/i;

/** Arg keys that carry a shell command / script body. */
const COMMAND_ARG_KEYS = ["command", "cmd", "script", "code", "shell", "input", "commandLine"];

/** Arg keys that carry a target filesystem path. */
const PATH_ARG_KEYS = ["path", "file_path", "filePath", "filename", "file", "target", "dest", "destination"];

function firstString(args: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "string" && v.length > 0) return v;
  }
  return undefined;
}

/** Flatten args into a compact, matchable string for generic tools. */
function renderArgs(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(args)) {
    if (v == null) continue;
    if (typeof v === "string") parts.push(`${k}=${v}`);
    else if (typeof v === "number" || typeof v === "boolean") parts.push(`${k}=${v}`);
    else {
      try {
        parts.push(`${k}=${JSON.stringify(v)}`);
      } catch {
        parts.push(`${k}=[object]`);
      }
    }
  }
  return parts.join(" ");
}

/**
 * Build an Action from an MCP tool call. Unwraps shell-wrapper tools into a
 * "shell" action; classifies path-bearing writes as "file-write"; renders
 * everything else as a generic "mcp-tool" action.
 */
export function toolAction(
  tool: string,
  args: Record<string, unknown> = {},
  opts: ActionOptions = {},
): Action {
  const command = firstString(args, COMMAND_ARG_KEYS);
  const path = firstString(args, PATH_ARG_KEYS);

  // A shell-wrapper tool, or any tool whose args carry a command body → treat
  // the embedded command as a shell action so all shell rules apply.
  if (SHELL_TOOL_NAMES.test(tool) || (command && command.length > 0)) {
    const cmd = command ?? "";
    const action: Action = {
      channel: "shell",
      tool,
      args,
      command: cmd,
      text: normalizeText(cmd || `${tool} ${renderArgs(args)}`),
    };
    if (opts.cwd !== undefined) action.cwd = opts.cwd;
    if (opts.source !== undefined) action.source = opts.source;
    return action;
  }

  // A file write/edit tool → file-write channel (path captured for rules).
  let channel: ActionChannel = "mcp-tool";
  if (path && /write|create|edit|save|append|put|upload|patch/i.test(tool)) {
    channel = "file-write";
  }

  const action: Action = {
    channel,
    tool,
    args,
    text: normalizeText(`${tool} ${renderArgs(args)}`),
  };
  if (path !== undefined) action.path = path;
  if (opts.cwd !== undefined) action.cwd = opts.cwd;
  if (opts.source !== undefined) action.source = opts.source;
  return action;
}
