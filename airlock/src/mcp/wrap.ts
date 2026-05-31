/**
 * MCP interception.
 *
 * This is the high-signal channel: an MCP tool call carries semantic intent —
 * the tool name and structured arguments — so the broker can reason about what
 * the agent is *trying* to do, not just guess from a shell string.
 *
 * Two primitives, no hard dependency on @modelcontextprotocol/sdk:
 *
 *   guardToolDispatch(dispatch, opts)
 *     Wrap any `(name, args) => result` function. The generic primitive.
 *
 *   guardCallToolHandler(handler, opts)
 *     Wrap a standard MCP SDK CallTool handler `(request) => result`, where
 *     request is `{ params: { name, arguments } }`. Drop-in for
 *     server.setRequestHandler(CallToolRequestSchema, guardCallToolHandler(fn)).
 *
 * In observe mode the call is logged and passed through unchanged. In enforce
 * mode a blocked call never reaches the real tool — instead the wrapper returns
 * an MCP error result the model can read ("blocked by Airlock, here's why"), so
 * the agent adapts rather than the server crashing.
 */

import { createAirlock, type Airlock } from "../broker.js";
import { toolAction } from "../actions.js";
import { explain } from "../audit/english.js";
import { AirlockBlockedError, type AirlockConfig, type Verdict } from "../types.js";

export interface McpGuardOptions {
  /** Reuse an existing Airlock instance (share one audit log across handlers). */
  airlock?: Airlock;
  /** Or build one from config. Ignored if `airlock` is given. */
  config?: AirlockConfig;
  /**
   * Produce the result returned to the model when a call is blocked in enforce
   * mode. Defaults to a standard MCP error result.
   */
  onBlock?: (verdict: Verdict) => unknown;
}

/** Standard MCP-style "this is an error" tool result the model can read. */
export function defaultBlockedResult(verdict: Verdict): {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
} {
  return {
    content: [
      {
        type: "text",
        text:
          "This action was blocked by Lictor Airlock and was NOT executed.\n\n" +
          explain(verdict) +
          "\n\nIf this action is genuinely needed, ask the human operator to allow it.",
      },
    ],
    isError: true,
  };
}

function resolveAirlock(options: McpGuardOptions): Airlock {
  return options.airlock ?? createAirlock(options.config ?? {});
}

export type ToolDispatch<R> = (
  name: string,
  args: Record<string, unknown>,
) => Promise<R> | R;

/**
 * Wrap a generic `(name, args) => result` tool dispatcher with Airlock.
 */
export function guardToolDispatch<R>(
  dispatch: ToolDispatch<R>,
  options: McpGuardOptions = {},
): ToolDispatch<R> {
  const airlock = resolveAirlock(options);
  return async (name: string, args: Record<string, unknown>) => {
    const action = toolAction(name, args ?? {});
    try {
      await airlock.broker(action); // observe: logs + returns; enforce: may throw
    } catch (err) {
      if (err instanceof AirlockBlockedError) {
        return (options.onBlock?.(err.verdict) ?? defaultBlockedResult(err.verdict)) as R;
      }
      throw err;
    }
    return dispatch(name, args ?? {});
  };
}

/** The shape of an MCP CallTool request (subset we need). */
export interface CallToolRequestLike {
  params: {
    name: string;
    arguments?: Record<string, unknown>;
  };
}

/**
 * Wrap a standard MCP SDK CallTool handler. Use as:
 *
 *   server.setRequestHandler(
 *     CallToolRequestSchema,
 *     guardCallToolHandler(myHandler, { config: { mode: "enforce" } }),
 *   );
 */
export function guardCallToolHandler<Req extends CallToolRequestLike, Res>(
  handler: (request: Req) => Promise<Res> | Res,
  options: McpGuardOptions = {},
): (request: Req) => Promise<Res> {
  const airlock = resolveAirlock(options);
  return async (request: Req): Promise<Res> => {
    const name = request.params.name;
    const args = request.params.arguments ?? {};
    const action = toolAction(name, args);
    try {
      await airlock.broker(action);
    } catch (err) {
      if (err instanceof AirlockBlockedError) {
        return (options.onBlock?.(err.verdict) ?? defaultBlockedResult(err.verdict)) as Res;
      }
      throw err;
    }
    return handler(request);
  };
}
