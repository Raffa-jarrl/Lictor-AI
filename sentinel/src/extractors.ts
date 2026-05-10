/**
 * Provider-specific extractors.
 *
 * Sentinel's `wrap()` intercepts SDK calls but doesn't know what their
 * arguments and return values look like — those are provider-specific.
 * This module knows how to pull text out of OpenAI / Anthropic / other
 * shapes without depending on those SDKs at runtime.
 *
 * Adding a new provider = adding a new entry in `KNOWN_PATHS` and a pair
 * of extractors here.
 */

import type { IncidentEvent } from "./types.js";

type Provider = IncidentEvent["model"]["provider"];

/** What's known about an intercepted method path. */
export interface InterceptInfo {
  provider: Provider;
}

/**
 * Map of dot-paths (relative to the wrapped client) → provider info.
 * `client.chat.completions.create` → 'chat.completions.create'.
 */
export const KNOWN_PATHS: Record<string, InterceptInfo> = {
  // OpenAI Node SDK
  "chat.completions.create": { provider: "openai" },
  "completions.create": { provider: "openai" }, // legacy text completions

  // Anthropic Node SDK
  "messages.create": { provider: "anthropic" },
};

// ─── Input extractors ────────────────────────────────────────────────────────

/**
 * Pull the user-text out of the arguments to a model call. Returns a
 * single concatenated string — checks operate on a flat string.
 */
export function extractInputText(provider: Provider, args: unknown[]): string {
  const arg0 = args[0];
  if (!arg0 || typeof arg0 !== "object") return "";

  if (provider === "openai" || provider === "anthropic") {
    return extractMessages((arg0 as { messages?: unknown }).messages);
  }
  return "";
}

/** Pull the model name (e.g. "gpt-4", "claude-3-sonnet") from args. */
export function extractModelName(_provider: Provider, args: unknown[]): string {
  const arg0 = args[0];
  if (!arg0 || typeof arg0 !== "object") return "unknown";
  const m = (arg0 as { model?: unknown }).model;
  return typeof m === "string" ? m : "unknown";
}

/**
 * Walk a `messages: [{role, content}]` array and concatenate the text.
 * Handles both string content and OpenAI/Anthropic content-part arrays
 * (`[{type: 'text', text: '...'}]`).
 */
function extractMessages(messages: unknown): string {
  if (!Array.isArray(messages)) return "";
  const out: string[] = [];
  for (const m of messages) {
    if (!m || typeof m !== "object") continue;
    const content = (m as { content?: unknown }).content;
    if (typeof content === "string") {
      out.push(content);
    } else if (Array.isArray(content)) {
      for (const part of content) {
        if (part && typeof part === "object") {
          const t = (part as { text?: unknown }).text;
          if (typeof t === "string") out.push(t);
        }
      }
    }
  }
  return out.join("\n");
}

// ─── Output extractors ───────────────────────────────────────────────────────

/** Pull the model's text response out of a (non-streaming) result. */
export function extractOutputText(provider: Provider, response: unknown): string {
  if (!response || typeof response !== "object") return "";

  if (provider === "openai") {
    // chat.completions: response.choices[].message.content
    // legacy completions: response.choices[].text
    const choices = (response as { choices?: unknown }).choices;
    if (!Array.isArray(choices)) return "";
    const out: string[] = [];
    for (const c of choices) {
      if (!c || typeof c !== "object") continue;
      const message = (c as { message?: { content?: unknown } }).message;
      if (message && typeof message.content === "string") {
        out.push(message.content);
        continue;
      }
      const text = (c as { text?: unknown }).text;
      if (typeof text === "string") out.push(text);
    }
    return out.join("\n");
  }

  if (provider === "anthropic") {
    // messages.create: response.content[].text
    const content = (response as { content?: unknown }).content;
    if (!Array.isArray(content)) return "";
    const out: string[] = [];
    for (const part of content) {
      if (part && typeof part === "object") {
        const t = (part as { text?: unknown }).text;
        if (typeof t === "string") out.push(t);
      }
    }
    return out.join("\n");
  }

  return "";
}
