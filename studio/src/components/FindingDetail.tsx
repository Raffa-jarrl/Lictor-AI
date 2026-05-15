import { Show } from "solid-js";
import type { Finding } from "../lib/audit-types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  finding: Finding;
  onClose: () => void;
}

/**
 * Per-finding detail panel. Shown in a side panel or modal when the user
 * clicks a FindingCard.
 *
 * Sections:
 *   - Header: severity + title + close button
 *   - Plain-English summary
 *   - Evidence: file path + line + code snippet (if available)
 *   - The fix: 1-line summary + diff/snippet (if available)
 *   - Rotated secrets: explicit callout (if any)
 *   - Agent attribution: which agent found this (if recorded)
 */
export function FindingDetail(props: Props) {
  return (
    <div class="fixed inset-y-0 right-0 w-full md:w-2/5 lg:max-w-2xl bg-zinc-950 border-l border-zinc-800 shadow-2xl overflow-y-auto z-50">
      <div class="sticky top-0 bg-zinc-950 border-b border-zinc-800 px-6 py-4 flex items-start justify-between">
        <div class="space-y-1.5 pr-4">
          <SeverityBadge severity={props.finding.severity} size="md" />
          <h2 class="text-xl text-zinc-100 font-semibold leading-snug">
            {props.finding.title}
          </h2>
          <Show when={props.finding.id}>
            <p class="text-xs text-zinc-500 font-mono">{props.finding.id}</p>
          </Show>
        </div>
        <button
          type="button"
          onClick={props.onClose}
          class="text-zinc-500 hover:text-zinc-200 text-2xl leading-none"
          aria-label="Close"
        >
          ×
        </button>
      </div>

      <div class="px-6 py-6 space-y-6">
        {/* Plain-English summary */}
        <section>
          <h3 class="text-xs uppercase text-zinc-500 mb-2">What this is</h3>
          <p class="text-zinc-200 leading-relaxed">{props.finding.summary}</p>
        </section>

        {/* Evidence */}
        <Show when={props.finding.evidence}>
          <section>
            <h3 class="text-xs uppercase text-zinc-500 mb-2">Where we found it</h3>
            <div class="bg-zinc-900 border border-zinc-800 rounded p-3 font-mono text-xs">
              <div class="text-amber-400">
                {props.finding.evidence!.file_path}
                <Show when={props.finding.evidence?.line}>
                  <span class="text-zinc-500">
                    :{props.finding.evidence!.line}
                  </span>
                </Show>
              </div>
              <Show when={props.finding.evidence?.code_snippet}>
                <pre class="mt-2 text-zinc-300 whitespace-pre-wrap overflow-x-auto">
                  {props.finding.evidence!.code_snippet}
                </pre>
              </Show>
            </div>
          </section>
        </Show>

        {/* Fix */}
        <Show when={props.finding.fix}>
          <section>
            <h3 class="text-xs uppercase text-zinc-500 mb-2">How to fix it</h3>
            <Show when={props.finding.fix!.summary}>
              <p class="text-zinc-200 leading-relaxed mb-3">
                {props.finding.fix!.summary}
              </p>
            </Show>
            <Show when={props.finding.fix!.diff_or_snippet}>
              <pre class="bg-zinc-900 border border-zinc-800 rounded p-3 text-xs font-mono text-zinc-300 whitespace-pre-wrap overflow-x-auto">
                {props.finding.fix!.diff_or_snippet}
              </pre>
            </Show>
          </section>
        </Show>

        {/* Rotated secrets warning */}
        <Show
          when={
            props.finding.fix?.rotated_secrets_needed &&
            props.finding.fix.rotated_secrets_needed.length > 0
          }
        >
          <section class="bg-red-950/40 border border-red-800 rounded-lg p-4">
            <h3 class="text-sm font-semibold text-red-300 mb-2">
              ⚠ Rotate these secrets immediately
            </h3>
            <ul class="space-y-1">
              {props.finding.fix!.rotated_secrets_needed!.map((s) => (
                <li class="font-mono text-sm text-red-200">{s}</li>
              ))}
            </ul>
            <p class="text-xs text-red-300/80 mt-3">
              Rotation runbook: run{" "}
              <code class="bg-red-900/40 px-1 rounded">/lictor-rotate</code> in
              Claude Code for provider-specific steps.
            </p>
          </section>
        </Show>

        {/* Agent attribution */}
        <Show when={props.finding.agent}>
          <section class="text-xs text-zinc-500 border-t border-zinc-800 pt-4">
            Found by{" "}
            <span class="text-zinc-300 font-medium capitalize">
              {props.finding.agent}
            </span>
            <Show when={props.finding.agent_confidence !== undefined}>
              <span>
                {" "}
                · confidence {(props.finding.agent_confidence! * 100).toFixed(0)}%
              </span>
            </Show>
          </section>
        </Show>

        {/* References */}
        <Show
          when={props.finding.references && props.finding.references.length > 0}
        >
          <section>
            <h3 class="text-xs uppercase text-zinc-500 mb-2">Learn more</h3>
            <ul class="space-y-1">
              {props.finding.references!.map((url) => (
                <li>
                  <a
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-sm text-amber-400 hover:text-amber-300 break-all"
                  >
                    {url}
                  </a>
                </li>
              ))}
            </ul>
          </section>
        </Show>
      </div>
    </div>
  );
}
