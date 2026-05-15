import { Show } from "solid-js";
import type { Finding } from "../lib/audit-types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  finding: Finding;
  onClick: (finding: Finding) => void;
}

/**
 * Single finding row in the findings list. Click → opens the detail view.
 *
 * Renders: severity pill, title, evidence hint (file:line), category tag.
 * No code preview in the card — that's the detail view's job. Stays compact
 * so 20+ findings fit on one screen.
 */
export function FindingCard(props: Props) {
  return (
    <button
      type="button"
      onClick={() => props.onClick(props.finding)}
      class="w-full text-left bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded-lg p-4 transition-colors space-y-2 group"
    >
      <div class="flex items-center gap-3">
        <SeverityBadge severity={props.finding.severity} size="sm" />
        <Show when={props.finding.category}>
          <span class="text-xs text-zinc-500 font-mono">
            {props.finding.category}
          </span>
        </Show>
      </div>

      <h3 class="text-zinc-100 font-medium leading-snug group-hover:text-amber-400 transition-colors">
        {props.finding.title}
      </h3>

      <Show when={props.finding.evidence?.file_path}>
        <p class="text-xs text-zinc-500 font-mono truncate">
          {props.finding.evidence!.file_path}
          <Show when={props.finding.evidence?.line}>
            :{props.finding.evidence!.line}
          </Show>
        </p>
      </Show>
    </button>
  );
}
