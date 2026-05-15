import { Show } from "solid-js";
import { SEVERITY_COLORS, SEVERITY_ICONS, type Severity } from "../lib/audit-types";

interface Props {
  severity: Severity;
  count?: number;
  size?: "sm" | "md" | "lg";
}

const SIZE_CLASSES = {
  sm: "text-xs px-1.5 py-0.5",
  md: "text-sm px-2 py-1",
  lg: "text-base px-3 py-1.5",
};

/**
 * Severity pill — used in the findings list, summary header, and per-finding
 * detail view. Always renders the icon (🔴🟠🟡🔵⚪) + the label, optionally
 * with a count for "header" usage like "🔴 Critical · 3".
 */
export function SeverityBadge(props: Props) {
  return (
    <span
      class={`inline-flex items-center gap-1 rounded font-medium ${
        SIZE_CLASSES[props.size ?? "md"]
      } ${SEVERITY_COLORS[props.severity]}`}
    >
      <span>{SEVERITY_ICONS[props.severity]}</span>
      <span class="uppercase tracking-wide">{props.severity}</span>
      <Show when={props.count !== undefined}>
        <span class="ml-1 opacity-70">· {props.count}</span>
      </Show>
    </span>
  );
}
