import { For } from "solid-js";
import type { Summary, Severity } from "../lib/audit-types";
import { SEVERITY_ICONS } from "../lib/audit-types";

interface Props {
  summary: Summary;
  activeFilter?: Severity | "all";
  onFilterChange: (sev: Severity | "all") => void;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Summary bar at the top of the findings view. Shows the severity histogram
 * and lets the user filter by clicking.
 */
export function SummaryBar(props: Props) {
  return (
    <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-zinc-200 font-medium">
          {props.summary.total} finding{props.summary.total === 1 ? "" : "s"}
        </h2>
        <button
          type="button"
          onClick={() => props.onFilterChange("all")}
          class={`text-xs px-2 py-1 rounded transition-colors ${
            props.activeFilter === "all" || !props.activeFilter
              ? "bg-amber-500/20 text-amber-300"
              : "text-zinc-500 hover:text-zinc-300"
          }`}
        >
          All
        </button>
      </div>

      <div class="grid grid-cols-5 gap-2">
        <For each={SEVERITY_ORDER}>
          {(sev) => {
            const count = () => props.summary[sev];
            const active = () => props.activeFilter === sev;
            return (
              <button
                type="button"
                onClick={() => props.onFilterChange(sev)}
                disabled={count() === 0}
                class={`text-left p-2 rounded transition-colors ${
                  active()
                    ? "bg-zinc-800 ring-1 ring-amber-500"
                    : count() === 0
                      ? "opacity-30 cursor-not-allowed"
                      : "hover:bg-zinc-800"
                }`}
                aria-label={`Filter by ${sev} severity`}
              >
                <div class="text-lg">{SEVERITY_ICONS[sev]}</div>
                <div class="text-xs uppercase text-zinc-500 mt-1">{sev}</div>
                <div class="text-xl font-semibold text-zinc-100 mt-1">
                  {count()}
                </div>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
}
