import { createMemo, createSignal, For, Show } from "solid-js";
import { FindingCard } from "../components/FindingCard";
import { FindingDetail } from "../components/FindingDetail";
import { SummaryBar } from "../components/SummaryBar";
import { tauri } from "../lib/tauri";
import type { AuditDocument, Finding, Severity } from "../lib/audit-types";

/**
 * Findings view — shown after the audit completes.
 *
 * Layout:
 *   - Top: SummaryBar (severity histogram + filter)
 *   - Below: list of FindingCards (filtered by severity)
 *   - Side panel: FindingDetail (when a card is clicked)
 *
 * Toolbar actions: re-audit, export AUDIT.json, import AUDIT.json (universal
 * translator for other tools' output).
 */
export function FindingsView(props: { document: AuditDocument; onReaudit: () => void }) {
  const [filter, setFilter] = createSignal<Severity | "all">("all");
  const [selected, setSelected] = createSignal<Finding | null>(null);
  const [exporting, setExporting] = createSignal(false);

  const filtered = createMemo(() => {
    const f = filter();
    if (f === "all") return props.document.findings;
    return props.document.findings.filter((x) => x.severity === f);
  });

  async function handleExport() {
    setExporting(true);
    try {
      const path = await tauri.exportAuditJson(props.document);
      console.log("Exported to:", path);
      // TODO: surface the path in a toast — for v0.1.0-pre.1 we just log.
    } catch (e) {
      console.error("Export failed:", e);
    } finally {
      setExporting(false);
    }
  }

  async function handleImport() {
    const imported = await tauri.importAuditJson();
    if (imported) {
      // For v0.1.0-pre.1 the import replaces the current view.
      // v0.2.0 will add a side-by-side compare view.
      window.location.reload();
    }
  }

  return (
    <main class="min-h-screen bg-zinc-950 text-zinc-100">
      <header class="border-b border-zinc-800 px-6 py-4 flex items-center gap-3 sticky top-0 bg-zinc-950 z-10">
        <img src="/lictor-mark.svg" alt="" class="w-7 h-7" />
        <h1 class="text-lg font-semibold">
          Lictor <span class="text-amber-400">Studio</span>
        </h1>
        <span class="text-xs text-zinc-500 ml-2 font-mono truncate max-w-md">
          {props.document.target.url_or_path}
        </span>
        <Show when={props.document.target.platform_fingerprint}>
          <span class="text-xs text-zinc-500 font-mono capitalize">
            · {props.document.target.platform_fingerprint}
          </span>
        </Show>

        <div class="ml-auto flex gap-2 text-sm">
          <button
            type="button"
            onClick={handleImport}
            class="px-3 py-1.5 rounded border border-zinc-700 hover:bg-zinc-800 text-zinc-300"
          >
            Import AUDIT.json
          </button>
          <button
            type="button"
            onClick={handleExport}
            disabled={exporting()}
            class="px-3 py-1.5 rounded border border-zinc-700 hover:bg-zinc-800 text-zinc-300 disabled:opacity-50"
          >
            {exporting() ? "Exporting…" : "Export"}
          </button>
          <button
            type="button"
            onClick={props.onReaudit}
            class="px-3 py-1.5 rounded bg-amber-500 text-zinc-950 hover:bg-amber-400 font-medium"
          >
            Re-audit
          </button>
        </div>
      </header>

      <div class="max-w-4xl mx-auto px-6 py-6 space-y-6">
        <SummaryBar
          summary={props.document.summary}
          activeFilter={filter()}
          onFilterChange={setFilter}
        />

        <Show
          when={filtered().length > 0}
          fallback={
            <div class="text-center py-12 text-zinc-500">
              <p>No findings at this severity level.</p>
              <button
                type="button"
                onClick={() => setFilter("all")}
                class="text-amber-400 hover:text-amber-300 mt-2 text-sm"
              >
                Show all findings
              </button>
            </div>
          }
        >
          <div class="space-y-2">
            <For each={filtered()}>
              {(finding) => (
                <FindingCard finding={finding} onClick={setSelected} />
              )}
            </For>
          </div>
        </Show>

        <footer class="text-xs text-zinc-500 border-t border-zinc-800 pt-4 space-y-1">
          <p>
            Audit ran in{" "}
            {props.document.audit.duration_ms !== undefined
              ? `${(props.document.audit.duration_ms / 1000).toFixed(1)}s`
              : "—"}
            {" · "}
            {props.document.audit.checks_run ?? "—"} checks {" · "}
            Lictor {props.document.tool.version}
          </p>
          <p>
            Local-only. No telemetry. Apache 2.0.
          </p>
        </footer>
      </div>

      <Show when={selected()}>
        <FindingDetail finding={selected()!} onClose={() => setSelected(null)} />
      </Show>
    </main>
  );
}
