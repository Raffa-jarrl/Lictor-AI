import { createSignal, onMount, Show } from "solid-js";
import { tauri } from "./lib/tauri";
import { FindingsView } from "./routes/findings";
import type { AuditDocument } from "./lib/audit-types";

/**
 * Studio shell — v0.1.0-pre.1
 *
 * State machine: drop-zone → auditing → findings view → re-audit.
 * The findings flow now wires through lictor-core for a real audit (no longer
 * a stub).
 */
export default function App() {
  const [version, setVersion] = createSignal<string | null>(null);
  const [auditing, setAuditing] = createSignal(false);
  const [document, setDocument] = createSignal<AuditDocument | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  onMount(async () => {
    setVersion(await tauri.getAppVersion());
  });

  async function pickProjectAndAudit() {
    setAuditing(true);
    setError(null);
    try {
      const result = await tauri.pickFolderAndAudit();
      if (result) {
        setDocument(result);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Audit failed");
    } finally {
      setAuditing(false);
    }
  }

  return (
    <>
      <Show
        when={document()}
        fallback={
          <DropZoneView
            version={version()}
            auditing={auditing()}
            error={error()}
            onPick={pickProjectAndAudit}
          />
        }
      >
        <FindingsView
          document={document()!}
          onReaudit={() => {
            setDocument(null);
            pickProjectAndAudit();
          }}
        />
      </Show>
    </>
  );
}

function DropZoneView(props: {
  version: string | null;
  auditing: boolean;
  error: string | null;
  onPick: () => void;
}) {
  return (
    <div class="min-h-screen flex flex-col bg-zinc-950 text-zinc-100">
      <header class="border-b border-zinc-800 px-6 py-4 flex items-center gap-3">
        <img src="/lictor-mark.svg" alt="" class="w-7 h-7" />
        <h1 class="text-xl font-semibold">
          Lictor <span class="text-amber-400">Studio</span>
        </h1>
        <Show when={props.version}>
          <span class="ml-auto text-xs text-zinc-500 font-mono">
            v{props.version}
          </span>
        </Show>
      </header>

      <main class="flex-1 px-6 py-12 max-w-3xl mx-auto w-full">
        <div class="space-y-6">
          <h2 class="text-2xl font-medium">
            The security crew for apps you built with AI.
          </h2>
          <p class="text-zinc-400 leading-relaxed">
            Drop a project folder below to run a local audit. Eleven specialist
            agents walk your code, find what's broken, and explain the fix in
            plain English. Nothing leaves your machine.
          </p>

          <div
            class="border-2 border-dashed border-zinc-700 rounded-lg p-12 text-center hover:border-amber-500 transition-colors cursor-pointer"
            onClick={props.onPick}
          >
            <p class="text-zinc-300">
              {props.auditing
                ? "Auditing your project…"
                : "Drop a project folder, or click to browse"}
            </p>
            <p class="text-xs text-zinc-500 mt-2">
              Local-only. No signup. No telemetry. Apache 2.0.
            </p>
          </div>

          <Show when={props.error}>
            <div class="border border-red-800 bg-red-950/40 rounded p-4 text-sm text-red-200">
              <strong class="block mb-1">Audit failed</strong>
              <span class="text-red-300 font-mono text-xs">{props.error}</span>
            </div>
          </Show>
        </div>
      </main>

      <footer class="border-t border-zinc-800 px-6 py-3 text-xs text-zinc-500 flex justify-between">
        <span>Lictor Studio — offline by design.</span>
        <a
          href="https://lictorai.com"
          target="_blank"
          rel="noopener"
          class="hover:text-amber-400"
        >
          lictorai.com
        </a>
      </footer>
    </div>
  );
}
