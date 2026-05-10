/**
 * Lictor Shield — popup script.
 *
 * Asks the background service worker for the current tab's audit state.
 * Renders a verdict header + finding list.
 */

import type { Finding, GetTabState, TabStateReply } from "../types.js";
import { severityRank, topSeverity } from "../types.js";

const SEVERITY_LABELS: Record<Finding["severity"], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const SEVERITY_PILL: Record<Finding["severity"], string> = {
  critical: "🟥",
  high: "🟧",
  medium: "🟨",
  low: "🟦",
  info: "⬜",
};

async function getCurrentTabState(): Promise<{ tabId: number | null; reply: TabStateReply | null }> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return { tabId: null, reply: null };
  const msg: GetTabState = { type: "get-tab-state", tabId: tab.id };
  const reply = (await chrome.runtime.sendMessage(msg)) as TabStateReply | undefined;
  return { tabId: tab.id, reply: reply ?? null };
}

function renderEmpty(): void {
  const status = document.getElementById("status")!;
  status.className = "status status--clean";
  status.querySelector(".status__title")!.textContent = "Nothing to audit here";
  status.querySelector(".status__sub")!.textContent =
    "Visit an AI-built site (Supabase, OpenAI/Anthropic, Vercel, etc.) to see audit results.";
}

function renderScanning(origin: string): void {
  const status = document.getElementById("status")!;
  status.className = "status status--scanning";
  status.querySelector(".status__title")!.textContent = "Scanning…";
  status.querySelector(".status__sub")!.textContent = origin;
}

function renderError(origin: string, err: string | undefined): void {
  const status = document.getElementById("status")!;
  status.className = "status status--critical";
  status.querySelector(".status__title")!.textContent = "Audit error";
  status.querySelector(".status__sub")!.textContent = err || origin;
}

function renderFindings(origin: string, findings: Finding[]): void {
  const status = document.getElementById("status")!;
  const list = document.getElementById("findings")!;

  if (findings.length === 0) {
    status.className = "status status--clean";
    status.querySelector(".status__title")!.textContent = "No findings";
    status.querySelector(".status__sub")!.textContent = origin;
    list.hidden = true;
    return;
  }

  // Sort by severity desc.
  const sorted = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const top = topSeverity(findings);
  const cls =
    top === "critical" || top === "high" ? "status--critical" :
    top === "medium"                     ? "status--warning"  :
                                           "status--clean";

  status.className = `status ${cls}`;
  status.querySelector(".status__title")!.textContent =
    `${findings.length} finding${findings.length === 1 ? "" : "s"} — top: ${SEVERITY_LABELS[top]}`;
  status.querySelector(".status__sub")!.textContent = origin;

  list.hidden = false;
  list.innerHTML = "";
  for (const f of sorted) {
    const li = document.createElement("li");
    li.className = `finding finding--${f.severity}`;
    li.innerHTML = `
      <div class="finding__head">
        <span class="finding__pill" aria-label="${SEVERITY_LABELS[f.severity]}">${SEVERITY_PILL[f.severity]}</span>
        <span class="finding__title">${escapeHtml(f.title)}</span>
      </div>
      <div class="finding__where mono">${escapeHtml(f.where_found)}</div>
    `;
    list.appendChild(li);
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function refresh(): Promise<void> {
  const { reply } = await getCurrentTabState();
  if (!reply || !reply.state) {
    renderEmpty();
    return;
  }
  const s = reply.state;
  if (s.status === "scanning") {
    renderScanning(s.origin);
    // Poll while still scanning.
    setTimeout(() => void refresh(), 700);
  } else if (s.status === "error") {
    renderError(s.origin, s.error);
  } else {
    renderFindings(s.origin, s.findings);
  }
}

void refresh().catch((e) => {
  console.error("[Lictor Shield popup]", e);
  renderError("(unknown)", String(e));
});
