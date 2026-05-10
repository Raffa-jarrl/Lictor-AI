/**
 * Lictor Shield — background service worker.
 *
 * Receives audit requests from content scripts, runs the WASM-backed audit
 * engine, maintains per-tab state, updates the toolbar badge, and answers
 * queries from the popup.
 */

import type {
  AuditRequest,
  ContentMessage,
  PopupMessage,
  TabAuditState,
  TabStateReply,
} from "./types.js";
import { topSeverity } from "./types.js";
import { audit } from "./audit-engine.js";

// Per-tab state. Cleared on tab close.
const tabState = new Map<number, TabAuditState>();

const BADGE_COLORS = {
  scanning: { text: "…", color: "#6E7780" },
  info:     { text: "",  color: "#3D7C5E" },
  low:      { text: "·", color: "#3D7C5E" },
  medium:   { text: "!", color: "#D68910" },
  high:     { text: "!", color: "#C0392B" },
  critical: { text: "✕", color: "#C0392B" },
  error:    { text: "?", color: "#6E7780" },
} as const;

function setBadge(tabId: number, kind: keyof typeof BADGE_COLORS) {
  const b = BADGE_COLORS[kind];
  void chrome.action.setBadgeText({ tabId, text: b.text });
  void chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function handleAuditRequest(req: AuditRequest, tabId: number): Promise<void> {
  // Mark scanning
  tabState.set(tabId, {
    origin: req.origin,
    status: "scanning",
    findings: [],
    startedAt: Date.now(),
  });
  setBadge(tabId, "scanning");

  try {
    const findings = await audit(req.origin, req.landingHtml);
    const top = findings.length === 0 ? "info" : topSeverity(findings);
    tabState.set(tabId, {
      origin: req.origin,
      status: "done",
      findings,
      startedAt: tabState.get(tabId)?.startedAt ?? Date.now(),
      completedAt: Date.now(),
    });
    setBadge(tabId, top);
    console.log(
      `[Lictor] tab ${tabId} ${req.origin}: ${findings.length} finding(s), top=${top}`
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    tabState.set(tabId, {
      origin: req.origin,
      status: "error",
      findings: [],
      startedAt: tabState.get(tabId)?.startedAt ?? Date.now(),
      completedAt: Date.now(),
      error: msg,
    });
    setBadge(tabId, "error");
    console.error(`[Lictor] tab ${tabId} ${req.origin} audit failed:`, e);
  }
}

chrome.runtime.onMessage.addListener(
  (msg: ContentMessage | PopupMessage, sender, sendResponse) => {
    if (msg.type === "audit-request") {
      const tabId = sender.tab?.id;
      if (typeof tabId === "number") {
        // Fire-and-forget. We don't sendResponse for this kind.
        void handleAuditRequest(msg, tabId);
      }
      return false;
    }

    if (msg.type === "get-tab-state") {
      const reply: TabStateReply = {
        type: "tab-state",
        tabId: msg.tabId,
        state: tabState.get(msg.tabId) ?? null,
      };
      sendResponse(reply);
      return false;
    }

    return false;
  }
);

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  // Reset state when navigating to a new URL.
  if (info.url) {
    tabState.delete(tabId);
    setBadge(tabId, "info"); // clears badge
    void chrome.action.setBadgeText({ tabId, text: "" });
  }
});

