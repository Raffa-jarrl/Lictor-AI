/**
 * Lictor Shield — service worker (background script).
 *
 * Responsibilities (target):
 *   - Receive findings from content scripts
 *   - Maintain a per-tab badge state (green / yellow / red)
 *   - Persist anonymous local-only history of audited origins (opt-in)
 *   - Surface real-time alarms when content script reports a sensitive
 *     surface being read by an AI agent
 *
 * Status: stub. Wire content-script → background message channel in Phase 1.
 */

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  where_found: string;
  remediation: string;
}

interface AuditMessage {
  type: 'audit-result';
  origin: string;
  findings: Finding[];
}

// Map: tabId -> highest-severity finding observed so far for that tab.
const tabSeverity = new Map<number, Severity>();

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function badgeForSeverity(s: Severity | undefined): { text: string; color: string } {
  if (!s || s === 'info') return { text: '', color: '#3D7C5E' };
  if (s === 'low') return { text: '·', color: '#3D7C5E' };
  if (s === 'medium') return { text: '!', color: '#D68910' };
  if (s === 'high') return { text: '!', color: '#C0392B' };
  return { text: '✕', color: '#C0392B' }; // critical
}

chrome.runtime.onMessage.addListener((msg: AuditMessage, sender) => {
  if (msg.type !== 'audit-result' || !sender.tab?.id) return;
  const tabId = sender.tab.id;

  const top: Severity =
    msg.findings.reduce<Severity>((acc, f) => maxSeverity(acc, f.severity), 'info');

  const previous = tabSeverity.get(tabId);
  const next = previous ? maxSeverity(previous, top) : top;
  tabSeverity.set(tabId, next);

  const badge = badgeForSeverity(next);
  void chrome.action.setBadgeText({ tabId, text: badge.text });
  void chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabSeverity.delete(tabId);
});
