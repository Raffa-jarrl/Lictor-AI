/**
 * Lictor Shield — popup script.
 *
 * Asks the active tab's content script for its current findings; renders
 * a quick verdict + scrollable list. Read-only — never writes anywhere.
 */

interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  where_found: string;
}

interface AuditSnapshot {
  origin: string;
  findings: Finding[];
}

const SEVERITY_LABELS: Record<Finding['severity'], string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

function rank(s: Finding['severity']): number {
  return ['info', 'low', 'medium', 'high', 'critical'].indexOf(s);
}

function topSeverity(findings: Finding[]): Finding['severity'] {
  return findings.reduce<Finding['severity']>(
    (acc, f) => (rank(f.severity) > rank(acc) ? f.severity : acc),
    'info',
  );
}

async function getActiveTabFindings(): Promise<AuditSnapshot | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return null;

  // TODO(Phase 1): replace with real round-trip to background.ts that holds
  // last audit per tab. For now, return a stub so the UI renders.
  return {
    origin: tab.url ? new URL(tab.url).origin : 'unknown',
    findings: [],
  };
}

function render(snapshot: AuditSnapshot | null) {
  const status = document.getElementById('status');
  const list = document.getElementById('findings');
  if (!status || !list) return;

  if (!snapshot) {
    status.className = 'status status--scanning';
    status.querySelector('.status__title')!.textContent = 'No active tab';
    return;
  }

  if (snapshot.findings.length === 0) {
    status.className = 'status status--clean';
    status.querySelector('.status__title')!.textContent = 'No findings';
    status.querySelector('.status__sub')!.textContent = snapshot.origin;
    return;
  }

  const top = topSeverity(snapshot.findings);
  const cls =
    top === 'critical' || top === 'high' ? 'status--critical' :
    top === 'medium'                    ? 'status--warning'  :
                                          'status--clean';

  status.className = `status ${cls}`;
  status.querySelector('.status__title')!.textContent =
    `${snapshot.findings.length} finding${snapshot.findings.length === 1 ? '' : 's'} — top: ${SEVERITY_LABELS[top]}`;
  status.querySelector('.status__sub')!.textContent = snapshot.origin;

  list.hidden = false;
  list.innerHTML = '';
  for (const f of snapshot.findings) {
    const li = document.createElement('li');
    li.innerHTML = `
      <div><strong>${f.title}</strong></div>
      <div class="mono" style="color: var(--text-muted)">${f.where_found}</div>
    `;
    list.appendChild(li);
  }
}

void getActiveTabFindings().then(render).catch((e) => {
  console.error('[Lictor Shield popup]', e);
  render(null);
});
