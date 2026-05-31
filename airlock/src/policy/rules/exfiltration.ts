/**
 * Rule: data-exfiltration.
 *
 * Fear #2: "the AI will quietly ship my data somewhere." This rule catches an
 * action *sending* local data out — uploading files, POSTing bodies to remote
 * hosts, piping local content into the network, or syncing to an external host.
 *
 * It deliberately does NOT flag ordinary downloads (curl/wget that only fetch)
 * — that's the supply-chain rule's job, and flagging every `curl` would be
 * noise. The signal here is *outbound payload*.
 */

import type { Action, Rule, RuleHit } from "../../types.js";
import { matchPatterns, type Pattern, PRIVATE_HOST_RE } from "../match.js";

const PATTERNS: Pattern[] = [
  {
    // curl/wget carrying an outbound body or file upload.
    re: /\b(?:curl|wget|http|https|xh)\b[^\n]*\s(?:-d\b|--data(?:-binary|-raw|-urlencode)?\b|-F\b|--form\b|-T\b|--upload-file\b|--data\b)/i,
    decision: "warn",
    severity: "high",
    title: "Outbound HTTP upload (curl/wget with a body)",
    reason:
      "This sends data out over HTTP — a request body or file upload. If that payload is your data, it just left the machine.",
    remediation:
      "Confirm the destination host and exactly what's in the body. If it includes local files or env values, don't send it.",
  },
  {
    // file piped/redirected into a network client.
    re: /(?:cat|tail|head|tar|zip|gzip|base64|env|printenv|cat\s+\S+)\b[^\n]*\|\s*(?:curl|wget|nc|ncat|netcat|socat|xh)\b/i,
    decision: "block",
    severity: "high",
    title: "Local data piped to the network",
    reason:
      "A local file (or the environment) is being piped straight into a network tool — a classic exfiltration shape.",
    remediation: "Don't pipe local contents into curl/nc. If you need to share a file, do it deliberately and review it first.",
  },
  {
    // netcat / socat used to push data out.
    re: /(?:^|[\s;&|])(?:nc|ncat|netcat|socat)\b[^\n]*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/i,
    decision: "warn",
    severity: "high",
    title: "Raw socket transfer (netcat/socat)",
    reason: "netcat/socat to a numeric host is often used to move data off a machine outside normal channels.",
    remediation: "Verify the destination IP. Prefer an auditable transfer (scp to a known host) if a transfer is intended.",
  },
  {
    // scp / rsync / sftp pushing to a remote (source is local, dest has host:).
    re: /(?:^|[\s;&|])(?:scp|rsync|sftp)\b[^\n]*\s[^\s]*@[^\s:]+:|(?:^|[\s;&|])(?:scp|rsync)\b[^\n]*\s[\w.-]+:[~/]/i,
    decision: "warn",
    severity: "medium",
    title: "Copy to a remote host (scp/rsync)",
    reason: "Files are being copied to a remote host. Fine if it's your server — a leak if the host isn't yours.",
    remediation: "Confirm the destination host belongs to you and the files are meant to leave this machine.",
    // Don't double-flag pushes to private/LAN hosts — lateral-movement owns those.
    guard: (a: Action) => !PRIVATE_HOST_RE.test(a.text),
  },
  {
    // Dumping the whole environment to anywhere networked.
    re: /\b(?:env|printenv|set)\b\s*(?:\|\s*(?:curl|wget|nc|ncat|socat))/i,
    decision: "block",
    severity: "critical",
    title: "Environment dumped to the network",
    reason:
      "The full environment — which usually holds API keys and tokens — is being sent over the network. That's a credential leak.",
    remediation: "Never pipe env/printenv into a network tool.",
  },
  {
    // Pastebin / transfer.sh / file.io style anonymous drop sites.
    re: /\b(?:curl|wget|xh)\b[^\n]*\b(?:pastebin\.com|hastebin\.com|paste\.ee|ix\.io|0x0\.st|transfer\.sh|file\.io|ngrok\.io|webhook\.site|requestbin\.\w+|pipedream\.net|burpcollaborator\.net|oast\.\w+|interact\.sh)\b/i,
    decision: "block",
    severity: "high",
    title: "Upload to an anonymous drop / collaborator site",
    reason:
      "The target is a throwaway paste or out-of-band collaborator host — where exfiltrated data and injection callbacks usually go.",
    remediation: "If you need to share output, use a destination you control and can audit.",
  },
];

function evaluate(action: Action): RuleHit[] {
  return matchPatterns(action, PATTERNS, "data-exfiltration");
}

export const exfiltrationRule: Rule = {
  id: "data-exfiltration",
  evaluate,
};
