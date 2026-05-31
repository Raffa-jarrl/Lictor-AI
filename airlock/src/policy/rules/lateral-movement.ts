/**
 * Rule: lateral-movement.
 *
 * Fear #3, and the one IT says out loud: "I can run AI on a laptop, but I can't
 * let it reach the rest of the network." This is the heart of Airlock's
 * isolation promise — keep the agent on the local machine, off the LAN, and
 * away from the cloud metadata endpoint.
 *
 * Anything that reaches a private/LAN/link-local host or the cloud
 * instance-metadata service is the signal. Scanning tools (nmap/masscan) are
 * flagged regardless of target — there's no benign reason for an AI coding
 * agent to port-scan.
 */

import type { Action, Rule, RuleHit } from "../../types.js";
import {
  matchPatterns,
  type Pattern,
  PRIVATE_HOST_RE,
  METADATA_HOST_RE,
} from "../match.js";

const PATTERNS: Pattern[] = [
  {
    // The cloud metadata endpoint — reaching it = harvesting cloud credentials.
    re: METADATA_HOST_RE,
    decision: "block",
    severity: "critical",
    title: "Cloud metadata endpoint access",
    reason:
      "169.254.169.254 (and friends) hands out the machine's cloud credentials. Reaching it is how an agent escalates from this box into your whole cloud account.",
    remediation: "Block this endpoint at the host firewall. No application code should hit it ad hoc.",
  },
  {
    // ssh / telnet into a private host.
    re: /(?:^|[\s;&|])(?:ssh|telnet|mosh)\b[^\n]*?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:local|internal|lan|corp|intranet))\b/i,
    decision: "block",
    severity: "high",
    title: "SSH/telnet to a LAN host",
    reason:
      "The agent is opening a session to another machine on your internal network — exactly the lateral movement isolation is meant to prevent.",
    remediation: "Keep the agent on this machine. Internal hosts should be reached by a person, not the AI.",
  },
  {
    // Any HTTP client aimed at a private/LAN/link-local host.
    re: /\b(?:curl|wget|http|https|xh|nc|ncat|socat)\b[^\n]*?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|[a-z0-9-]+\.(?:local|internal|lan|corp|intranet))\b/i,
    decision: "block",
    severity: "high",
    title: "Network request to a LAN/private host",
    reason:
      "This reaches a host on your internal network rather than the public internet — the agent is probing or talking to other machines.",
    remediation: "If the agent only needs the local machine, it should use 127.0.0.1, not a LAN address.",
    guard: (a: Action) => !METADATA_HOST_RE.test(a.text), // metadata handled above
  },
  {
    // Port / network scanners — no benign use for a coding agent.
    re: /(?:^|[\s;&|])(?:nmap|masscan|zmap|rustscan|unicornscan)\b/i,
    decision: "block",
    severity: "high",
    title: "Port scanner",
    reason: "Network scanners map out other machines and services. An AI agent has no legitimate reason to run one.",
    remediation: "Remove the scan. If you genuinely need a network inventory, run it yourself, deliberately.",
  },
  {
    // arp/route/ip neighbor discovery — recon of the local network.
    re: /(?:^|[\s;&|])(?:arp\s+-a|ip\s+neigh|nbtscan|avahi-browse|arp-scan)\b/i,
    decision: "warn",
    severity: "medium",
    title: "Local network discovery",
    reason: "This enumerates other devices on the LAN — reconnaissance that precedes lateral movement.",
    remediation: "Not needed for local work. Confirm why the agent is mapping the network.",
  },
  {
    // SMB / network shares.
    re: /(?:^|[\s;&|])(?:smbclient|mount\s+-t\s+(?:cifs|nfs)|net\s+use)\b/i,
    decision: "warn",
    severity: "medium",
    title: "Network share access",
    reason: "Mounting an SMB/NFS share connects this machine to network storage that may hold other teams' data.",
    remediation: "Confirm the share is intended and the agent should be touching it.",
    guard: (a: Action) => PRIVATE_HOST_RE.test(a.text) || /\\\\|cifs|nfs|smb/i.test(a.text),
  },
];

function evaluate(action: Action): RuleHit[] {
  return matchPatterns(action, PATTERNS, "lateral-movement");
}

export const lateralMovementRule: Rule = {
  id: "lateral-movement",
  evaluate,
};
