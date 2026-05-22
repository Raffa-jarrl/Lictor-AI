"""Anti-ransomware external exposure scanner.

Detects services and CVEs that are the top ransomware entry vectors:
- Exposed RDP (3389), SMB (445), RPC (135), WinRM (5985/5986), NetBIOS (139)
- VPN gateway fingerprints with known KEV CVEs (Fortinet/Citrix/Pulse/SonicWall)
- Outdated Exchange OWA / SharePoint (Hafnium, ProxyShell, ProxyLogon)
- Public remote-access tools (TeamViewer, AnyDesk, ScreenConnect)
- Public file-share platforms (MOVEit, GoAnywhere, Accellion FTA)

For each host, compute a "Ransomware Readiness Score":
  100 = clean (no risky exposures)
  <70 = at significant risk
  <50 = immediate attention needed (multiple critical exposures)
"""
import socket, json, sys, urllib.request, ssl, re
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "ransomware-exposure.jsonl"

# Ports that are TOP ransomware entry vectors when exposed externally
RISKY_PORTS = {
    3389: ("RDP", "CRITICAL", "RDP exposed externally — top ransomware entry vector. BlueKeep, brute-force, leaked creds."),
    445:  ("SMB", "CRITICAL", "SMB exposed externally — EternalBlue / SMBGhost CVEs / leaked credential attacks"),
    135:  ("RPC", "HIGH",     "RPC exposed externally — endpoint mapper for lateral movement"),
    139:  ("NetBIOS", "HIGH", "NetBIOS exposed externally — null sessions, enumeration"),
    5985: ("WinRM-HTTP", "HIGH", "WinRM HTTP exposed — remote management, often default-credential"),
    5986: ("WinRM-HTTPS", "MEDIUM", "WinRM HTTPS exposed — same risk as WinRM but encrypted"),
    23:   ("Telnet", "CRITICAL", "Telnet exposed — cleartext credentials, often legacy network gear default creds"),
    21:   ("FTP", "HIGH", "FTP exposed — cleartext credentials, frequent target for credential reuse"),
    8443: ("HTTPS-alt", "INFO", "Alternative HTTPS port — verify if intentional"),
    4444: ("Metasploit-default", "MEDIUM", "Port 4444 is Metasploit's default handler — verify legitimate"),
}

# HTTP banners that indicate vulnerable VPN/remote-access products
HTTP_FINGERPRINTS = [
    # Fortinet FortiOS (Vista MAJOR CVEs in CISA KEV)
    (re.compile(rb"FortiGate|FortiOS|fgt_lang|fortinet", re.I),
     "CRITICAL", "Fortinet FortiGate detected — multiple CISA KEV CVEs (CVE-2024-21762, CVE-2023-27997, CVE-2022-42475 RCEs)"),
    # Citrix NetScaler / ADC
    (re.compile(rb"NetScaler|Citrix Gateway|nsdcontroller|/vpn/index\.html", re.I),
     "CRITICAL", "Citrix NetScaler/ADC detected — CitrixBleed CVE-2023-4966, CVE-2023-3519 known-exploited"),
    # Pulse Secure / Ivanti Connect Secure
    (re.compile(rb"Pulse Secure|Ivanti Connect Secure|/dana-na/", re.I),
     "CRITICAL", "Pulse Secure / Ivanti Connect Secure detected — CVE-2024-21887, CVE-2023-46805 known-exploited"),
    # SonicWall SMA / NetExtender
    (re.compile(rb"SonicWall|sonicwall|/cgi-bin/welcome", re.I),
     "HIGH", "SonicWall detected — CVE-2021-20016, CVE-2024-40766 known-exploited"),
    # MOVEit Transfer
    (re.compile(rb"MOVEit|MoveIT Transfer|ipswitch", re.I),
     "CRITICAL", "MOVEit Transfer detected — CVE-2023-34362 (Cl0p ransomware mass-exploitation)"),
    # GoAnywhere MFT
    (re.compile(rb"GoAnywhere MFT|HelpSystems", re.I),
     "CRITICAL", "GoAnywhere MFT detected — CVE-2023-0669 (Cl0p ransomware exploitation)"),
    # Exchange OWA
    (re.compile(rb"/owa/|outlook web access|Exchange Server", re.I),
     "MEDIUM", "Exchange OWA detected — verify patches for ProxyShell/ProxyLogon (Hafnium-era)"),
    # SharePoint
    (re.compile(rb"SharePoint|_layouts/15/", re.I),
     "MEDIUM", "SharePoint detected — verify patches for ToolShell / CVE-2023-29357"),
    # TeamViewer
    (re.compile(rb"TeamViewer", re.I),
     "MEDIUM", "TeamViewer detected — verify is intentional + locked down"),
    # ConnectWise ScreenConnect
    (re.compile(rb"ScreenConnect|ConnectWise Control", re.I),
     "HIGH", "ScreenConnect/ConnectWise Control detected — CVE-2024-1709 (auth bypass)"),
    # Confluence
    (re.compile(rb"Confluence|Atlassian", re.I),
     "MEDIUM", "Confluence detected — check for OGNL injection CVEs"),
    # PrintNightmare (network printer)
    (re.compile(rb"HP LaserJet|Canon imageRUNNER", re.I),
     "INFO", "Network printer detected — verify firmware patched against PrintNightmare-class"),
]


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return True
    except: return False


def check_http_fingerprint(host, port=443, timeout=8):
    """GET / on HTTPS to fingerprint product."""
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    findings = []
    for scheme, port_v in (("https", 443), ("http", 80)):
        try:
            req = urllib.request.Request(f"{scheme}://{host}:{port_v}/", headers={"User-Agent": "Lictor-RansomScan"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(4000)
                server = r.headers.get("Server", "")
                # Check headers + body for fingerprints
                for pattern, sev, msg in HTTP_FINGERPRINTS:
                    if pattern.search(body) or pattern.search(server.encode() if server else b""):
                        findings.append({"severity": sev, "issue": msg, "detected_via": f"{scheme}://{host}:{port_v}"})
        except Exception:
            continue
        if findings: break  # one scheme is enough
    return findings


def audit_host(host):
    findings = []
    # Port check
    port_results = {}
    for port, (name, sev, msg) in RISKY_PORTS.items():
        if check_port(host, port, timeout=2):
            port_results[port] = name
            findings.append({"severity": sev, "issue": f"Port {port} ({name}) externally accessible — {msg}", "detected_via": f"tcp://{host}:{port}"})

    # HTTP fingerprints
    http_findings = check_http_fingerprint(host)
    findings.extend(http_findings)

    if not findings: return None

    # Score: 100 - penalty per finding
    penalty_map = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}
    total_penalty = sum(penalty_map.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - total_penalty)

    return {
        "host": host,
        "ransomware_readiness_score": score,
        "open_risky_ports": list(port_results.keys()),
        "findings": findings,
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
    print(f"[+] Anti-ransomware exposure scan — {len(hosts)} hosts", flush=True)
    print(f"[+] Probes: {len(RISKY_PORTS)} risky ports + {len(HTTP_FINGERPRINTS)} VPN/RAT/MFT product fingerprints", flush=True)
    all_findings = []
    completed = 0
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = {pool.submit(audit_host, h): h for h in hosts}
        for fut in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} with ransomware exposure", flush=True)
            try:
                r = fut.result(timeout=60)
                if r:
                    all_findings.append(r)
                    crit = [f for f in r["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
                    if crit:
                        print(f"  🔴 {r['host']}  score={r['ransomware_readiness_score']}", flush=True)
                        for f in crit[:3]:
                            print(f"      [{f['severity']}] {f['issue'][:90]}", flush=True)
            except Exception: pass

    print(f"\n[+] Ransomware-exposure scan complete: {len(all_findings)} hosts with at least one issue", flush=True)
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for r in all_findings: f.write(json.dumps(r) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
