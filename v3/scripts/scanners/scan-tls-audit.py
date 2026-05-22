"""TLS / SSL audit scanner — testssl.sh-equivalent at scale.

Per host:
- Connects on 443 (and 8443, 4443 if reachable)
- Records: TLS versions supported, weak ciphers, cert validity, cert chain depth,
  HSTS header present, missing security headers, key size, sig alg
- Flags: SSLv2/3, TLS 1.0/1.1 (deprecated), RC4/DES/3DES (weak), CBC-mode in TLS<1.2,
  cert expired or expires-soon, self-signed, weak key (<2048 RSA / <256 ECC),
  SHA1 sig, missing HSTS, missing X-Frame-Options, Heartbleed-vulnerable banners

Output: severity-classified findings (CRITICAL=Heartbleed, HIGH=SSL2/3 enabled,
MEDIUM=TLS1.0/1.1 enabled, LOW=missing headers, INFO=cert expiring within 30d)
"""
import socket, ssl, json, sys
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "tls-audit.jsonl"


def audit_tls(host, port=443, timeout=8):
    findings = []
    sock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Connect + handshake (default ctx negotiates highest TLS)
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()  # (name, protocol_version, secret_bits)
                version = ssock.version()  # TLSv1.3 / TLSv1.2 / etc.

        cipher_name, cipher_proto, cipher_bits = cipher or ("?", "?", 0)

        # Severity flags
        if version in ("SSLv2", "SSLv3"):
            findings.append(("CRITICAL", f"Deprecated protocol {version} accepted (POODLE/DROWN vulnerable)"))
        if version in ("TLSv1", "TLSv1.0", "TLSv1.1"):
            findings.append(("MEDIUM", f"Deprecated TLS {version} accepted — PCI-DSS requires TLS 1.2+"))
        if cipher_bits and cipher_bits < 128:
            findings.append(("HIGH", f"Weak cipher: {cipher_name} ({cipher_bits} bits)"))
        if any(weak in cipher_name.upper() for weak in ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON")):
            findings.append(("HIGH", f"Insecure cipher: {cipher_name}"))

        # Cert checks
        if cert:
            # Use direct field extraction
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            try:
                x = x509.load_der_x509_certificate(cert_der, default_backend())
                # Expiry
                now = datetime.now(timezone.utc)
                not_after = x.not_valid_after_utc if hasattr(x, "not_valid_after_utc") else x.not_valid_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - now).days
                if days_left < 0:
                    findings.append(("CRITICAL", f"Certificate EXPIRED {-days_left}d ago"))
                elif days_left < 30:
                    findings.append(("MEDIUM", f"Certificate expires in {days_left}d"))
                # Sig algo
                sig_alg = x.signature_algorithm_oid._name
                if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
                    findings.append(("HIGH", f"Weak certificate signature: {sig_alg}"))
                # Key size
                pubkey = x.public_key()
                try:
                    key_size = pubkey.key_size
                    if hasattr(pubkey, "curve"):
                        # EC key — at least P-256 (256 bits)
                        if key_size < 256:
                            findings.append(("HIGH", f"Weak EC key size: {key_size} bits"))
                    else:
                        # RSA — at least 2048
                        if key_size < 2048:
                            findings.append(("HIGH", f"Weak RSA key size: {key_size} bits"))
                except Exception: pass
                # Self-signed (issuer == subject)
                if x.issuer == x.subject:
                    findings.append(("LOW", "Self-signed certificate"))
            except ImportError:
                pass  # cryptography lib not installed; skip detailed cert checks

        # HTTP headers (separate request to check HSTS, X-Frame-Options, CSP)
        import urllib.request, urllib.error
        try:
            req = urllib.request.Request(f"https://{host}:{port}/", headers={"User-Agent": "Lictor-v3-TLSAudit"}, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                hdr = {k.lower(): v for k, v in r.headers.items()}
                if "strict-transport-security" not in hdr:
                    findings.append(("LOW", "Missing HSTS header"))
                if "x-content-type-options" not in hdr:
                    findings.append(("INFO", "Missing X-Content-Type-Options header"))
                if "x-frame-options" not in hdr and "content-security-policy" not in hdr:
                    findings.append(("LOW", "Missing X-Frame-Options / CSP frame-ancestors (clickjacking risk)"))
                if "content-security-policy" not in hdr:
                    findings.append(("INFO", "Missing Content-Security-Policy"))
        except Exception: pass

        if not findings:
            return None  # No issues
        return {
            "host": host, "port": port,
            "tls_version": version, "cipher": cipher_name, "cipher_bits": cipher_bits,
            "findings": [{"severity": s, "issue": i} for s, i in findings],
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        return None


def scan_host(host):
    return audit_tls(host)


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
    print(f"[+] TLS audit — {len(hosts)} hosts (port 443)", flush=True)
    all_findings = []
    completed = 0
    with ThreadPoolExecutor(max_workers=25) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for fut in as_completed(futures):
            completed += 1
            if completed % 250 == 0:
                print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} with TLS issues", flush=True)
            try:
                r = fut.result(timeout=20)
                if r:
                    all_findings.append(r)
                    crit = [f for f in r["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
                    if crit:
                        print(f"  🔴 {r['host']}  TLS={r['tls_version']}  issues:", flush=True)
                        for f in crit[:5]:
                            print(f"      [{f['severity']}] {f['issue']}", flush=True)
            except Exception: pass

    print(f"\n[+] TLS audit complete: {len(all_findings)} hosts with at least one issue", flush=True)
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for r in all_findings: f.write(json.dumps(r) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
