"""Cellphone backup scanner — Telegram, WhatsApp, iPhone, Android backup leaks.

Targets the most distinctive backup file shapes that EXIST nowhere else on
the web other than as user phone backups. If any of these are exposed, it's
MAXIMUM PII severity (contacts, messages, photos, auth tokens).

Ethical: HEAD-only. Never downloads contents. Records size + content-type only.
ANY 200 on these paths is automatically CRITICAL severity.
"""
import urllib.request, urllib.error, ssl, json, secrets, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-MobileBackupHunt/0.1 (ethical-research; +https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "mobile-backup-candidates.jsonl"

# Backup file paths grouped by source
MOBILE_BACKUP_PATHS = [
    # ───── Telegram (tdata = Telegram desktop, .session = Telethon/Pyrogram clients) ─────
    "/tdata", "/tdata/", "/tdata.zip", "/tdata.tar.gz",
    "/telegram.session", "/telegram-backup.zip", "/tg_backup.zip",
    "/telegram.db", "/telegram_export.json", "/telegram_chat_export.html",
    # ───── WhatsApp (msgstore is the canonical WhatsApp Android DB) ─────
    "/msgstore.db", "/msgstore.db.crypt14", "/msgstore.db.crypt15", "/msgstore.db.crypt12",
    "/wa.db", "/wa-backup.db", "/whatsapp-backup.zip", "/whatsapp_chat.txt",
    "/WhatsApp Chat.zip", "/whatsapp_export.zip", "/chats.db",
    "/Backups/msgstore.db", "/WhatsApp/Backups/msgstore.db",
    # ───── iPhone iTunes/iCloud backup ─────
    "/Manifest.db", "/Manifest.plist", "/Info.plist", "/Status.plist",
    "/iphone_backup.zip", "/iphone.zip", "/ios_backup.tar.gz",
    "/Backup/Manifest.db", "/MobileSync/Backup/Manifest.db",
    # ───── Android backup (.ab is Android Backup format) ─────
    "/backup.ab", "/data.ab", "/android_backup.ab",
    "/app_backup.tar", "/android-data.zip",
    # ───── Generic contacts / address book ─────
    "/contacts.vcf", "/Contacts.vcf", "/CONTACTS.VCF",
    "/contacts.csv", "/Contacts.csv", "/contacts.json",
    "/phonebook.csv", "/phonebook.vcf", "/address_book.csv",
    "/contacts-export.csv", "/contacts.xls", "/contacts.xlsx",
    "/all_contacts.vcf", "/Outlook_Contacts.csv",
    # ───── SMS / call log backups ─────
    "/sms_backup.xml", "/sms_export.csv", "/sms.db", "/sms.json",
    "/call_log.xml", "/call_log_backup.csv", "/calls.db",
    "/messages.db", "/messages_backup.zip",
    # ───── Signal / Threema / Wire (encrypted but the file presence is the leak) ─────
    "/signal_backup.bin", "/signal-backup.zip", "/signal.db",
    "/threema_backup.zip", "/threema_export.csv",
    "/wire_backup.tar.gz",
    # ───── Photos / media leaks ─────
    "/Camera Roll.zip", "/DCIM.zip", "/Photos.zip", "/photos_backup.zip",
    "/icloud_photos.zip", "/google_photos_takeout.zip", "/photo_backup.tar.gz",
    # ───── Google / Apple takeout exports ─────
    "/takeout.zip", "/takeout-001.zip", "/google-takeout.tgz",
    "/icloud_export.zip", "/icloud-export.zip",
    # ───── Phone exports / generic backup zips with phone keywords ─────
    "/phone_backup.zip", "/Phone_Backup.zip", "/MyPhone.zip",
    "/iPhoneBackup.zip", "/AndroidBackup.zip",
    "/PhoneBackup/", "/PhoneBackup.zip",  # the btc.do bucket had this exact path!
]

# Distinctive content-type heuristics for real backups
EXPECTED_CTS = ("application/octet-stream", "application/zip", "application/x-tar",
                "application/gzip", "application/x-sqlite3",
                "text/x-vcard", "text/csv", "text/vcard",
                "application/vnd.openxmlformats", "application/json",
                "application/x-plist", "application/binary")

HTML_CT_RX = __import__("re").compile(r"text/html|application/xhtml", __import__("re").I)


def fetch_head(url, timeout=5):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA}, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, {k: v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k: v for k, v in (e.headers.items() if e.headers else [])}
    except Exception:
        return None, None


def head_cl(url):
    st, hdr = fetch_head(url)
    if st != 200 or not hdr: return None
    try: return int(hdr.get("Content-Length", "0"))
    except: return 0


def scan_host(host):
    findings = []
    base = f"https://{host}"
    # Canary check — 5 diverse-shape canaries (mobile-backup-style extensions)
    nonce = secrets.token_hex(6)
    canary_cls = set()
    for cp in [f"/__canary_{nonce}.db", f"/__canary_{nonce}.zip",
               f"/__canary_{nonce}.vcf", f"/__canary_{nonce}.crypt14",
               f"/non/existent/{nonce}/backup.zip"]:
        cl = head_cl(f"{base}{cp}")
        if cl is not None and cl > 0:
            canary_cls.add(cl)

    raw_hits = []
    for path in MOBILE_BACKUP_PATHS:
        st, hdr = fetch_head(f"{base}{path}")
        if st != 200: continue
        if not hdr: continue
        try: cl = int(hdr.get("Content-Length", "0"))
        except: cl = 0
        ct = hdr.get("Content-Type", "?")
        # Drop HTML responses (catch-all SPA)
        if HTML_CT_RX.search(ct): continue
        # Drop canary-matching
        if any(c > 0 and cl > 0 and abs(cl - c) / c < 0.05 for c in canary_cls): continue
        # Mobile backups should generally be > 1KB to be real
        if cl < 200: continue
        raw_hits.append({"path": path, "cl": cl, "ct": ct})

    # Cluster dedup
    if len(raw_hits) >= 4:
        cls = [h["cl"] for h in raw_hits]
        mean_cl = statistics.mean(cls)
        if mean_cl > 0:
            within = [h for h in raw_hits if abs(h["cl"] - mean_cl) / mean_cl < 0.05]
            if len(within) >= 4:
                print(f"  [drop-cluster]  {host}  {len(within)} hits cluster — drop", flush=True)
                raw_hits = []

    for h in raw_hits:
        # Mark severity
        sev = "CRITICAL"  # Any mobile-backup hit = max severity
        print(f"  🔴🔴🔴 MOBILE-BACKUP {host}{h['path']}  size={h['cl']}  ct={h['ct']}  [CRITICAL]", flush=True)
        findings.append({
            "type": "mobile-backup-exposure",
            "host": host, "path": h["path"],
            "content_length": h["cl"], "content_type": h["ct"],
            "severity": sev,
            "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
print(f"[+] mobile-backup hunt — {len(hosts)} hosts × {len(MOBILE_BACKUP_PATHS)} paths (HEAD-only)", flush=True)
print(f"[+] Targets: Telegram tdata, WhatsApp msgstore, iPhone Manifest, Android .ab, contacts.vcf/csv, SMS/call logs, Takeouts", flush=True)
print(f"[+] ETHICAL: HEAD-only, NEVER downloads content. Any 200 = CRITICAL.", flush=True)
print(flush=True)

all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=25) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 200 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} findings", flush=True)
        try:
            r = fut.result(timeout=30)
            if r: all_findings.extend(r)
        except Exception:
            pass

print(f"\n[+] mobile-backup hunt complete: {len(all_findings)} findings", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
    print(f"\n🔴🔴🔴 ALL FINDINGS ARE CRITICAL — REQUIRE IMMEDIATE DISCLOSURE 🔴🔴🔴", flush=True)
    for f in all_findings:
        print(f"   {f['host']}{f['path']}  size={f['content_length']}", flush=True)
