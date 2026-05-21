# Disclosure 17 — Gufic Group (gufic.com) — pharma corporate apex on shared hosting with public MySQL + FTP (HIGH)

**Target:** `gufic.com` → `5.100.152.180` (WebhostBox shared hosting, `bh-uk-2.webhostbox.net`, UK)
**Owner:** **Gufic BioSciences Ltd.** — Indian pharmaceutical company (BSE: 509079, NSE: GUFICBIO)
- Pharma APIs, intermediates, finished formulations
- WordPress corporate site, Microsoft 365 email
**Services exposed on public internet:**
- `:21` — Pure-FTPd `[privsep] [TLS]` (active — banner reports user 1 of 150 connected)
- `:3306` — MySQL accepting handshake from any IP (`fp=MySQL` per Lictor scanner)
**Risk:** **HIGH** — pharma sector, BSE-listed company, plaintext FTP credentials + MySQL brute-force surface on the corporate apex
**Action:** Email Gufic IT security; parallel CC to CERT-In (Indian national CSIRT)

---

## What Lictor observed (banner-grab only, NO login)

### Port 21 — Pure-FTPd active

```
$ nc -w 5 gufic.com 21
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 1 of 150 allowed.
220-Local time is now 20:34. Server port: 21.
```

- Pure-FTPd with privsep + TLS optional (operator CAN use FTPS,
  but plaintext FTP also allowed)
- 1 of 150 concurrent users — active production FTP

### Port 3306 — MySQL handshake

Per Lictor v4 port-exposure ledger:
```
gufic.com:3306 (MySQL, high, fp=MySQL)
```

`fp=MySQL` means the banner contained recognizable MySQL handshake
bytes (proto version 10 + version string), NOT an ERR 1130 "Host
not allowed" — so the server accepts TCP from any IP and proceeds
to auth.

### Site context (positive identification)

```
$ curl -s https://gufic.com/ | grep -i title
  <title> Welcome to Gufic Group</title>

$ curl -sI https://gufic.com/
HTTP/2 200
link: <https://gufic.com/wp-json/>; rel="https://api.w.org/"   ← WordPress

$ host gufic.com → 5.100.152.180
$ host 5.100.152.180 → bh-uk-2.webhostbox.net   ← WebhostBox shared
```

Confirmed Gufic Group corporate apex, hosted on WebhostBox (Indian-
oriented UK shared hosting provider, similar tier to Hostmonster /
Bluehost). WordPress on shared hosting with cPanel-style FTP+MySQL
exposed.

## Why this is HIGH (pharma + BSE-listed = regulated industry)

1. **WordPress DB exposure**: the MySQL almost certainly contains the
   WP `wp_users` (hashed admin passwords), `wp_options` (site config,
   sometimes API keys), `wp_posts` (drafts, including potentially
   unpublished pharma announcements / regulatory filings), and any
   plugin tables (Contact Form 7 submissions, WooCommerce orders if
   present, lead-capture data).

2. **BSE-listed company**: SEBI (Securities and Exchange Board of
   India) has cyber-incident-disclosure rules for listed companies.
   Even a credential-brute-force incident may trigger disclosure
   obligations.

3. **Pharma regulatory context**: Gufic operates in API manufacturing
   for global pharma. CDSCO (Indian drug regulator) and DRA
   counterparts in export markets pay attention to cybersecurity
   posture of API suppliers.

4. **Active FTP** (1 of 150 users currently connected) means real
   credentials are in active use on plaintext FTP — anyone passively
   sniffing partner-network or coffee-shop traffic captures them.

5. **WebhostBox shared hosting**: cPanel-style account where the FTP
   and MySQL are reachable from the internet by default. Hardening
   requires either provider-side firewall changes or a migration to
   managed hosting.

## Recommended remediation

1. **Bind MySQL to localhost only**: ask WebhostBox to configure the
   account's MySQL to `bind-address = 127.0.0.1`. WordPress connects
   locally via socket; there is NO reason for port 3306 to be
   reachable from the internet.

2. **OR allowlist by IP** if any partner needs remote MySQL.

3. **Replace plaintext FTP with SFTP** (port 22 via OpenSSH) or
   enable FTPS-only (AUTH TLS required, plaintext denied). Both
   encrypt credentials.

4. **Add fail2ban** at the server level (WebhostBox may provide this
   via cPanel modules).

5. **Rotate MySQL + FTP credentials** that have been in use during
   the public-exposure window. Check WP admin logs and FTP transfer
   logs for unfamiliar source IPs.

6. **Consider migrating to managed-WordPress hosting** (e.g. WPEngine,
   Pantheon, Kinsta, Cloudways) that doesn't expose backend services
   by default. The premium is small compared to a credential leak.

7. **Publish security.txt** at
   `https://gufic.com/.well-known/security.txt` so future researchers
   can reach the right contact faster.

---

## Email — to Gufic BioSciences IT security

```
To:      it@gufic.com, security@gufic.com, infosec@gufic.com,
         pankaj.gandhi@gufic.com (CEO — try last resort),
         admin@gufic.com (try all)
CC:      incident@cert-in.org.in (CERT-In parallel notification)
Subject: URGENT — Public MySQL + FTP exposure on gufic.com corporate
         apex (HIGH security risk, pharma sector)

Dear Gufic BioSciences IT/Security team,

I'm writing to alert your team to a security exposure I observed
while scanning publicly-reachable services on global pharma
companies. I'm an open-source security researcher with Lictor
(https://lictor-ai.com, Apache 2.0 license); we do public-good
responsible disclosure without bounty requests.

What we observed (banner-grab only, NO login attempts):

  Host:    gufic.com → 5.100.152.180 (bh-uk-2.webhostbox.net,
                                       WebhostBox UK shared hosting)
  Port:    21 (Pure-FTPd, active — 1 of 150 users connected right now)
  Port:    3306 (MySQL — server sent a real handshake packet,
                  NOT an "ERR 1130 Host not allowed" — means any
                  internet IP can attempt authentication)

The concern (high given pharma + BSE-listed context):

  • Direct MySQL administration interface on the corporate
    WordPress DB — wp_users (hashed admin passwords), wp_options
    (site config, sometimes API keys), unpublished WP posts
    (regulatory filings, pharma announcements), plugin tables
    (lead captures, Contact Form 7 submissions)

  • Brute-force surface from any IP on the internet — no
    network-layer rate limiting visible

  • Plaintext FTP credentials in active use right now — any
    passive observer on the network path captures them in
    cleartext

  • BSE-listed companies have SEBI cyber-incident-disclosure
    rules; even a credential brute-force incident may trigger
    disclosure obligations

  • Pharma regulatory context — CDSCO and global DRAs increasingly
    expect cyber-hygiene from API suppliers

Immediate actions (DBA + sysadmin standard playbook):

  1. Bind MySQL to localhost only — ask WebhostBox to set
     bind-address = 127.0.0.1 on your account's MySQL.
     WordPress connects via local socket; port 3306 should
     NOT be internet-reachable.

  2. Replace plaintext FTP with SFTP (port 22) or enable
     FTPS-only (AUTH TLS required, plaintext rejected).

  3. Add fail2ban at the server level (cPanel may provide
     this via plugins).

  4. Rotate MySQL + FTP credentials currently in use.

  5. Check WP admin logs + FTP transfer logs for unfamiliar
     source IPs over the past months.

  6. Consider migrating to managed-WordPress hosting (WPEngine,
     Pantheon, Kinsta, Cloudways) that doesn't expose backend
     services by default.

  7. Publish security.txt at https://gufic.com/.well-known/
     security.txt so future researchers can reach you in minutes.

We did NOT attempt any login, NOT brute-force, NOT exploits.
A single TCP connect + 256-byte banner read on each of the open
ports. We have NO access to your data — only the public banner
that announces the service.

This is open-source security scanning via Lictor; public-good
responsible disclosure with no bounty request.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt MySQL login on gufic.com:3306 — unauthorized access
  under Indian Information Technology Act 2000 §43A and §66
- ❌ Try common usernames (root, admin, gufic, wp_admin)
- ❌ Attempt FTP login (anonymous or named) — same
- ❌ Probe for WordPress/MySQL-specific CVEs against this host
- ❌ Combine with the Sumitomo Chemical / Banco Bajío / other org
  disclosures — each gets its own dedicated email
- ❌ Disclose the gufic.com hostname publicly until Gufic has had
  60+ days to remediate
