# Disclosure 14 — Bundle to CERT-IL — 10 Israeli orgs with public FTP exposures (medium hardening)

**Target:** Mixed Israeli hosts — small/medium orgs across retail, education, non-profit
**Bundle reason:** Same finding-class (public plaintext FTP) across 10 orgs; routing efficiency = single CERT-IL email rather than 10 individual outreaches
**Service:** Various FTP servers (ProFTPD + Pure-FTPd) — plaintext credentials, brute-force surface
**Risk:** MEDIUM (hardening) per host; LOW-MEDIUM aggregate (no confirmed breach)
**Action:** Single email to CERT-IL / INCD with full list + remediation playbook

---

## Why bundle to CERT-IL vs individual outreach

- Each finding is **medium hardening**, not breach-level
- Each org is **SMB-tier** with no published security.txt or bug-bounty contact
- CERT-IL has the **relationships** to route to each org's IT team faster
  than I can guess emails (info@/support@/security@ at 10 different orgs)
- **Consistent remediation playbook** (SFTP/FTPS migration + IP allowlist
  + fail2ban + banner customization) means one note covers all
- Avoids the **disclosure-spam risk** of 10 similar emails landing in
  multiple Israeli IT inboxes from a foreign-sounding researcher in
  one batch (looks like phishing pattern)

The two HIGH-severity IL findings tonight (`golf.co.il` MySQL and
`harel.co.il` insurance ProFTPD) are being disclosed **directly** to
the orgs in parallel with CERT-IL CC. This bundle is for the
remaining medium-FTP findings.

---

## The findings (banner-grab only, NO login attempts on any host)

| # | Host | IP | Service | Banner | Org context |
|---|------|----|---------|--------|-------------|
| 1 | `campusil.co.il:21` | (DNS) | Pure-FTPd `[privsep] [TLS]` | "Welcome to Pure-FTPd" | IL education / e-learning platform |
| 2 | `golf.co.il:21` | 143.95.77.247 | ProFTPD | (companion to MySQL — see direct disclosure) | E-commerce, golf retail |
| 3 | `hamashbir.co.il:21` | (DNS) | ProFTPD | (banner not preserved in log) | IL department store chain |
| 4 | `jct.ac.il:21` | (DNS) | ProFTPD | (banner not preserved in log) | Jerusalem College of Technology |
| 5 | `nofar.org.il:21` | 91.98.65.63 | ProFTPD | (banner not preserved in log) | Israeli non-profit; **also** MariaDB on :3306 with ACL hardened (good config) |
| 6 | `otzar.co.il:21` | 88.99.24.18 | Pure-FTPd `[privsep] [TLS]` | "Welcome to Pure-FTPd" | "אוצר אחסון ממוחשב" — IL ECM/storage solutions B2B; **also** MariaDB on :3306 with ACL hardened (good config — ERR 1130 "Host not allowed") |
| 7 | `toys.co.il:21` | (DNS) | ProFTPD | (banner not preserved in log) | Israeli toy retail |
| 8 | `yedidim.org.il:21` | (DNS) | ProFTPD | (banner not preserved in log) | Yedidim — roadside-assistance non-profit |
| 9 | `zomet.co.il:21` | (DNS) | ProFTPD | (banner not preserved in log) | Israeli retail / electronics chain |
| 10 | `ness-tech.com:21` | (DNS) | ProFTPD | (banner not preserved in log) | Ness Technologies — IL IT services company |

### Two MariaDB instances (positive note)

Worth highlighting that **otzar.co.il:3306** and **nofar.org.il:3306**
both returned `Host '85.65.84.52' is not allowed to connect to this
MariaDB server` (ERR packet 1130) — meaning their MariaDB IS publicly
TCP-reachable but **host-based ACL is correctly enforced**. This is
hardened config worth keeping; just consider whether port 3306 needs
to be open at all if no remote DBA access is required.

By contrast, `golf.co.il:3306` returned a full MySQL handshake packet
(server version 5.7.23-23), indicating **NO ACL** — which is the
HIGH/CRITICAL finding being disclosed directly to that operator.

---

## Common remediation playbook (one paragraph for each org)

The fix is the same on every host:

1. **Replace plaintext FTP with SFTP** (port 22 via OpenSSH with
   `ChrootDirectory` per user) — modern equivalent, encrypted in
   transit, simpler to manage with key-based auth.
2. **OR enable FTPS** (AUTH TLS on port 21 / FTPS on port 990) if
   the FTP service must remain — both encrypt credentials.
3. **Restrict by IP / behind VPN** — if FTP is only used by specific
   partners (backup vendor, dev team, accountant), firewall to those
   source IPs. Most hosts here probably have ≤5 legitimate clients.
4. **Add fail2ban** — slow username brute-force per source IP.
5. **Customize the banner** — change `ServerName` in
   `/etc/proftpd/proftpd.conf` (ProFTPD) or `pure-ftpd.conf`
   (Pure-FTPd). Removes version-disclosure surface.
6. **Confirm server is patched** — ProFTPD latest stable 1.3.8b+,
   Pure-FTPd latest 1.0.51+.
7. **Publish `/.well-known/security.txt`** so future researchers can
   reach the right contact quickly.

---

## Email — to CERT-IL / INCD

```
To:      cert@cert.gov.il
CC:      report@cyber.gov.il
Subject: CVD bundle — 10 IL orgs with public plaintext FTP exposures
         (medium-severity hardening; please route to each)

Hello CERT-IL / INCD team,

Following Israeli CVD practice, I'm batch-notifying you of 10 small
and medium Israeli orgs with publicly-reachable plaintext FTP servers
on port 21. None of these is a confirmed breach — they are hardening
items. I'm bundling them to you for routing rather than emailing 10
SMB IT teams individually (lower spam risk, faster triage).

The 10 hosts and their org context:

   1. campusil.co.il:21       — Pure-FTPd  — IL education platform
   2. golf.co.il:21           — ProFTPD    — golf-equipment e-commerce
                                (PLUS critical MySQL 5.7 on :3306
                                 — directly disclosed to golf.co.il
                                 operator under separate cover)
   3. hamashbir.co.il:21      — ProFTPD    — IL department store chain
   4. jct.ac.il:21            — ProFTPD    — Jerusalem College of
                                              Technology
   5. nofar.org.il:21         — ProFTPD    — non-profit (also has
                                              MariaDB on :3306, ACL-
                                              hardened — good config)
   6. otzar.co.il:21          — Pure-FTPd  — IL ECM/storage SMB
                                              (also has MariaDB on
                                              :3306, ACL-hardened)
   7. toys.co.il:21           — ProFTPD    — IL toy retail
   8. yedidim.org.il:21       — ProFTPD    — roadside-assistance NGO
   9. zomet.co.il:21          — ProFTPD    — retail / electronics
  10. ness-tech.com:21        — ProFTPD    — Ness Technologies (IL IT
                                              services)

Method: single TCP connect per host on port 21, read of the first
256 bytes of FTP banner. NO login attempts, NO brute force, NO
exploits. Confirmation via independent re-scan that each host was
NOT a WAF/CDN edge (filtered out separately).

For each host, the standard SFTP/FTPS migration playbook applies:

  • Replace plaintext FTP with SFTP (port 22 via OpenSSH) OR enable
    FTPS (AUTH TLS on port 21)
  • Restrict by IP / behind VPN to partner IPs only
  • Add fail2ban for brute-force throttling
  • Customize banner (ServerName directive) to remove version disclosure
  • Confirm server is patched to latest stable
  • Publish security.txt on the apex domain

Two SEPARATE direct disclosures going out this batch:

  • golf.co.il (operator: Ronen Zur) — MySQL 5.7.23 fully exposed on
    :3306 with NO ACL (server accepts handshake from any IP).
    HIGH/CRITICAL. Hebrew+English email + remediation directly to
    info@/support@golf.co.il.

  • harel.co.il (Harel Insurance & Finance Ltd) — ProFTPD on
    insurance-org perimeter with "Default Installation" banner.
    HIGH given the org context (life/health/pension/P&C insurance =
    PII + medical + financial data). Hebrew+English email +
    remediation directly to security@/infosec@/it-security@harel-
    group.co.il + CERT-IL CC.

I'm not requesting bounty for any of these. Public-good disclosure
via the open-source Lictor scanner (https://lictor-ai.com, Apache 2.0).

Full disclosure drafts (Markdown) are publicly archived at:
  https://github.com/Raffa-jarrl/Lictor-AI/tree/main/v3/docs/disclosures-2026-05-21/

Would you like me to:
  - Send the individual SMB notices myself with CERT-IL CC, or
  - Route them through your team (preferred — you have the
    relationships), or
  - Hold the bundle here and do nothing further?

I'll act on whichever you prefer. Default action if I hear nothing
in 14 days: send individual notices with explicit CERT-IL CC.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt FTP login on ANY of these 10 hosts (unauthorized under
  Israeli Computer Law §4)
- ❌ Try anonymous-FTP or common usernames on any host
- ❌ Probe for FTP-version-specific CVEs against these hosts
- ❌ Combine this with the golf.co.il (MySQL) or harel.co.il
  (insurance) disclosures — those go DIRECT to their orgs, this
  goes to CERT-IL
- ❌ Disclose any of the 10 hostnames publicly until CERT-IL has had
  60 days to route + each org to remediate
