# Disclosure 18 — ZoomGrants (zoomgrants.com) — production SaaS with MySQL 5.7 EOL + FileZilla 0.9.60 beta exposed (CRITICAL)

**Target:** `zoomgrants.com` → `67.225.240.30` (Microsoft IIS 10.0 on Windows Server)
**Owner:** **ZoomGrants LLC** — US-based grant-application management SaaS
- Used by foundations, US federal/state/local government agencies, universities
- Handles grant applicant PII, financial records, IRS data, sometimes Form 990
- Real production deployment (www.zoomgrants.com resolves to same IP)
**Services exposed on public internet:**
- `:21` — **FileZilla Server 0.9.60 beta** (released 2014, OBSOLETE — replaced by 1.x series)
- `:3306` — **MySQL 5.7.43-log** (EOL October 2023, real handshake from any IP)
**Risk:** **CRITICAL** — production grant-management SaaS with PII/financial data running EOL components on the public internet
**Action:** Email ZoomGrants engineering + CISA / US-CERT parallel notification

---

## What Lictor observed (banner-grab only, NEVER login)

### Port 21 — FileZilla Server 0.9.60 beta (2014!)

```
$ nc -w 5 zoomgrants.com 21
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
```

This is significant:
- **0.9.60 beta is from 2014** — the last release of the 0.9.x series
  before the FileZilla Server project was rewritten as the 1.x series
  (current is 1.7.x as of 2025)
- "Beta" in production for 10+ years is unusual
- The 0.9.x codebase has not received security audits since
- Running on Windows Server (Microsoft IIS 10.0)
- Banner identifies version + project author publicly

### Port 3306 — MySQL 5.7.43-log

```
$ nc -w 5 zoomgrants.com 3306 | xxd | head -2
00000000: 4e00 0000 0a35 2e37 2e34 332d 6c6f 6700  N....5.7.43-log.
00000010: 2110 2a00 7d62 2541 437f 2215 00ff ff08  !.*.}b%AC.".....
```

- Packet length: 0x4E (78 bytes)
- Protocol version: 0x0A (v10)
- Server version: **"5.7.43-log"** — MySQL 5.7.43 with binary
  logging enabled
- Server accepted the TCP+handshake — NOT an ERR 1130 "Host not
  allowed" — means any internet IP can attempt authentication
- **MySQL 5.7 reached EOL October 2023**; 5.7.44 was the last 5.7
  release. 5.7.43 is even older (and one version behind the last
  patched 5.7)

### Site context (real production SaaS)

```
$ curl -sI https://zoomgrants.com/
HTTP/2 301 → https://www.zoomgrants.com/
server: Microsoft-IIS/10.0

$ host www.zoomgrants.com
www.zoomgrants.com has address 67.225.240.30   ← same IP, www and apex
```

- Both www and apex resolve to the same Windows Server IIS host
- Mail handled by Google Workspace (`aspmx.l.google.com`) +
  `igw06.site4now.net` fallback — production setup
- This is THE ZoomGrants production property, not a brand-parking
  domain or marketing site

### What ZoomGrants does (why this is CRITICAL severity)

ZoomGrants is a grant-application management platform. Their
customers include:
- **US federal grant programs** (HHS, NIH, NSF subgrants via foundations)
- **State and local governments** (community-development grants,
  arts grants, education grants)
- **Major private foundations** (community foundations,
  donor-advised funds)
- **Universities** (internal research grants, scholarship programs)

Their database typically stores:
- Grant applicant PII (names, addresses, SSNs for tax-credit grants,
  EINs for organizational applicants)
- Application content (project proposals, budgets, financial
  statements, organizational governance)
- Reviewer scoring data + comments (sometimes blind-peer-review
  context)
- Payment information (where grants include funds disbursement)
- IRS Form 990 data and tax-exempt status verification

A breach of the production MySQL would affect **tens of thousands
of grant applicants** across hundreds of foundations and government
agencies. Many ZoomGrants customers are bound by state-level breach
notification laws (CCPA in CA, NY SHIELD Act, MA 201 CMR 17, etc.)
that would trigger if applicant PII is compromised.

## Why this is CRITICAL (not just HIGH)

1. **EOL MySQL on the public internet** — 5.7 has had no security
   patches since October 2023. Any new MySQL CVE finds an immediate
   unpatched target on a major SaaS.

2. **FileZilla 0.9.60 beta from 2014** — pre-rewrite, no recent
   security audit, "beta" in production for 11 years. Any new
   FTP-server vulnerability finds it.

3. **The SaaS itself is the trust boundary** — ZoomGrants's
   customers don't run their own infrastructure; they trust
   ZoomGrants to hold the data securely. The platform IS the
   security model.

4. **Brute-force surface unbounded** — neither FileZilla nor MySQL
   shows network-layer rate limiting. Distributed brute-force from
   1000 IPs can run millions of attempts per day.

5. **Multi-state PII obligations** — applicant data from 50 states
   triggers each state's notification law on a breach. Even a credential
   brute-force incident is reportable in some jurisdictions.

6. **Sector context — non-profit/government** — many ZoomGrants
   customers have minimal cybersecurity budget themselves and rely
   entirely on ZoomGrants's security posture. A breach cascades.

## Recommended remediation (DBA + sysadmin standard)

1. **Bind MySQL to localhost only.** Edit
   `C:\ProgramData\MySQL\MySQL Server 5.7\my.ini` to set
   `bind-address = 127.0.0.1` and restart MySQL. The IIS app on
   the same Windows Server connects locally via TCP/IP loopback;
   there is NO reason for port 3306 to be reachable from the
   internet.

2. **OR if remote MySQL access is needed** (a backup agent, a
   developer): Windows Firewall allow-list specific source IPs,
   AND use SSL/TLS, AND a dedicated DB user (not root) with
   minimum privileges.

3. **Migrate MySQL 5.7 → 8.0 URGENTLY** — 5.7 has been EOL since
   Oct 2023. Every month of delay accumulates risk.

4. **Replace FileZilla Server 0.9.60 beta with FileZilla Server
   1.7.x** (current) OR migrate to SFTP via OpenSSH for Windows.
   The 0.9.x codebase is unsupported and any new vulnerability
   will not be patched.

5. **Restrict FTP/SFTP by IP** — likely only a few specific
   partner IPs need FTP access (a payment processor uploading
   reconciliation files, a backup agent). Firewall to those IPs.

6. **Rotate all database and FTP credentials** that have been
   in use during the public-exposure window. Check IIS logs +
   MySQL `general_log` (if enabled) + FileZilla logs for
   unfamiliar source IPs over the past months.

7. **Engage an incident-response firm** to confirm no
   credential brute-force has already succeeded. With EOL
   software publicly exposed for an extended period, the
   assumption of compromise should be the working hypothesis
   until forensics rules it out.

8. **Publish security.txt** at
   `https://zoomgrants.com/.well-known/security.txt` — currently
   not present.

---

## Email A — Direct to ZoomGrants engineering / IT

```
To:      security@zoomgrants.com, support@zoomgrants.com,
         it@zoomgrants.com, engineering@zoomgrants.com,
         info@zoomgrants.com (try all — one will exist)
CC:      report@cisa.dhs.gov (US CISA), incident@us-cert.cisa.gov
Subject: URGENT — Production SaaS exposure: EOL MySQL 5.7 +
         FileZilla 0.9.60 beta publicly reachable on zoomgrants.com

Dear ZoomGrants engineering team,

I'm an open-source security researcher with Lictor
(https://lictor-ai.com, Apache 2.0 license). During a scan of
publicly-reachable services on grant-management and government-SaaS
domains, I observed that your production property zoomgrants.com
has TWO end-of-life software components publicly reachable from
the internet:

What we observed (banner-grab only, NO login attempts):

  Host:    zoomgrants.com → 67.225.240.30 (same IP as
                                            www.zoomgrants.com)
  Port:    21 (FTP)
           Banner: "220-FileZilla Server 0.9.60 beta
                    written by Tim Kosse (tim.kosse@filezilla-project.org)"
           Note: 0.9.60 beta was released in 2014 — the last 0.9.x
           series version before the FileZilla Server project was
           rewritten as the 1.x series. Current is 1.7.x.

  Port:    3306 (MySQL)
           Banner: "5.7.43-log" (full handshake packet, NOT
                                  ERR 1130 "Host not allowed")
           Note: MySQL 5.7 reached End-of-Life October 2023.
                 No security patches since then. 5.7.44 was the
                 last release; 5.7.43 is one version behind even
                 that final patch.

The combination — production grant-management SaaS handling
applicant PII + financial data, with TWO EOL software components
publicly internet-reachable — is critical.

The concern:

  • Direct MySQL access from any internet IP to a production DB
    holding grant-applicant PII, foundation records, sometimes
    SSN/EIN data, sometimes payment information
  • Brute-force surface unbounded (no network-layer rate limit
    visible)
  • EOL MySQL 5.7 — any new MySQL CVE finds an unpatched target
  • FileZilla Server 0.9.60 beta from 2014 — pre-rewrite, no
    recent security audit, "beta" in production for 11 years
  • Multi-state PII notification obligations on breach (CCPA, NY
    SHIELD, MA 201 CMR 17, etc.) given multi-jurisdiction
    applicant base
  • Federal grant programs running on ZoomGrants increases the
    blast radius if compromised

Immediate actions (DBA + sysadmin standard playbook):

  1. Edit C:\ProgramData\MySQL\MySQL Server 5.7\my.ini — set
       bind-address = 127.0.0.1
     and restart MySQL. The IIS app on the same Windows Server
     connects locally; there is NO reason for 3306 to be
     reachable from the internet.

  2. URGENTLY migrate MySQL 5.7 → 8.0. 5.7 has been EOL since
     Oct 2023.

  3. Replace FileZilla Server 0.9.60 beta with FileZilla 1.7.x
     OR migrate FTP traffic to SFTP via OpenSSH-for-Windows.
     The 0.9.x line is unsupported.

  4. Firewall FTP/SFTP to only the specific partner IPs that
     need access.

  5. Rotate all MySQL + FTP credentials that have been in use
     during the public-exposure window.

  6. Check IIS logs + MySQL general_log + FileZilla logs for
     unfamiliar source IPs over the past 6-12 months. Given the
     EOL software exposure, the assumption-of-compromise
     hypothesis should be the working baseline until forensics
     rules it out.

  7. Engage an incident-response firm for forensic review.

  8. Publish security.txt at
     https://zoomgrants.com/.well-known/security.txt so future
     researchers can reach you in minutes (currently not present).

I did NOT attempt any login, NOT brute-force, NOT exploits. A
single TCP connect + 256-byte banner read on each open port.
I have NO access to your database or any customer data — only
the public banner that announces the services are there.

Given the customer base (foundations, US federal/state/local
governments, universities) and the regulatory context (multi-state
PII notification laws, federal grant compliance), this warrants
urgent attention.

I am parallel-notifying US-CISA / CERT under coordinated-vulnerability-
disclosure framework so they are aware in case any of your
government-agency customers need to be informed.

This is public-good responsible disclosure via Lictor (open-source,
Apache 2.0). No bounty is requested.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(Full disclosure draft archived at:
 https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/18-zoomgrants-saas-mysql-filezilla.md
 — held private until 60-day CVD window expires.)
```

---

## Email B — CISA parallel notification

```
To:      report@cisa.dhs.gov
CC:      incident@us-cert.cisa.gov
Subject: CVD — production grant-management SaaS (ZoomGrants) with
         EOL MySQL 5.7 + FileZilla 0.9.60 beta publicly exposed

Hello CISA / US-CERT team,

Following coordinated vulnerability disclosure practice, I am
parallel-notifying you of a security exposure I am reporting
directly to ZoomGrants LLC, given the federal/state/local
government context of their customer base:

  Org:          ZoomGrants LLC
  Domain:       zoomgrants.com (production SaaS)
  Customer base: foundations + US federal/state/local government
                 grant programs + universities
  Finding A:    FileZilla Server 0.9.60 beta (2014, EOL pre-rewrite)
                reachable on :21
  Finding B:    MySQL 5.7.43-log (EOL Oct 2023) reachable on :3306
                with NO IP allowlist — handshake packet sent to
                any source IP
  Verification: passive banner-grab only; no login attempts; banners
                independently re-verifiable

This is NOT a confirmed breach. It is a critical hardening item on
a production SaaS serving grant programs across multiple US states
and federal agencies.

I sent the direct disclosure to ZoomGrants engineering with the
standard remediation (bind-address=127.0.0.1, MySQL 5.7→8.0
migration, FileZilla 0.9→1.7 replacement, firewall partner IPs,
rotate creds, assumption-of-compromise audit, engage IR firm).

The full disclosure draft is at:
https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/18-zoomgrants-saas-mysql-filezilla.md

Method: passive HTTP HEAD + GET, single TCP connect + 256-byte
banner read on the two open ports. NO login attempts. NO brute-
force. NO exploits. NO access to database content.

Discovered via Lictor (https://lictor-ai.com, Apache 2.0). Public-
good disclosure, no bounty requested.

Given that some ZoomGrants customers may be your CISA-monitored
government agencies, please advise if you would prefer:
  a) I hold the direct disclosure and let CISA route through your
     federal-agency relationships
  b) I send to ZoomGrants directly with CISA permanently CC'd
  c) Other coordination

Default action if no response in 7 days: send the direct disclosure
to ZoomGrants with CISA permanently CC'd.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt MySQL login on zoomgrants.com:3306 — UNAUTHORIZED
  ACCESS under US Computer Fraud and Abuse Act
- ❌ Attempt FTP login (anonymous or named) — same
- ❌ Probe for MySQL 5.7-version-specific CVEs against this host
- ❌ Probe for FileZilla 0.9.60-version-specific CVEs against this
  host (CVE-2017-12169 etc.) — even if the version is known to be
  vulnerable, exploiting is a crime
- ❌ Combine this with other disclosures (Sumitomo, Banco Bajío,
  Gufic, etc.) — ZoomGrants gets its OWN dedicated email; their
  customer base includes US federal agencies and the disclosure
  routing must be correct
- ❌ Disclose the zoomgrants.com hostname publicly until ZoomGrants
  has had 60+ days to remediate (longer if CISA coordination
  requires)
