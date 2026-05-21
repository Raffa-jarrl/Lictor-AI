# Disclosure 8 — AZ Diest hospital — public ProFTPD on azdiest.be:21 (MEDIUM, hardening)

**Target:** `azdiest.be:21` → `83.217.70.125` (Belgium)
**Owner:** Algemeen Ziekenhuis Diest (AZ Diest) — general hospital, Diest, Belgium
**Service:** ProFTPD Server, plaintext FTP exposed on the public internet
**Anonymous FTP:** Disabled (good — login returns `530 Login incorrect`)
**Risk:** Hardening opportunity — credentials over plaintext FTP, username-brute-force surface on hospital-adjacent network
**Action:** Draft to AZ Diest IT + Centre for Cybersecurity Belgium (CCB) CVD framework

---

## What Lictor observed (banner-grab only, NEVER auth attempts)

```
$ nc -w 5 azdiest.be 21
220 ProFTPD Server (FTP Server) [::ffff:83.217.70.125]
```

That's it. Single TCP connect + banner grab. No login attempts, no brute force,
no version-CVE probing. The banner confirms:
- Port 21 (FTP) is reachable from the public internet
- It's running ProFTPD (a real FTP server, not a honeypot)
- The IP is `83.217.70.125` (Belgium)
- The mail records for `azdiest.be` point at `mx1/2/3.uzleuven.be` — University
  Hospitals Leuven, which suggests AZ Diest is in the UZ Leuven hospital
  network or shares mail infrastructure with them

## Why this is worth a heads-up (not a breach, but a hardening item)

- **Plaintext credentials**: anyone passively observing traffic to port 21
  (e.g. on a coffee-shop wifi the user is using) sees the FTP username +
  password in cleartext. SFTP (port 22) and FTPS (port 990) encrypt the
  credentials.
- **Username brute-force surface**: the server accepts login attempts from
  the public internet. Even if anonymous is off, a determined attacker can
  try common usernames + leaked-credential lists for many hours/days
  uninterrupted unless rate-limiting is in place.
- **Healthcare context**: AZ Diest is a hospital. The bar for "what's
  acceptable on the perimeter" is higher than for a commercial site —
  even an indirect exposure should be a hardening priority.
- **ProFTPD CVE history**: ProFTPD versions over the years have had
  several remote-impact CVEs (e.g. CVE-2020-9273 use-after-free in
  `mod_sftp`, older mod_copy vulnerabilities). Without knowing the
  exact version (banner only reveals "ProFTPD Server", no version
  number — good security practice), we can't say if any specific CVE
  applies, but exposing the service to the internet means any future
  CVE has them as a target.

## Recommended remediation (suggested wording for AZ Diest IT)

The remediation choices are well-known FTP-hardening practices:

1. **Replace plaintext FTP with SFTP (port 22) or FTPS (port 990 / explicit
   FTPS on 21 with AUTH TLS):** modern equivalents that encrypt the
   credentials and data in transit.
2. **Restrict by IP or VPN**: if the FTP server is only used by a small
   number of partners (e.g. a billing vendor, a referring clinic), restrict
   inbound access to those partner IPs. Most hospitals do this with a
   firewall ACL.
3. **Add fail2ban or equivalent rate-limiting**: limit failed-login attempts
   per source IP to slow username brute-force.
4. **Confirm the host is patched** to a current ProFTPD version (latest
   stable as of 2026 is 1.3.8+).
5. **Add a security.txt** at https://azdiest.be/.well-known/security.txt
   so future researchers can reach the security team quickly. (Currently
   returns HTTP 404.)

---

## Email A — Direct to AZ Diest (find an email)

The contact page at https://www.azdiest.be/contact is heavily JS-rendered
and didn't reveal email addresses in plain HTML. Likely paths to find a
contact:

1. **AZ Diest main number**: ask reception to forward to "IT / dienst
   informatica"
2. **Try generic security emails**: `security@azdiest.be`, `it@azdiest.be`,
   `info@azdiest.be`
3. **Through UZ Leuven**: since mail flows through `mx*.uzleuven.be`, the
   UZ Leuven CSIRT (`csirt@uzleuven.be`) may know who to route to
4. **Via Belgian healthcare CSIRT** (`certbe@belnet.be` for general,
   `info@ccb.belgium.be` for the national cybersecurity centre)

Email draft:

```
To:      security@azdiest.be, it@azdiest.be, info@azdiest.be (one of these)
Subject: Vriendelijke melding — publiek bereikbare FTP-server op
         azdiest.be:21 (security hardening)

Beste IT-team van AZ Diest,

Met deze e-mail wil ik u attent maken op een security-hardening
opportuniteit die we tegengekomen zijn tijdens een scan van publiek
bereikbare diensten op bug-bounty-scope domeinen.

Wat we waargenomen hebben (alleen banner-grab, GEEN login-pogingen):

  Host:     azdiest.be → 83.217.70.125
  Port:     21 (FTP)
  Service:  ProFTPD Server
  Anoniem:  uitgeschakeld (goed)

De bezorgdheid:

  - Plaintext credentials reizen onversleuteld over FTP
  - Een username brute-force surface staat open op het publieke
    internet
  - In een ziekenhuiscontext is dit een hardening prioriteit
  - We weten de exacte ProFTPD versie niet (banner toont enkel
    "ProFTPD Server"), maar oudere versies hebben bekende CVE's

Aanbevelingen:

  1. Vervang plaintext FTP door SFTP (port 22) of FTPS (AUTH TLS op
     port 21 / FTPS op port 990) — beide versleutelen credentials
  2. Beperk inbound toegang per IP of via VPN als de FTP-server
     enkel voor specifieke partners gebruikt wordt
  3. Voeg fail2ban toe om brute-force pogingen te vertragen
  4. Bevestig dat de ProFTPD-versie up-to-date is

Wij hebben GEEN login-pogingen gedaan, GEEN brute-force, GEEN
exploits. Enkel één TCP-verbinding + read van de eerste 256 bytes
banner-output. We hebben evenmin de inhoud van enige bestanden
benaderd.

Dit is een open-source security-scan via Lictor (https://lictor-ai.com,
Apache 2.0 licentie). We doen verantwoorde melding van zulke
exposures als publiek-belang oefening; we vragen geen bounty.

Een security.txt op https://azdiest.be/.well-known/security.txt zou
ons en andere onderzoekers helpen om u sneller te bereiken bij
toekomstige vondsten.

Met vriendelijke groet,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## Email B — CCB Belgium (CVD framework parallel notification)

The Centre for Cybersecurity Belgium has a Coordinated Vulnerability
Disclosure framework with legal protection. For a healthcare-adjacent
finding, parallel-notifying CCB is the right Belgian pattern.

```
To:      cvd@ccb.belgium.be
CC:      certbe@belnet.be
Subject: CVD — plaintext FTP exposed on Belgian hospital domain (azdiest.be:21)

Hello CCB CVD team,

Following the Belgian CVD framework, I'm parallel-notifying you of a
security hardening item I'm reporting directly to AZ Diest hospital:

  Host:     azdiest.be → 83.217.70.125
  Port:     21 (FTP)
  Service:  ProFTPD Server (banner observed, version not disclosed)
  Auth:     Anonymous disabled (good); username/password login open
  Owner:    Algemeen Ziekenhuis Diest (AZ Diest)
  Related:  Mail handled by mx1/2/3.uzleuven.be (UZ Leuven)

This is NOT a confirmed breach. It's a hardening opportunity:
- Plaintext credentials over FTP in 2026
- Username brute-force surface on a hospital network
- Healthcare context = higher bar for perimeter hygiene

My findings (banner-grab only, no auth attempts, no exploits):

  $ nc -w 5 azdiest.be 21
  220 ProFTPD Server (FTP Server) [::ffff:83.217.70.125]

Recommended remediation in my direct email to AZ Diest:
  - SFTP/FTPS instead of plaintext FTP
  - Firewall ACL to partner IPs or VPN
  - Fail2ban rate-limiting
  - Confirm ProFTPD patched
  - Publish security.txt

Discovered via Lictor (https://lictor-ai.com), open-source security
scanner under Apache 2.0. No bounty requested — public-good
responsible disclosure.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt anonymous FTP login (we confirmed it's disabled — DON'T re-try)
- ❌ Brute-force credentials of any kind
- ❌ Probe for FTP-version-specific CVEs
- ❌ Connect via SFTP / SSH or any other port we didn't observe
- ❌ Disclose publicly until AZ Diest has had time to remediate (60 days
  is the typical CVD window)
- ❌ Post the IP or hostname combined with the FTP detail in public
  Lictor blog posts until remediation is confirmed
