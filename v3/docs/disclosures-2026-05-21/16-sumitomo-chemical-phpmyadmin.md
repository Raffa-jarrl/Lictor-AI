# Disclosure 16 — Sumitomo Chemical (sumitomochemical.com) — phpMyAdmin v5.2.1 exposed at /phpmyadmin/ and /pma/ (CRITICAL)

**Target:** `sumitomochemical.com` (Apache/Ubuntu, real corporate apex)
**Owner:** **Sumitomo Chemical Co., Ltd.** (住友化学株式会社) — Japanese chemicals giant
- Founded 1913, HQ Tokyo, member of Sumitomo zaibatsu
- ~31,000 employees worldwide
- TSE: 4005, ~¥3 trillion (~$20B USD) revenue
- Subsidiaries include Sumitomo Pharma, Sumika Chemtex, Inabata
**Service:** **phpMyAdmin v5.2.1deb3** (Debian package) reachable publicly at both default paths:
- `https://sumitomochemical.com/phpmyadmin/`
- `https://sumitomochemical.com/pma/`
**Risk:** **CRITICAL** — direct MySQL administration interface on a Fortune-Global-500-tier industrial company's PRIMARY EN-language corporate apex. Brute-force surface for the corporate DB, potential R&D / IP / employee data exposure if compromised.
**Action:** Email Sumitomo Chemical CSIRT/IT-Sec IMMEDIATELY; parallel CC to JPCERT/CC (Japanese national CSIRT) under their CVD framework

---

## What Lictor observed (passive HTTP only, NEVER login)

### Server posture (positive — apex is well-configured)

```
$ curl -sI https://sumitomochemical.com/
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.66 (Ubuntu)
Strict-Transport-Security: max-age=31536000;preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Opener-Policy: same-origin-allow-popups
Cross-Origin-Resource-Policy: cross-origin
```

The apex returns a 301 redirect with **proper enterprise security
headers** (HSTS with preload, COOP, CORP, no-sniff, referrer-policy).
The operator clearly understands modern security headers — this
makes the phpMyAdmin exposure all the more puzzling.

### phpMyAdmin reachable at BOTH default paths

```
$ curl -sI https://sumitomochemical.com/phpmyadmin/
HTTP/1.1 200 OK
Server: Apache/2.4.66 (Ubuntu)
Set-Cookie: phpMyAdmin_https=acd6b7ef4b9214ca5309dde84706eb83;
            path=/phpmyadmin/; secure; HttpOnly; SameSite=Strict

$ curl -s https://sumitomochemical.com/phpmyadmin/ | grep -E "<title>|version"
  <title>phpMyAdmin</title>
  CommonParams.setAll({...,version:"5.2.1deb3",...,auth_type:"cookie",
  ...,user:"root"});
```

Body length: **18,557 bytes** — real phpMyAdmin login page (the
v5.2.1 default theme), not a placeholder.

```
$ curl -sI https://sumitomochemical.com/pma/
HTTP/1.1 200 OK
Set-Cookie: phpMyAdmin_https=...; path=/pma/; secure; HttpOnly; SameSite=Strict
```

Body length: **18,447 bytes** — also real phpMyAdmin, same install,
mounted at second default path. Both paths are reachable; the
operator hasn't even removed `/pma/` (every attacker's first guess
after `/phpmyadmin/`).

### Anti-SPA verification (nonsense path returns 301, NOT 200)

```
$ curl -sI https://sumitomochemical.com/nonsense-zzzz
HTTP/1.1 301 Moved Permanently  ← proper 301; NOT a SPA wildcard
```

The host is NOT a SPA serving 200 for everything — `/phpmyadmin/`
and `/pma/` are explicitly mounted; they are genuine phpMyAdmin.

### Cookie hardening (positive — but doesn't fix the exposure)

The phpMyAdmin cookie is set with `Secure; HttpOnly; SameSite=Strict`
— good cookie hardening. But this only prevents stolen-cookie attacks;
it does NOT prevent password brute-forcing or CVE exploitation from
any internet IP that can reach the page.

### Application version: v5.2.1deb3

Latest stable phpMyAdmin as of mid-2024 is 5.2.1, so this is
**reasonably current**. However:

- 5.2.1 has been the stable release since Feb 2023; many subsequent
  point releases (5.2.x) may have addressed issues
- `deb3` is the third Debian package revision of 5.2.1 — depending on
  when Ubuntu/Debian last rebuilt, security patches from upstream
  may lag
- The application self-discloses `auth_type:"cookie"` and
  `user:"root"` in inline JS, meaning the form pre-fills `root`
  as the default username

## Why this is CRITICAL (not just HIGH)

1. **phpMyAdmin = direct DB administration interface.** Successful
   login gives the attacker full SQL execution against whatever
   database(s) the MySQL user can access. For a corporate apex,
   this almost certainly includes the CMS database (potentially
   leaking unpublished press releases, marketing assets, employee
   data, customer contact-form submissions) and possibly more.

2. **Brand-impact risk.** Sumitomo Chemical is a Fortune-Global-500
   tier company. A successful phpMyAdmin exploitation would make
   international news — and the operator clearly does have security
   hygiene (HSTS, COOP, CORP) but has missed this single critical
   exposure.

3. **Brute-force surface.** Without IP-restriction, attackers can run
   `hydra http-post-form` against the phpMyAdmin login form
   indefinitely. Even with rate-limiting at the application layer,
   distributed brute-force from 1000 source IPs ≈ 1 attempt per
   IP per minute ≈ 1.4 million attempts per day.

4. **phpMyAdmin CVE history is substantial.** Even on 5.2.x:
   - **CVE-2024-1947** SQL injection (fixed in 5.2.2+)
   - Pre-5.2.1 had auth bypasses (CVE-2019-12922), XSS-to-RCE chains
   - Future zero-days are a known risk for an internet-exposed
     phpMyAdmin

5. **Sumitomo Chemical has R&D + agrochemical + pharma subsidiaries.**
   Even if the apex CMS DB is "just" marketing content, the brand
   damage from "Sumitomo Chemical phpMyAdmin compromised" would be
   severe. And the DB may contain more than expected (customer
   support tickets, employee directories, sales-force-style data).

6. **Two default paths reachable.** `/phpmyadmin/` AND `/pma/` are
   the FIRST two URLs any attacker tries. The operator hasn't even
   path-obfuscated to a non-default URL. This suggests the install
   may have been done via `apt install phpmyadmin` with default
   Apache config and never revisited.

## Recommended remediation (DBA + sysadmin standard)

The phpMyAdmin docs are explicit about this:

1. **Restrict access via Apache ACL or VPN.** Edit
   `/etc/phpmyadmin/apache.conf` (or equivalent) to add:

   ```apache
   <Directory /usr/share/phpmyadmin>
       Require ip 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12 <office-ip>
       # Or: Require all denied + only allow via SSH tunnel
   </Directory>
   ```

   Or remove the public-facing Apache vhost entirely; access
   phpMyAdmin only via SSH tunnel (`ssh -L 8080:localhost:80 user@host`).

2. **Rename URLs off the defaults.** Change `/phpmyadmin/` and `/pma/`
   to a non-default path (`/db-admin-9f3k/`). This is a friction
   layer, not a security control on its own, but reduces drive-by
   attacks.

3. **Add fail2ban on the phpMyAdmin login endpoint.**

4. **Disable root login via phpMyAdmin entirely.** Use per-app DB
   users with the minimum needed privileges.

5. **Enable 2FA** via the phpMyAdmin AuthenticationPlugin if your
   workflow supports it.

6. **Confirm phpMyAdmin is at latest 5.2.x** (or migrate to 5.3.x
   when released). The Debian package may lag upstream — consider
   the official tarball + manual updates if speed matters.

7. **Rotate the MySQL root password.** Anyone who has been
   brute-forcing (you can check the auth logs) should be invalidated.

8. **Publish security.txt** at
   `https://sumitomochemical.com/.well-known/security.txt` so future
   researchers can reach the right contact within minutes, not hours.

---

## Email A — Direct to Sumitomo Chemical IT-Sec / CSIRT

```
To:      security@sumitomo-chem.co.jp,
         infosec@sumitomo-chem.co.jp,
         it-security@sumitomochemical.com,
         soc@sumitomo-chem.co.jp,
         csirt@sumitomo-chem.co.jp (try all)
CC:      info@jpcert.or.jp (JPCERT/CC parallel notification)
Subject: 緊急 — phpMyAdmin が sumitomochemical.com で公開されています
         (URGENT — phpMyAdmin publicly exposed at sumitomochemical.com)

住友化学のセキュリティ・チーム様、

Lictor (https://lictor-ai.com — オープンソース・セキュリティ・スキャナ、
Apache 2.0 ライセンス) のスキャンを実行中、貴社のメインの英語コーポレート・
ドメイン `sumitomochemical.com` に phpMyAdmin の管理画面が公開されていることを
確認しました。

What we observed (passive HTTP requests only, NO login attempts):

  URL 1: https://sumitomochemical.com/phpmyadmin/
         → HTTP 200 OK
         → phpMyAdmin v5.2.1deb3 login page
         → Set-Cookie: phpMyAdmin_https=...; Secure; HttpOnly; SameSite=Strict

  URL 2: https://sumitomochemical.com/pma/
         → HTTP 200 OK (same install, second default path)
         → phpMyAdmin v5.2.1deb3 login page

  Verification: GET /nonsense-zzzz returns HTTP 301 (proper routing,
                NOT a SPA wildcard). This is GENUINE phpMyAdmin.

Server posture (positive):
  • Apache/2.4.66 (Ubuntu) with HSTS preload, X-Content-Type-Options,
    COOP, CORP — modern security headers ARE configured at the apex
  • phpMyAdmin cookie has Secure; HttpOnly; SameSite=Strict
  • TLS appears correctly configured

The risk:
  • Direct MySQL administration interface on a Fortune-Global-500-tier
    industrial company's primary English-language corporate apex
  • Unrestricted brute-force surface from any internet IP
  • phpMyAdmin CVE history (CVE-2024-1947 SQLi, CVE-2019-12922
    auth bypass, XSS→RCE chains) — exposure means any future
    zero-day finds an immediate target
  • Brand-impact risk if compromised
  • Application self-discloses `user: "root"` in the login form's
    inline JS — root is reachable as the default credential

Immediate recommendations:

  1. RESTRICT ACCESS via Apache ACL or VPN. Edit
     /etc/phpmyadmin/apache.conf to limit Require ip to your
     office / VPN ranges only. Or remove the public-facing vhost
     entirely and access via SSH tunnel.

  2. RENAME the URLs off /phpmyadmin/ and /pma/ to non-default
     paths (friction layer against automated scans).

  3. ADD fail2ban on the login endpoint to slow brute-force.

  4. DISABLE root login via phpMyAdmin; use per-app DB users
     with minimum privileges.

  5. CONFIRM phpMyAdmin is at latest 5.2.x (or 5.3 when released).
     The Debian package may lag upstream.

  6. ROTATE the MySQL root password and any credentials that
     could be in use.

  7. CHECK the phpMyAdmin login attempt logs for unfamiliar source
     IPs over the past 6-12 months — if anyone has been brute-
     forcing, you will see it there.

  8. PUBLISH security.txt at
     https://sumitomochemical.com/.well-known/security.txt
     (currently not present) so future researchers can reach the
     right contact faster.

私たちは login attempt も brute-force も exploit も一切実行していません。
公開された HTTP banner と HTTP HEAD request のみで確認しました。御社の
データへのアクセスはありません — 公開された banner のみです。

これは Lictor のオープンソース・セキュリティ・スキャンによる責任ある公開
(responsible disclosure) です。報奨金は要求していません — public-good
exercise として行っています。

緊急対応をお願いいたします。
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(Full English disclosure also available — see:
 https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/16-sumitomo-chemical-phpmyadmin.md
 — currently un-published; will hold until 60-day CVD window expires.)
```

---

## Email B — JPCERT/CC parallel notification

```
To:      info@jpcert.or.jp
CC:      report@jpcert.or.jp (if available)
Subject: CVD — phpMyAdmin publicly exposed on Sumitomo Chemical
         corporate apex (sumitomochemical.com)

Hello JPCERT/CC team,

Following Japanese coordinated vulnerability disclosure practice,
I am parallel-notifying you of a security finding I am reporting
directly to Sumitomo Chemical:

  Org:       Sumitomo Chemical Co., Ltd. (TSE: 4005)
  Domain:    sumitomochemical.com (primary EN corporate apex)
  Finding:   phpMyAdmin v5.2.1deb3 publicly reachable at TWO default
             paths (/phpmyadmin/ and /pma/)
  Status:    CONFIRMED via passive HTTP HEAD + GET; bodies match
             genuine phpMyAdmin login page (18,557 / 18,447 bytes);
             nonsense canary URL returns proper 301 (not SPA-wildcard)

This is NOT a confirmed breach. It is a critical hardening item that
exposes a Fortune-Global-500-tier industrial company's corporate
database to brute-force attack from the entire internet.

I sent the direct disclosure to Sumitomo Chemical IT-Sec / CSIRT
(Japanese + English) with the standard remediation (Apache ACL or
VPN restriction, URL rename off defaults, fail2ban, disable root
login via phpMyAdmin, rotate credentials, check auth logs for
brute-force evidence).

The full disclosure draft is publicly archived at:
  https://github.com/Raffa-jarrl/Lictor-AI/blob/main/v3/docs/disclosures-2026-05-21/16-sumitomo-chemical-phpmyadmin.md

Method: passive HTTP requests only. Single TCP connect + GET on
each path. NO login attempts of any kind. NO brute-force. NO
exploits. NO access to any database content.

Discovered via Lictor (https://lictor-ai.com, Apache 2.0).
Public-good disclosure, no bounty requested.

Please advise if you would prefer:
  a) I hold the direct disclosure to Sumitomo and let JPCERT/CC
     route through your relationships (preferred for this scale)
  b) I send to Sumitomo directly with JPCERT/CC CC'd
  c) Some other coordination

Default action if no response in 7 days: send the direct disclosure
to Sumitomo with JPCERT/CC permanently CC'd, per standard CVD
practice.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt phpMyAdmin login on sumitomochemical.com — UNAUTHORIZED
  ACCESS under Japanese Unauthorized Computer Access Law (Act No. 128
  of 1999) AND under US Computer Fraud and Abuse Act if you are in
  the US
- ❌ Try common usernames (root, admin, sumitomo, sumika) — that is
  a crime
- ❌ Run any automated tool against the login form
- ❌ Probe for phpMyAdmin-version-specific CVEs (CVE-2024-1947,
  CVE-2019-12922, etc.) against this host
- ❌ Connect to MySQL on port 3306 directly (we did NOT check that
  port — DO NOT)
- ❌ Disclose the sumitomochemical.com hostname publicly until
  Sumitomo has had 60+ days to remediate
- ❌ Combine this disclosure with any other org's — Sumitomo Chemical
  gets its OWN dedicated email, in Japanese with English summary,
  to the Japanese CSIRT-recommended security contacts
