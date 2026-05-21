# Disclosure 12 — Harel Insurance (harel.co.il) — public ProFTPD "Default Installation" (HIGH given context)

**Target:** `harel.co.il:21` → `185.145.254.160` (Israel)
**Owner:** **Harel Insurance & Finance Ltd** — one of Israel's largest insurance groups
  (life, health, P&C insurance + pension funds)
**Service:** ProFTPD Server with banner **"ProFTPD Default Installation"**
**Risk:** **HIGH given the org context** — insurance industry stores PII + financial + medical data; unhardened FTP is a critical perimeter hygiene issue
**Action:** Email Harel security/IT + CC the Israel National Cyber Directorate (INCD) coordinated disclosure

---

## What Lictor observed (banner-grab only)

```
$ nc -w 5 harel.co.il 21
220 ProFTPD Server (ProFTPD Default Installation) [::ffff:185.145.254.160]
```

That's the giveaway: the literal text **"ProFTPD Default Installation"**.
ProFTPD emits this exact phrase in its banner until the operator changes
the `ServerName` directive in `/etc/proftpd/proftpd.conf`. Same pattern
we observed tonight on Blue Sky Travel Vietnam and (separately) on AZ
Diest hospital — except this is a major Israeli insurer.

The IP `185.145.254.160` is hosted on **AS50384 (Bezeq International)**
based on previous geolocation lookups — an Israeli ISP. So this is
Israel-hosted infrastructure, not a third-party cloud or partner.

## Why this is HIGH (despite being just "FTP exposed")

Harel Insurance handles:
- **Life insurance policies** (beneficiary data, medical underwriting)
- **Health insurance / supplementary coverage** (medical records, claims)
- **Pension funds** (financial data, salary, employer details)
- **P&C insurance** (vehicle, home, liability — addresses, valuations)

The bar for perimeter hygiene at an insurer is HIGHER than for a tour
operator or e-commerce site, because:
- **Plaintext credentials over FTP** — anyone passively observing traffic
  to port 21 (e.g. ISP-level surveillance, MITM on partner networks)
  sees the FTP user/pass in cleartext
- **Username brute-force surface** — open to entire internet, no
  rate-limiting visible
- **"Default Installation" banner** — strongly suggests unhardened
  config: probably default users, default `mod_*` modules enabled,
  default logging, default chroot behavior
- **ProFTPD CVE history** — CVE-2020-9273 (mod_sftp use-after-free,
  RCE), CVE-2019-12815 (mod_copy arbitrary file copy), CVE-2015-3306
  (mod_copy unauth file read). Without knowing the exact version
  (banner doesn't disclose), all of these are open question marks.
- **Insurance industry regulator context** — Israeli Ministry of
  Finance has insurance-industry cyber directives (Capital Markets,
  Insurance and Savings Authority — `mof.gov.il`); a plaintext FTP
  exposure may be a compliance issue independent of any actual breach.

## Recommended remediation (for Harel IT)

The remediation playbook is the same as for any FTP exposure — but
the URGENCY is higher because of the org context:

1. **Replace plaintext FTP with SFTP** (port 22 via OpenSSH) or **FTPS**
   (AUTH TLS on port 21 / FTPS on port 990). Both encrypt the
   credentials and data in transit.
2. **Restrict by IP / behind VPN** — if this FTP is only used by
   specific partners (a reinsurer, a claims-processing partner, a
   payroll vendor), firewall it to those source IPs.
3. **Add fail2ban or webserver-level rate-limiting** on the FTP login
   endpoint to slow username brute-forcing.
4. **Customize the banner** — edit `ServerName "Harel-FTP"` in
   `/etc/proftpd/proftpd.conf` to stop disclosing "Default Installation".
5. **Confirm ProFTPD version is current** (latest stable 1.3.8b+ as
   of 2026) and that mod_sftp and mod_copy are patched.
6. **Internal audit**: pull the FTP server's access log and look for
   unfamiliar source-IP patterns over the past 6-12 months.
7. **Publish security.txt** at https://harel.co.il/.well-known/security.txt
   so future researchers can reach the right contact faster (currently
   not present).

---

## Email A — direct to Harel security/IT

Harel's main contact channels are corporate; a likely IT security inbox:
- `security@harel-group.co.il` (try)
- `infosec@harel-group.co.il` (try)
- `it-security@harel.co.il` (try)
- General contact form on `https://www.harel.co.il/contact-us/`

```
To:      security@harel-group.co.il, infosec@harel-group.co.il,
         it-security@harel.co.il (try all — one will exist)
Subject: דחוף - שרת FTP חשוף לאינטרנט הציבורי על harel.co.il:21
         (URGENT — public-internet FTP exposed on harel.co.il:21)

שלום צוות אבטחת המידע של הראל,

אנחנו מקבוצת חוקרי-אבטחה ב-Lictor (open-source). במהלך סריקה
שגרתית של דיירקטוריות גלויות באינטרנט גילנו ש-FTP server שלכם
חשוף ישירות לרשת הציבורית, וה-banner שלו מצביע על קונפיגורציה
לא-מוקשחת.

What we observed (banner-grab only, NO login attempts):

  Host:    harel.co.il → 185.145.254.160 (Israeli IP, Bezeq Int'l)
  Port:    21 (FTP, plaintext)
  Banner:  "220 ProFTPD Server (ProFTPD Default Installation)
            [::ffff:185.145.254.160]"

The "Default Installation" phrase in the banner is ProFTPD's stock
configuration — it suggests the operator hasn't modified the
ServerName directive in /etc/proftpd/proftpd.conf, which often
correlates with broader hardening gaps (default mod_* modules,
default chroot, etc.).

החשש (בעיקר בהקשר של חברת ביטוח):

  • Plaintext credentials עוברים לא-מוצפנים על FTP — כל מי
    שמשמש כמרי-AT-MAN על הרשת רואה את שם המשתמש והסיסמה
  • Username brute-force surface פתוח לכל IP באינטרנט בלי
    הגבלת קצב נראית ב-network layer
  • בהקשר של ביטוח: PII רגיש (שמות, ת.ז., כתובות), נתוני
    תביעות רפואיות, נתוני פנסיה
  • ProFTPD CVE history כולל CVE-2020-9273 (mod_sftp RCE),
    CVE-2019-12815 (mod_copy arbitrary file copy),
    CVE-2015-3306 (mod_copy unauth file read) — בלי גרסה
    מדויקת ב-banner קשה לפסול אחד מהם
  • דרישות רגולטוריות של רשות שוק ההון, הביטוח והחיסכון:
    plaintext FTP על perimeter הוא issue של תאימות גם בלי
    אירוע בפועל

המלצות (DBA/security playbook סטנדרטי):

  1. החלף FTP ב-SFTP (port 22 דרך OpenSSH) או FTPS (AUTH TLS
     על port 21) — מצפין credentials ונתונים בתעבורה
  2. הגבל גישה לפי IP או דרך VPN — אם FTP זה משמש לפרטנרים
     ספציפיים (ביטוח-משנה, מעבדים, פרל)
  3. הוסף fail2ban על endpoint ההתחברות להאט brute-force
  4. שנה את ServerName ב-proftpd.conf — מסיר את ה-"Default
     Installation" tell ומקטין surface של disclosure
  5. אשר שגרסת ProFTPD עדכנית (latest stable 1.3.8b+)
  6. Audit פנימי: משוך FTP access log וחפש patterns חריגים
     של source-IP ב-6-12 חודשים האחרונים
  7. פרסם security.txt על https://harel.co.il/.well-known/security.txt

לא ניסינו אף login, לא brute-force, לא exploit. רק TCP connect
יחיד + read של 256 byte banner על port 21. אין לנו שום גישה
ל-data שלכם — רק ל-banner הציבורי שמצהיר שהשירות שם.

זוהי סריקת-אבטחה open-source דרך Lictor (https://lictor-ai.com,
רישיון Apache 2.0). אנחנו עושים disclosure אחראי לטובת הציבור
ללא בקשת bounty.

A security.txt at https://harel.co.il/.well-known/security.txt
would help us and other researchers reach you faster on future
findings.

תודה,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(English summary available on request.)
```

---

## Email B — INCD (Israel National Cyber Directorate)

The INCD operates the CERT-IL service and has a coordinated vulnerability
disclosure process. For an insurance-industry finding, parallel-notifying
INCD is the right Israeli pattern.

```
To:      cert@cert.gov.il
CC:      report@cyber.gov.il
Subject: CVD — public-internet FTP on Israeli insurance company
         (harel.co.il:21, ProFTPD Default Installation)

Hello CERT-IL / INCD team,

Following Israeli coordinated-vulnerability-disclosure practice, I'm
parallel-notifying you of a security hardening item that I'm
reporting directly to Harel Insurance (harel.co.il):

  Host:        harel.co.il → 185.145.254.160 (Bezeq Int'l)
  Port:        21 (FTP, plaintext)
  Service:     ProFTPD Server
  Banner:      "ProFTPD Default Installation" (literal — unhardened)
  Owner:       Harel Insurance & Finance Ltd (life/health/pension/P&C)

This is NOT a confirmed breach. It's a hardening item:
- Plaintext credentials on the perimeter of a major Israeli insurer
- Username brute-force surface, no visible rate-limiting
- "Default Installation" banner suggests unhardened ProFTPD config
- ProFTPD CVE history (CVE-2020-9273, CVE-2019-12815, CVE-2015-3306)
- Likely Capital Markets, Insurance and Savings Authority compliance
  question independent of any actual breach

My findings are based only on:
  $ nc -w 5 harel.co.il 21
  220 ProFTPD Server (ProFTPD Default Installation) [::ffff:185.145.254.160]

No login attempts, no brute-force, no exploits. Single TCP connect +
banner read.

I'm sending the direct disclosure to Harel security/IT (Hebrew +
English summary) with the standard SFTP/FTPS migration and
IP-restriction recommendations.

Discovered via Lictor (https://lictor-ai.com, Apache 2.0). Public-good
disclosure, no bounty requested.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt FTP login on harel.co.il:21 — that's unauthorized access
  under Israeli Computer Law (§4)
- ❌ Try common usernames (anonymous, admin, harel) — same
- ❌ Probe for ProFTPD-version-specific CVEs against this host
- ❌ Connect via SFTP/SSH or any other port we didn't observe
- ❌ Disclose publicly until Harel has had time to remediate
  (60-day CVD window is the standard norm)
- ❌ Combine with the golf.co.il MySQL or any other IL disclosure
  — each org gets its own dedicated email; especially for an
  insurer where the wrong inbox could be a compliance issue
