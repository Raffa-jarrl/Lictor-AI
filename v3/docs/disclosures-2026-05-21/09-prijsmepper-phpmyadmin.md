# Disclosure 9 — prijsmepper.nl phpMyAdmin exposed at /phpmyadmin/ and /pma/ (HIGH)

**Target:** `prijsmepper.nl` → `37.97.145.109` (Netherlands)
**Owner:** Prijsmepper (Dutch consumer comparison/price site)
**Service:** **phpMyAdmin login page exposed publicly** at TWO URLs:
- `https://prijsmepper.nl/phpmyadmin/`
- `https://prijsmepper.nl/pma/`
**Risk:** **HIGH** — direct MySQL login interface on the internet, brute-force surface + classic default-credential history
**Action:** Email Prijsmepper directly; CC info@ if no specific security contact

---

## What Lictor observed (passive HTTP only, NEVER login)

```
$ curl -s https://prijsmepper.nl/phpmyadmin/ | grep title
  <title>phpMyAdmin</title>

$ curl -s https://prijsmepper.nl/pma/ | grep title
  <title>phpMyAdmin</title>

Both pages return:
  HTTP/2 200
  Content-Type: text/html
  <title>phpMyAdmin</title>
  <h1>Welcome to phpMyAdmin</h1>
  <img src="./themes/pmahomme/img/logo_right.png" id="imLogo" alt="phpMyAdmin">

Both pages serve identical 18,570-byte responses.
Root page (https://prijsmepper.nl/) is a different 8,824-byte site.
A nonsense URL (https://prijsmepper.nl/__zzz_canary) returns 404.
```

So the host correctly routes 404s and these are NOT SPA-wildcard 200s
— they're the genuine phpMyAdmin install, available at both `/phpmyadmin/`
and `/pma/` (both the default install paths most attackers try).

The phpMyAdmin response itself self-discloses a configuration issue:

> "There is a mismatch between HTTPS indicated on the server and client.
> This can lead to a non working phpMyAdmin or a security risk. Please
> fix your server configuration to indicate HTTPS properly."

So even the application is warning the operator about a misconfiguration.

## Why this matters (HIGH severity)

- **phpMyAdmin is a direct MySQL login interface.** If default or weak
  credentials are configured (root/blank, root/root, common passwords),
  an attacker gets the entire database with one HTTP POST.
- **The username brute-force surface is open** to the whole internet.
  Without rate-limiting or fail2ban-class protection, an attacker can
  try millions of password combinations from a single source IP.
- **phpMyAdmin CVE history**: SQL injection bypasses (CVE-2020-26935),
  auth bypasses (CVE-2019-12922), XSS-to-RCE chains have appeared in
  multiple versions. Even a patched install is a target because of
  zero-day risk.
- **Two paths reachable** (`/phpmyadmin/` and `/pma/`): suggests this
  is the default install with no path obfuscation. Both paths in the
  scanner's wordlist are the first things any attacker tries.
- **HTTPS-vs-HTTP mismatch warning** appearing in the phpMyAdmin UI
  itself indicates the server may be running phpMyAdmin behind a
  reverse proxy without proper `$cfg['PmaAbsoluteUri']` / `X-Forwarded-Proto`
  configuration — a configuration error that often also weakens cookie
  security.

## Recommended remediation (for Prijsmepper IT)

The phpMyAdmin team's official hardening guidance, applied here:

1. **Restrict access by IP or behind a VPN.** phpMyAdmin should not be
   reachable from the public internet. Most production deployments
   restrict access to office IPs or require SSH-tunneling.
2. **Rename the URL** off the defaults `/phpmyadmin/` and `/pma/` to
   make automated discovery harder (not a security control on its own,
   but a friction layer).
3. **Add fail2ban or webserver rate-limiting** on the phpMyAdmin login
   endpoint to slow username/password brute-forcing.
4. **Use 2FA** via the phpMyAdmin `AuthenticationPlugin` if Apache
   modules support it.
5. **Confirm the phpMyAdmin version is current** (latest stable as of
   2026 is 5.2.x). Older 4.x branches have unpatched CVEs.
6. **Disable the `root` user via phpMyAdmin** entirely; use per-application
   MySQL users with the minimum needed privileges.
7. **Fix the HTTPS-vs-HTTP mismatch** in the phpMyAdmin config so cookies
   are flagged Secure and CSRF tokens aren't leaked over HTTP.
8. **Publish a `/.well-known/security.txt`** so future researchers can
   reach the right contact. (Currently 404.)

---

## Email — Direct to Prijsmepper

The Prijsmepper site's contact page didn't expose an email address in
plain HTML. Best routes:

1. Look on the live site's contact form / about page (likely behind JS)
2. Try generic emails: `security@prijsmepper.nl`, `info@prijsmepper.nl`,
   `support@prijsmepper.nl`
3. Hosting provider: 37.97.145.109 is Dutch (likely TransIP, Hostnet,
   or similar Netherlands VPS provider) — they often have abuse contacts
   who can forward to the customer
4. Mail records point at `prijsmepper-nl.mail.protection.outlook.com`
   (Microsoft 365 mail filtering) — try general inbox patterns

Email draft (Dutch, with English fallback):

```
To:      security@prijsmepper.nl, info@prijsmepper.nl, support@prijsmepper.nl
Subject: Vriendelijke melding — publiek bereikbare phpMyAdmin op
         prijsmepper.nl/phpmyadmin (HIGH security risk)

Beste team van Prijsmepper,

Met deze e-mail wil ik u attent maken op een security-issue dat
we tegengekomen zijn tijdens een scan van publiek bereikbare diensten
op bug-bounty-scope domeinen.

Wat we waargenomen hebben (alleen passieve HTTP, GEEN login-pogingen):

  Domein:    prijsmepper.nl
  IP:        37.97.145.109 (Nederland)
  Pad 1:     https://prijsmepper.nl/phpmyadmin/  → HTTP 200, phpMyAdmin
  Pad 2:     https://prijsmepper.nl/pma/         → HTTP 200, phpMyAdmin

Beide URL's serveren een werkende phpMyAdmin-loginpagina (18.5 KB,
title "phpMyAdmin", standaard pmahomme thema). Een 404-test op een
random URL bewijst dat het geen catch-all is — dit is een echte
phpMyAdmin-installatie.

phpMyAdmin geeft zelf een waarschuwing in de pagina:
  "There is a mismatch between HTTPS indicated on the server and
   client. This can lead to a non working phpMyAdmin or a security
   risk."

De bezorgdheid:

  - phpMyAdmin is een directe MySQL login-interface
  - Een aanvaller kan onbeperkt username/password combinaties proberen
  - Standaard root-credentials (root/blank, root/root) zijn historisch
    een veelvoorkomende kwetsbaarheid
  - phpMyAdmin heeft een actieve CVE-geschiedenis (SQL injection,
    auth bypass, XSS → RCE chains)

Aanbevelingen:

  1. Beperk toegang per IP of via VPN (phpMyAdmin hoort niet publiek)
  2. Hernoem de URL weg van /phpmyadmin/ en /pma/
  3. Voeg fail2ban toe op de loginpagina
  4. Schakel 2FA in als de Apache modules dat toelaten
  5. Bevestig dat phpMyAdmin patched is op 5.2.x
  6. Fix de HTTPS/HTTP mismatch in de phpMyAdmin config
  7. Publiceer een security.txt op /.well-known/security.txt

Wij hebben GEEN login-pogingen gedaan, GEEN brute-force, GEEN
exploits. Alleen drie HTTP GET-requests om te bevestigen dat de
pagina echt phpMyAdmin is en geen catch-all 200.

Dit is een open-source security-scan via Lictor (https://lictor-ai.com,
Apache 2.0 licentie). We doen verantwoorde melding van zulke
exposures als publiek-belang oefening; we vragen geen bounty.

Een security.txt zou ons en andere onderzoekers helpen om u in de
toekomst sneller te bereiken.

Met vriendelijke groet,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Try ANY login on /phpmyadmin/ or /pma/ — that is unauthorized access
- ❌ Brute-force credentials (even "common" defaults — DON'T)
- ❌ Try SQL injection payloads on the login form
- ❌ Probe for phpMyAdmin-version-specific CVEs
- ❌ Disclose publicly until Prijsmepper has had time to remediate (60-day
  CVD window)
- ❌ Combine with the AZ Diest disclosure or report multiple findings as
  a single email — each gets its own dedicated message so the receiving
  team isn't overwhelmed
