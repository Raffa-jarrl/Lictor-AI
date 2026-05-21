# Disclosure 11 — golf.co.il — MySQL 5.7.23 directly exposed on the internet (HIGH/CRITICAL)

**Target:** `golf.co.il:3306` → `143.95.77.247`
**Owner:** Golf.co.il (Israeli golf-equipment e-commerce, WooCommerce/WordPress, operator: Ronen Zur)
**Service:** **MySQL 5.7.23-23** answering on the public internet WITHOUT IP allow-listing
**Risk:** **HIGH→CRITICAL** — direct DB exposure, brute-force surface = entire customer table / order history / WooCommerce session data
**Action:** Email Golf.co.il owner directly via the contact form / Facebook page; CC hosting provider abuse

---

## What Lictor observed (banner-grab only, NEVER login)

```
$ nc -w 5 golf.co.il 3306 | xxd | head -2
00000000: 4d00 0000 0a35 2e37 2e32 332d 3233 0066  M....5.7.23-23.f
00000010: 8ac7 0029 6668 4f5d 6c57 1e00 ffff c002  ...)fhO]lW......
00000040: 5f6e 6174 6976 655f 7061 7373 776f 7264  _native_password
```

Parsing the MySQL Protocol Handshake packet (server → client, packet
type 0x0a):

- Packet length: 0x4D (77 bytes) — standard
- Protocol version: 0x0A (v10, current)
- Server version string: **"5.7.23-23"** — this is MySQL 5.7.23 community-edition
- Thread ID, salt, capabilities flags follow
- Auth plugin name: **`mysql_native_password`** (default)

**The key point:** golf.co.il sent us a HANDSHAKE PACKET — not an error
response. This means the server is configured to accept TCP connections
from any source IP and proceed to the authentication phase. Compare to
properly-hardened MariaDB instances (e.g. otzar.co.il, nofar.org.il)
which return ERR packet 1130 "Host '...' is not allowed to connect"
immediately, before the handshake.

For golf.co.il, the next step a malicious client would take is to send
a Login Request packet with a username + password attempt. We did NOT
do this. But anyone on the internet can, and can keep trying forever
without IP-based rate limiting visible at the network layer.

## Site context

- `https://golf.co.il/` = Israeli golf-equipment e-commerce
- Platform: **WooCommerce on WordPress** (powered by LiteSpeed / Pure-FTPd)
- Operator: **Ronen Zur** (per Facebook profile linked in site metadata)
- The WooCommerce DB schema typically contains:
  - `wp_users` — customer credentials (bcrypt or PHPpass hashes)
  - `wp_usermeta` — names, emails, billing/shipping addresses
  - `wp_postmeta` — order line items, payment status
  - `wp_options` — site-wide config, sometimes including API keys
  - `wp_woocommerce_*` — order details, customer addresses, IPs, possibly
    truncated credit-card hints depending on which payment gateway is used

If an attacker brute-forces the root password (or any DB user), the
entire WooCommerce DB is theirs. This is a high-impact retail exposure.

## Why this is HIGH/CRITICAL severity

1. **Direct MySQL on internet with no IP allowlist**: every internet IP
   can attempt authentication. Brute-force is unlimited.
2. **MySQL 5.7.23 has known CVEs**: 5.7.23 was released 2018-07; security
   fixes from 5.7.24 through 5.7.44 are NOT applied. Possible auth-bypass
   or remote-code-execution vectors depending on patch level.
3. **WooCommerce DB content**: customer PII (names, emails, addresses),
   order history, possibly hashed passwords. The site is active commerce
   so this is real customer data, not test data.
4. **No visible rate-limiting**: nothing prevents an attacker from running
   `hydra mysql://golf.co.il -L users.txt -P passwords.txt` for days.
5. **Companion port-21 (FTP) also exposed** on same host: dual exposure
   suggests this is the production WordPress host directly on the
   internet, not behind a managed-DB service or VPC.

## Recommended remediation (for Golf.co.il)

The MySQL docs and any DBA will say the same things:

1. **Bind MySQL to localhost only**: edit
   `/etc/mysql/mysql.conf.d/mysqld.cnf` to set `bind-address = 127.0.0.1`
   and restart. WordPress connects locally via socket; there is NO reason
   for port 3306 to be reachable from the internet.
2. **OR if remote access is genuinely needed** (a backup script, a
   developer): firewall port 3306 to only allow specific source IPs,
   AND require SSL/TLS, AND use a dedicated DB user with minimum
   privileges (not `root`).
3. **Patch MySQL 5.7.23 → 5.7.44 (last 5.7) or migrate to 8.0**: 5.7
   reaches EOL October 2023. Many CVEs accumulated.
4. **Rotate any DB credentials** that may have been brute-force attempted
   recently. Check MySQL's `general_log` (if enabled) for connection
   attempts from unfamiliar IPs.
5. **Also close port 21 (FTP)** on the same host — use SFTP via OpenSSH.

---

## Email — to Golf.co.il owner

The site lists `Ronen Zur` as the operator and links to his Facebook.
The site uses WooCommerce so they likely have an `info@golf.co.il`
or `support@golf.co.il` inbox. The hosting provider IP block
(`143.95.77.0/24`) is likely an Israeli VPS.

```
To:      info@golf.co.il, support@golf.co.il (one of these likely exists)
CC:      hostmaster@golf.co.il (try)
Subject: דחוף - MySQL חשוף לאינטרנט במופע golf.co.il (HIGH security risk)
         (URGENT — MySQL directly exposed to internet on golf.co.il)

שלום רונן והצוות,

אנחנו מקבוצת חוקרי-אבטחה ב-Lictor (open-source). במהלך סריקה של
דיירקטוריות גלויות באינטרנט גילינו ש-MySQL server שלכם חשוף ישירות
לאינטרנט הציבורי, ללא הגבלת-IP ברמת הרשת.

What we found (banner-grab only, NO login attempts of any kind):

  Host:    golf.co.il → 143.95.77.247
  Port:    3306 (MySQL)
  Server:  MySQL 5.7.23-23 (community edition)
  Auth:    mysql_native_password (default)
  Status:  Server sent us a HANDSHAKE PACKET (no IP restriction in
           the network layer — anyone can attempt logins)

The concern (high/critical for a live commerce site):

  • Any attacker on the internet can run unlimited brute-force
    attempts against MySQL credentials
  • If `root` (or any DB user) has a weak password, the entire
    WooCommerce DB is exposed: wp_users (hashed passwords),
    wp_usermeta (customer names/emails/addresses), wp_postmeta
    (order history), wp_woocommerce_* (full order details)
  • MySQL 5.7.23 was released 2018-07; many CVEs since (latest 5.7
    is 5.7.44). 5.7 reached EOL October 2023.
  • Port 21 (FTP) on the same host suggests this is the production
    WordPress host directly on the internet, not behind a managed-DB
    service.

Immediate actions (DBA-standard playbook):

  1. Edit /etc/mysql/mysql.conf.d/mysqld.cnf — set:
       bind-address = 127.0.0.1
     and restart MySQL. WordPress connects locally via socket;
     there is NO reason for 3306 to be reachable from the internet.

  2. OR (if you have legitimate remote access need): firewall 3306
     to only allow specific source IPs, AND require SSL/TLS, AND
     use a dedicated DB user (not root) with minimum privileges.

  3. Patch to MySQL 5.7.44 (last 5.7) or migrate to 8.0 — your
     current version has 5+ years of accumulated CVEs.

  4. Check MySQL general_log (if enabled) for connection attempts
     from unfamiliar IPs over the past months — if anyone has been
     brute-forcing, you'd see it there.

  5. Also close port 21 (FTP) on same host — use SFTP via OpenSSH
     instead. FTP credentials travel plaintext.

We did NOT attempt any login, NOT any brute-force, NOT any exploits.
A single TCP connect + 256-byte banner read on each of the open
ports. We do NOT have any access to your data — only to the public
banner that announces the service is there.

This is an open-source security scan via Lictor (https://lictor-ai.com,
Apache 2.0). We do public-good responsible disclosure without
requesting bounty.

A security.txt at https://golf.co.il/.well-known/security.txt would
help us and other researchers reach you faster in the future.

תודה, ובהצלחה,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(English summary above for any DBA who reads English better;
willing to follow up in Hebrew on any specific recommendation.)
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt MySQL login on golf.co.il:3306 — that's unauthorized access
- ❌ Try common usernames/passwords (root, admin, mysql) — that's a crime in IL
- ❌ Probe for MySQL-specific CVEs of the 5.7.23 version
- ❌ Touch the FTP service or any other ports beyond the banner-grab
- ❌ Disclose publicly until Golf.co.il has had time to remediate
  (60-day CVD window is the standard Belgian/EU norm, similar in IL)
- ❌ Combine this with the harel.co.il (insurance) or any other IL
  disclosure — each org gets its own dedicated email
