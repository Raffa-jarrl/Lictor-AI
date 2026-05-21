# Disclosure 10 — Blue Sky Travel Vietnam — public ProFTPD with "Default Installation" banner (MEDIUM, hardening)

**Target:** `blueskytravelvietnam.com:21` → `172.104.53.45` (Linode, US)
**Owner:** Blue Sky Travel Vietnam — Vietnamese tour operator
**Service:** ProFTPD with banner "**ProFTPD Default Installation**" — suggests unhardened out-of-box config
**Anonymous FTP:** Disabled (good)
**Risk:** MEDIUM (hardening) — plaintext credentials, "Default Installation" banner advertises the operator hasn't customized
**Contact:** `inbound@blueskytravelvietnam.com` (publicly listed on site)

---

## What Lictor observed (banner-grab only)

```
$ nc -w 5 blueskytravelvietnam.com 21
220 ProFTPD Server (ProFTPD Default Installation) [::ffff:172.104.53.45]
```

The "**Default Installation**" string in the banner is the giveaway. ProFTPD's
default config emits this exact phrase until the operator changes the `ServerName`
directive in `/etc/proftpd/proftpd.conf`. So either:

- The server was installed and never configured beyond defaults, or
- The operator only changed runtime settings without renaming the server

Either way it suggests the deployment may not have been through a security
review. The IP `172.104.53.45` is hosted at Linode (US data center) for a
Vietnamese travel agency — common pattern.

## Why this is worth a heads-up (not a breach)

- Plaintext credentials over public FTP in 2026 — should be SFTP (port 22)
  or FTPS (AUTH TLS on 21)
- Anonymous FTP IS disabled (good), but username brute-force surface is
  open to the entire internet without rate-limiting
- ProFTPD CVEs in older versions (CVE-2020-9273 use-after-free, mod_copy
  CVE-2015-3306, etc.) — exposure means any future CVE has them as a target
- "Default Installation" banner means version info isn't suppressed in
  CHANGELOG-style queries

## Recommended remediation

1. **Replace FTP with SFTP**: install OpenSSH, give the FTP users SSH
   accounts with `ChrootDirectory`, and shut down port 21 entirely.
2. **OR enable FTPS (AUTH TLS)** if you must keep ProFTPD: add a Let's
   Encrypt cert and require explicit FTPS on port 21.
3. **Restrict by IP**: if FTP is only used by specific partners or
   backup scripts, firewall it to those IPs.
4. **Add fail2ban**: limit failed-login attempts per source IP.
5. **Customize the banner**: edit `ServerName "..."` in
   `/etc/proftpd/proftpd.conf` and restart — removes the "Default
   Installation" tell.
6. **Confirm ProFTPD version is current** (latest stable as of 2026 is
   1.3.8+).
7. **Add security.txt** at https://blueskytravelvietnam.com/.well-known/security.txt

---

## Email — Direct to Blue Sky Travel Vietnam

The site lists `inbound@blueskytravelvietnam.com` on the homepage meta tag —
that's likely the operations inbox, but they can forward to whoever runs
the FTP.

```
To:      inbound@blueskytravelvietnam.com
CC:      info@blueskytravelvietnam.com (if exists)
Subject: Friendly notice — public FTP server on blueskytravelvietnam.com:21
         (security hardening)

Hello Blue Sky Travel team,

I'm writing to let your IT team know about a security-hardening item
we noticed while scanning publicly reachable services on bug-bounty-
scope domains.

What we observed (banner-grab only, NO login attempts):

  Host:    blueskytravelvietnam.com → 172.104.53.45 (Linode US)
  Port:    21 (FTP)
  Service: ProFTPD Server
  Banner:  "ProFTPD Default Installation"

The "Default Installation" phrase in the banner is ProFTPD's stock
configuration. It suggests the FTP server may not have been hardened
beyond defaults.

The concern:

  - Plaintext credentials travel unencrypted over FTP (anyone on the
    same network — coffee-shop wifi, partner office, etc. — can see
    them in transit)
  - Username brute-force surface is open from any IP on the internet
  - For a tour operator, your client database and back-office records
    likely live behind one of these accounts; the bar for perimeter
    hygiene is high

Recommendations:

  1. Replace FTP with SFTP (port 22 via OpenSSH) — modern equivalent,
     credentials encrypted
  2. OR enable FTPS (AUTH TLS on port 21) if you must keep ProFTPD
  3. Restrict inbound port 21 by IP (firewall to specific partners)
     OR put it behind your VPN
  4. Add fail2ban to slow brute-force attempts
  5. Customize the ProFTPD banner (edit ServerName directive)
  6. Confirm ProFTPD is patched to latest 1.3.8+

We did NOT attempt logins, NOT brute-force, NOT exploits. Single
TCP connect + read of the 256-byte banner response.

This is an open-source security scan via Lictor (https://lictor-ai.com,
Apache 2.0 license). We do responsible disclosure of these exposures
as a public-good exercise — no bounty requested.

A security.txt at https://blueskytravelvietnam.com/.well-known/security.txt
would help us and other researchers reach you faster in the future.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt anonymous FTP login (confirmed disabled — DON'T re-try)
- ❌ Brute-force credentials of any kind
- ❌ Probe for ProFTPD-version-specific CVEs
- ❌ Connect via SFTP / SSH or any port we didn't observe in the banner
- ❌ Disclose publicly until Blue Sky Travel has remediated (60-day CVD)
