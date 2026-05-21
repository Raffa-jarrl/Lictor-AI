# Disclosure 20 — Qatar First Bank (qfb.com.qa) — brand-domain on cPanel shared hosting with public MySQL + FTP (HIGH given bank context)

**Target:** `qfb.com.qa` → `35.214.78.243` (Google Cloud Platform shared hosting, `bc.googleusercontent.com`)
**Owner:** Likely **Qatar First Bank LLC (QFB)** — Qatari Shari'ah-compliant investment bank
- Listed: Qatar Stock Exchange (QFBQ)
- Licensed by Qatar Financial Centre Regulatory Authority (QFCRA)
- Investment banking + private equity focus
**Services exposed:**
- `:21` — Default cPanel-style FTP ("Please upload your web files to the public_html directory")
- `:3306` — MySQL accepting handshake from any IP (`fp=MySQL` per scanner = real handshake, not ACL-hardened)
**Web:** `403 | Access blocked` (21-byte body — actively blocked at HTTP layer)
**Mail:** Barracuda + Office 365 + Barracuda backup (enterprise mail = real org behind this domain)
**Risk:** **HIGH given bank-brand context** — even though production is likely on a different host, a Qatar-based investment bank's brand-domain exposing MySQL on shared hosting is a brand-trust + regulatory issue
**Action:** Email QFB IT security; CC Q-CERT (Qatar national CSIRT)

---

## What Lictor observed (banner-grab only, NO login)

### Port 21 — Default cPanel-style FTP banner

```
$ nc -w 5 qfb.com.qa 21
220-##########################################################
220-Please upload your web files to the public_html directory.
220-Note that letters are case sensitive.
```

This is the **literal default cPanel-style banner** — same one we observed on `underarmournext.com` (Google Cloud shared hosting) and the same generic message that Hostmonster / WebhostBox / similar providers ship by default. The operator has not customized the banner.

### Port 3306 — MySQL real handshake (NOT ACL-hardened)

The Lictor v4 port-exposure scanner classified this as `fp=MySQL` (full handshake packet returned, NOT ERR 1130 "Host not allowed"). Any internet IP can complete the TCP handshake and proceed to the authentication phase.

### Web layer (positive — locked down)

```
$ curl https://qfb.com.qa/
403 | Access blocked
```

A minimal 21-byte 403 response. Whoever administers this knows enough to lock the HTTP layer down. The MySQL + FTP exposure on the same host is the gap.

### Mail infrastructure (real org indicator)

```
qfb.com.qa MX records:
   0  d312104a.ess.barracudanetworks.com
   20 qfb-com-qa.mail.protection.outlook.com
   10 d312104b.ess.barracudanetworks.com
```

Mail flows through **Barracuda Email Security Service + Office 365** — that's a real-organization enterprise mail setup, not a parked domain. Strongly suggests this IS Qatar First Bank's domain (or a closely-related entity that uses QFB's mail infrastructure).

### Hosting attribution

```
$ host 35.214.78.243
243.78.214.35.in-addr.arpa → 243.78.214.35.bc.googleusercontent.com
```

Google Cloud Platform shared-hosting (cPanel-style provider on GCP). Multi-tenant infrastructure where individual customer accounts have FTP/MySQL by default unless explicitly disabled.

## Why HIGH given bank context

Same reasoning as `banbajio.com` (Banco Bajío brand-parking domain): a publicly-traded Gulf investment bank with a domain pointed at cPanel shared hosting + MySQL reachable from any internet IP is:

1. **Brand-trust exposure**: any researcher (or attacker) finding QFB's name on shared hosting creates a phishing/social-engineering vector ("we noticed QFB uses cPanel; here's a phishing template targeted at QFB customers")
2. **Brute-force surface unbounded**: cPanel MySQL accepts connections from any IP; common cPanel user patterns (`qfb_main`, `qfb_prod`) brute-forceable indefinitely
3. **Qatar Central Bank + QFCRA cyber-supervision rules**: Qatari financial institutions are subject to QFCRA cyber-risk requirements that include perimeter hygiene of all brand-owned domains
4. **Brand-parking pattern**: even if QFB's actual production banking infra is at a different domain (e.g. `qfb.qa`, `qfbqa.com`), `qfb.com.qa` is THEIR brand and THEIR responsibility

## Recommended remediation

1. **Move qfb.com.qa off cPanel shared hosting**: a 21-byte 403 response doesn't need cPanel + MySQL + FTP. Park it on a CDN (Cloudflare Pages, AWS CloudFront, GCP Load Balancer with Cloud Run) with HTTP-level 301 redirect to the canonical site. Zero attack surface.
2. **OR if shared hosting is contractually needed**: ask the provider to disable remote MySQL (`bind-address = 127.0.0.1`) and IP-restrict FTP to specific partner IPs.
3. **Audit ALL QFB brand-parking domains** (`qfb.qa`, `qfbqa.com`, `qatar-first-bank.com`, etc.) for similar exposures.
4. **Customize the FTP banner** — remove the "Please upload to public_html" default.
5. **Publish security.txt** at `https://qfb.com.qa/.well-known/security.txt`.

---

## Email — to Qatar First Bank IT/Security

```
To:      security@qfb.com.qa, infosec@qfb.com.qa,
         it-security@qfb.com.qa, ciso@qfb.com.qa (try all)
CC:      qcert@motc.gov.qa (Q-CERT, Qatari national CSIRT),
         info@qcert.org (Q-CERT alternate)
Subject: URGENT — qfb.com.qa exposing default-cPanel MySQL + FTP on
         shared hosting (HIGH security risk, bank brand)

Dear Qatar First Bank IT/Security team,

I'm an open-source security researcher with Lictor (Apache 2.0,
https://lictor-ai.com). During a scan of publicly-reachable services
on Middle East financial-sector domains, I observed that your
brand-domain `qfb.com.qa` is hosted on Google Cloud shared hosting
and exposes:

  Host:   qfb.com.qa → 35.214.78.243 (GCP shared, bc.googleusercontent.com)
  Port:   21 (FTP, default-cPanel banner — "Please upload your web
                files to the public_html directory")
  Port:   3306 (MySQL, real handshake from any IP — NOT ACL-hardened)
  Web:    403 "Access blocked" (21 bytes — HTTP layer locked down)
  Mail:   Barracuda + Office 365 (consistent with real QFB organization)

The mail-infrastructure setup (enterprise Barracuda + O365) strongly
suggests this is Qatar First Bank's domain, even if production
banking infrastructure is elsewhere.

The concern (high given bank brand context):

  • Default cPanel FTP banner = operator hasn't hardened
  • MySQL accepts handshake from any IP = brute-force surface
    unbounded; common cPanel user patterns (qfb_main, qfb_prod, etc.)
    can be brute-forced indefinitely from distributed source IPs
  • Brand-trust exposure: a Qatari investment bank's name on
    shared hosting creates a phishing/social-engineering vector
  • QFCRA cyber-supervision: Qatari financial institutions are
    subject to perimeter-hygiene requirements for all brand-owned
    domains

Immediate recommendations:

  1. Move qfb.com.qa off cPanel shared hosting. A 21-byte 403
     response doesn't need cPanel + MySQL + FTP. Park it on a
     CDN (Cloudflare Pages, AWS CloudFront, GCP Load Balancer)
     with HTTP-level 301 redirect to your canonical site. Zero
     attack surface.

  2. OR (if shared hosting is contractually required): ask the
     hosting provider to:
       - Disable remote MySQL (bind-address = 127.0.0.1)
       - IP-restrict FTP to specific partner IPs only
       - Customize the FTP banner

  3. Audit ALL QFB brand-parking domains (qfb.qa, qfbqa.com,
     qatar-first-bank.com, etc.) for similar exposures.

  4. Publish security.txt at https://qfb.com.qa/.well-known/
     security.txt so future researchers can reach you in minutes.

I did NOT attempt MySQL login, NOT FTP login, NOT brute-force,
NOT exploits. Single TCP connect + 256-byte banner read on each
of the open ports. I have NO access to your data — only the
public banner that announces the services are there.

This is public-good responsible disclosure via Lictor (open-source,
Apache 2.0). No bounty is requested.

Best regards,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt MySQL login on qfb.com.qa:3306 — unauthorized access
  under Qatari Penal Code (Law No. 11 of 2004) + Cybercrime
  Prevention Law (Law No. 14 of 2014)
- ❌ Try common cPanel usernames (qfb_*, admin, root)
- ❌ Attempt FTP login (anonymous or named)
- ❌ Probe for MySQL CVEs against this host
- ❌ Combine with other org disclosures — QFB gets its own dedicated
  email; bank disclosures must route correctly
- ❌ Disclose the qfb.com.qa hostname publicly until QFB has had
  60+ days to remediate
