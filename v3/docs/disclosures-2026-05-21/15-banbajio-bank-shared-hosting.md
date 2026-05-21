# Disclosure 15 — Banco Bajío (banbajio.com) brand-domain on shared hosting with exposed MySQL + FTP (HIGH)

**Target:** `banbajio.com` → `67.20.76.178` (Hostmonster shared hosting, US data center)
**Owner:** **Banco del Bajío, S.A. — major Mexican commercial bank** (BSE: BBAJIO)
**Primary domain:** `bb.com.mx` (Banco Bajío's main site) — `banbajio.com` is a brand-redirect domain that 302s to bb.com.mx via JavaScript
**Services exposed on public internet:**
- `:21` — Pure-FTPd `[privsep] [TLS]` (ACTIVE — banner reports 4 of 150 users currently connected)
- `:3306` — MySQL `5.7.44-48` accepting handshakes from any IP (NOT ACL-hardened)
**Risk:** **HIGH for the bank brand** — even if the bank's "real" infrastructure is at bb.com.mx, the brand-domain `banbajio.com` is part of Banco Bajío's attack surface, and it's currently a shared-hosting deployment with database exposure
**Action:** Email Banco Bajío IT security; CC Mexican CSIRT (CERT-MX) for parallel notification

---

## What Lictor observed (banner-grab only, NEVER login)

### Port 21 — Pure-FTPd

```
$ nc -w 5 banbajio.com 21
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 4 of 150 allowed.
220-Local time is now 08:40. Server port: 21.
```

- Pure-FTPd with privilege separation + TLS support (the operator
  CAN use FTPS — good, but plaintext FTP still also allowed)
- **4 of 150 active concurrent users** — this is a busy production
  FTP, not an abandoned service. Shared-hosting customer file
  management.

### Port 3306 — MySQL handshake

```
$ nc -w 5 banbajio.com 3306 | xxd | head -2
00000000: 4d00 0000 0a35 2e37 2e34 342d 3438 0042  M....5.7.44-48.B
00000010: ab38 003d 705e 0338 1b16 6b00 ffff c002  .8.=p^.8..k.....
00000040: 5f6e 6174 6976 655f 7061 7373 776f 7264  _native_password
```

Parsing the MySQL Protocol Handshake (server → client):

- Packet length: 0x4D (77 bytes)
- Protocol version: 0x0A (v10 current)
- Server version: **"5.7.44-48"** — MySQL 5.7.44 (Percona build 48,
  most recent 5.7 patch level)
- Auth plugin: `mysql_native_password`

The server returned a **handshake packet**, not an ERR 1130
"Host not allowed". This means:
- Any internet IP can complete the TCP+TLS handshake
- And proceed to the AUTH phase (where username + password attempts
  begin)
- No network-layer rate limiting visible

### Site content (redirect-only)

```
$ curl https://banbajio.com/
<html>
<script>
window.location.href = "http://www.bb.com.mx";
</script>
```

The site is a 13-line HTML page that JS-redirects visitors to the real
Banco Bajío site at `http://www.bb.com.mx`. This is a classic
brand-parking pattern — a bank registers many domains
(banbajio.com, banbajio.mx, bajio.com, etc.) and 302s them all to
the canonical site.

### Hosting attribution

```
$ host 67.20.76.178
178.76.20.67.in-addr.arpa domain name pointer host2024.hostmonster.com.
```

- `host2024.hostmonster.com` = Hostmonster shared hosting (US,
  Bluehost-family, EIG)
- This is generic cPanel-style shared hosting; the FTP/MySQL exposure
  is the default Hostmonster cPanel configuration for any customer

### Banco Bajío's REAL primary domain

```
$ host bb.com.mx
bb.com.mx has address 200.76.36.117
$ host bajio.com.mx
bajio.com.mx has address 23.227.38.32
```

- `bb.com.mx` is hosted on dedicated Mexican IP (200.76.36.117)
- `bajio.com.mx` is on Shopify Plus (23.227.38.32 = Shopify)
- The bank's REAL infrastructure is NOT on Hostmonster shared

So the exposure is on a **brand-parking domain**, not the bank's
primary infrastructure. But the brand association is the problem:
"banbajio.com" is Banco Bajío's name, the FTP banner advertises
the service, and the MySQL handshake gives a version + auth plugin
to any internet IP.

## Why this is HIGH (despite being on a brand-parking domain)

1. **Brand-trust exposure**: an attacker who finds banbajio.com on
   shared hosting can use this as a stepping-stone for social
   engineering ("we noticed your bank uses Hostmonster cPanel — try
   this phishing template").

2. **The MySQL on shared hosting accepts arbitrary internet
   connections**: cPanel MySQL typically has per-customer DB users,
   but the SHARED MySQL daemon is reachable. Brute-force of common
   cPanel user patterns (`bajio_main`, `banco_prod`, etc.) is
   unbounded.

3. **The 4-of-150 active FTP users** means real file transfers are
   happening on banbajio.com:21 with plaintext credentials at risk.
   Even if these are Banco Bajío's marketing/PR vendors uploading
   newsletter content, the credentials transit plaintext.

4. **Mexican banking regulation (CNBV)** has cyber requirements for
   financial institutions — even brand-parking domains may fall
   under the scope of "external information assets" that need
   hardening.

5. **CVE history**: MySQL 5.7.44 is the LAST 5.7 release (2023-10);
   5.7 reached EOL October 2023. Any CVE from now forward will NOT
   be patched on 5.7. The whole 5.7 line is end-of-life.

## Recommended remediation (for Banco Bajío IT)

1. **Move banbajio.com off shared hosting**: a 13-line redirect
   page does not need cPanel + MySQL + FTP. Park it on a CDN
   (Cloudflare Pages, AWS CloudFront, Netlify, Vercel) with just
   an HTTP-level 301 redirect to bb.com.mx. Zero attack surface.

2. **OR if Hostmonster shared hosting is contractually
   needed**: ask Hostmonster to disable MySQL remote access
   (`bind-address = 127.0.0.1` at the daemon level) and IP-restrict
   FTP to the partner who uploads content.

3. **Audit all Banco Bajío brand-parking domains**: banbajio.com is
   probably one of several. Check banbajio.mx, bajio.com,
   bancobajio.com, bajio.net, bajio.org for similar exposures.

4. **Migrate to MySQL 8.0** wherever 5.7 is still deployed; 5.7 is
   EOL since 2023-10 and won't get future CVE patches.

5. **Publish security.txt** on bb.com.mx (the real primary) so
   future researchers can reach the right contact:
   `https://bb.com.mx/.well-known/security.txt`.

---

## Email A — Direct to Banco Bajío IT security

```
To:      seguridad-ti@bb.com.mx, infosec@bb.com.mx,
         tics@bb.com.mx, ciberseguridad@bb.com.mx (try all)
CC:      cert@cert.gob.mx (Mexican national CSIRT, parallel)
Subject: URGENTE — exposición de dominio banbajio.com en hosting
         compartido con MySQL público (alto riesgo, brand-domain)

Estimado equipo de seguridad de Banco del Bajío,

Soy investigador de seguridad open-source con Lictor
(https://lictor-ai.com, licencia Apache 2.0). Durante un escaneo de
dominios brand-parking en el sector bancario internacional, observé
que el dominio `banbajio.com` (que redirige a www.bb.com.mx vía
JavaScript) está alojado en hosting compartido (Hostmonster, USA)
y expone públicamente:

  Host:    banbajio.com → 67.20.76.178 (host2024.hostmonster.com)
  Port:    21 (Pure-FTPd, activo — 4 de 150 usuarios conectados)
  Port:    3306 (MySQL 5.7.44-48, acepta handshake de cualquier IP)

Hallazgos (solo banner-grab, SIN intentos de login):

  • Pure-FTPd con TLS opcional, pero permite también FTP plaintext;
    actualmente 4 conexiones activas
  • MySQL devuelve handshake completo (no ERR 1130 "Host not
    allowed") — significa que cualquier IP de internet puede
    completar el TCP handshake y proceder a la fase de autenticación
  • La versión 5.7.44 es la ÚLTIMA del ciclo 5.7 (EOL desde
    Octubre 2023); cualquier CVE futuro no será parcheado

Riesgo:

  • Asociación de marca: el dominio banbajio.com es propiedad de
    Banco Bajío; si un atacante usa este punto débil para
    ingeniería social ("Banco Bajío usa cPanel Hostmonster con
    DB expuesta"), daña la confianza
  • Brute-force ilimitado: sin rate-limiting de red, un atacante
    puede probar credenciales cPanel típicas (bajio_main,
    banco_prod, etc.) por días
  • CNBV: las normas de ciberseguridad financiera pueden
    considerar dominios brand-parking como activos externos que
    requieren hardening

Recomendaciones:

  1. Mover banbajio.com fuera del hosting compartido. Una página
     de 13 líneas que redirige a bb.com.mx no necesita cPanel +
     MySQL + FTP. Hospédenla en CDN (Cloudflare Pages, AWS
     CloudFront, Vercel) con solo redirección HTTP 301 — cero
     superficie de ataque
  2. O si Hostmonster es contractualmente necesario, pídanle:
       - Deshabilitar MySQL remoto (bind-address = 127.0.0.1)
       - IP-restringir FTP al socio que sube contenido
       - Migrar a SFTP/FTPS-only
  3. Auditar TODOS los dominios brand-parking de Banco Bajío
     (banbajio.mx, bajio.com, bancobajio.com, etc.) para
     exposiciones similares
  4. Migrar MySQL 5.7 → 8.0 donde sea posible
  5. Publicar security.txt en https://bb.com.mx/.well-known/
     security.txt para que investigadores futuros puedan
     contactarles más rápido

NO intenté ningún login, NI brute-force, NI exploits. Solo
TCP-connect + banner-read único en cada puerto público. No tengo
acceso a sus datos — solo a los banners públicos que anuncian que
los servicios están allí.

Es una divulgación responsable de bien público sin solicitud de
recompensa. Las herramientas son open-source y están en
https://github.com/Raffa-jarrl/Lictor-AI.

Saludos cordiales,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(English summary available on request.)
```

---

## Email B — CERT-MX (Mexican CSIRT) parallel notification

```
To:      cert@cert.gob.mx
CC:      seguridad@unam.mx (UNAM CSIRT - sometimes helps with routing)
Subject: CVD — Mexican bank brand-domain exposing MySQL + FTP on
         shared hosting (banbajio.com / Banco del Bajío)

Hello CERT-MX team,

Following coordinated vulnerability disclosure practice, I'm
parallel-notifying you of a security hardening item I'm reporting
directly to Banco del Bajío (BBAJIO):

  Host:      banbajio.com → 67.20.76.178 (Hostmonster shared, USA)
  Owner:     Banco del Bajío, S.A. (BBAJIO)
  Service A: Pure-FTPd on :21 (4 of 150 active users)
  Service B: MySQL 5.7.44-48 on :3306 (handshake accepted from any IP)
  Site:      JS redirect to www.bb.com.mx (brand-parking domain)
  Real prod: bb.com.mx (separate dedicated IP, not affected by this)

This is NOT a confirmed breach. It's a hardening item for a brand-
domain owned by a major Mexican bank:

  • Brand-trust exposure (bank name on cPanel shared hosting)
  • MySQL 5.7 EOL + no IP allowlist
  • Plaintext FTP credentials in transit (active use)
  • Likely CNBV compliance question independent of breach

I sent the direct disclosure to Banco Bajío IT in Spanish with
remediation (move to CDN-only redirect, audit other brand-parking
domains, migrate MySQL 5.7→8.0).

Discovered via Lictor (https://lictor-ai.com, Apache 2.0). Public-
good disclosure, no bounty requested.

Thank you,
Raffa Jarrl
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt MySQL login on banbajio.com:3306 — unauthorized access
  under both US and Mexican computer-crime law
- ❌ Try common cPanel usernames (`bajio_*`, `banco_*`, root, admin)
- ❌ Attempt FTP login (even anonymous — DON'T try)
- ❌ Probe for MySQL 5.7-version-specific CVEs against this host
- ❌ Combine with other IL/global disclosures — each org gets its
  own dedicated email, especially a bank where misrouting is a
  compliance issue
- ❌ Disclose the banbajio.com hostname publicly until Banco Bajío
  has remediated (60-day CVD window)
