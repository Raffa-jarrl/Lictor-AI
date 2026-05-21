# Disclosure 19 — Chiesi Farmaceutici (chiesi.com) — public Pure-FTPd on pharma corporate apex (HIGH)

**Target:** `chiesi.com` → `217.174.152.70` (managed VPS at `cloud-e469b5.managed-vps.net`, EU)
**Owner:** **Chiesi Farmaceutici S.p.A.** — major Italian pharmaceutical company
- Founded 1935, family-owned (Chiesi family, 4 generations)
- 6,500+ employees globally
- ~€2.5B revenue (2023)
- Headquartered Parma, Italy
- Major specialty: respiratory medicines (Trimbow / Foster / Atimos)
- Operates in 30+ countries; B Corp certified
**Service:** `:21` — Pure-FTPd `[privsep] [TLS]` (1 of 50 users connected at scan time)
**Risk:** **HIGH given pharma context** — plaintext FTP on perimeter of a pharma company subject to EMA/AIFA regulations and GDPR
**Action:** Email Chiesi IT/security + CERT-IT (Italian national CSIRT) parallel

---

## What Lictor observed (banner-grab only, NO login)

```
$ nc -w 5 chiesi.com 21
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 1 of 50 allowed.
220-Local time is now 16:48. Server port: 21.
```

```
$ curl -sI https://chiesi.com/
HTTP/2 301
strict-transport-security: max-age=31536000; includeSubDomains
x-frame-options: SAMEORIGIN
referrer-policy: same-origin
x-content-type-options: nosniff
```

Apex is professionally managed (HSTS, X-Frame-Options, X-Content-Type-
Options, Referrer-Policy — enterprise security headers) and 301s to
their canonical site. Mail handled by Mimecast (enterprise email
security). Hosting on `managed-vps.net` (German managed-VPS provider).

So the apex shows the operator DOES practice security hygiene at the
HTTP layer — but Pure-FTPd is exposed on port 21 alongside it.

## Why HIGH (despite Pure-FTPd having TLS support)

The `[TLS]` flag means Pure-FTPd CAN serve FTPS (encrypted FTP with
AUTH TLS). But the configuration also typically allows plaintext FTP
unless the operator has explicitly required AUTH TLS for every
connection. Without seeing the actual config, we have to assume
plaintext is also possible.

Additional concerns:
- **1 of 50 users connected** = active production FTP (not abandoned)
- **Pharma regulatory context** — EMA (European Medicines Agency)
  GxP, AIFA (Italian medicines authority), GDPR for any patient/HCP
  data
- **ProFTPD/Pure-FTPd CVE history** — even with TLS, the daemon code
  has had vulnerabilities; an exposed FTP daemon is an attack
  surface
- **Brute-force surface** — open from any IP on the internet
- **Banner discloses version family + privilege model** (`privsep`)
  to anyone connecting

## Recommended remediation

1. **Migrate to SFTP via OpenSSH** (port 22). Same encrypted file
   transfer; well-audited daemon; chroot per user.
2. **OR enforce FTPS-only** on port 21 (require AUTH TLS; deny
   any plaintext-FTP connection).
3. **Restrict by IP / VPN** — if FTP is for specific partners
   (clinical trial CROs, regulatory submission vendors), firewall
   to those IPs.
4. **Add fail2ban** at the daemon or OS level.
5. **Customize banner** — change the ServerName directive in
   `pure-ftpd.conf` to remove "Welcome to Pure-FTPd" disclosure.
6. **Publish security.txt** at
   `https://chiesi.com/.well-known/security.txt` — currently not
   present.

---

## Email — to Chiesi IT/security

```
To:      security@chiesi.com, infosec@chiesi.com,
         it-security@chiesi.com, ciso@chiesi.com (try all)
CC:      cert@certfin.it (CERT-IT/Banca d'Italia financial CERT —
                          for parallel notification path),
         cert@csirt.gov.it (CSIRT Italia — national CSIRT)
Subject: Avviso urgente — server FTP pubblicamente raggiungibile
         su chiesi.com:21 (hardening security, settore farmaceutico)

Gentile team IT/Security di Chiesi Farmaceutici,

Sono un ricercatore di sicurezza open-source con Lictor
(https://lictor-ai.com, licenza Apache 2.0). Durante una scansione
di servizi pubblicamente raggiungibili nel settore farmaceutico
globale, ho osservato che il vostro dominio corporate `chiesi.com`
ha un server FTP raggiungibile dall'internet pubblico:

What we observed (banner-grab only, NO login attempts):

  Host:    chiesi.com → 217.174.152.70 (managed-vps.net, EU)
  Port:    21 (FTP)
  Service: Pure-FTPd [privsep] [TLS]
  Status:  1 di 50 utenti connessi (servizio attivo)

Il dominio principale stesso è ben configurato (HSTS, X-Frame-
Options, X-Content-Type-Options, Mimecast per email) — segno che
il team di sicurezza pratica un'igiene HTTP corretta. Ma la porta
21 FTP è esposta accanto al sito principale.

La preoccupazione (alta nel contesto farmaceutico):

  • Pure-FTPd con TLS opzionale — il flag [TLS] indica che
    AUTH TLS è disponibile, ma di default permette anche FTP
    plaintext. Senza la configurazione esplicita di "Require
    TLS for all connections", le credenziali viaggiano in
    chiaro
  • Brute-force surface aperto da qualsiasi IP internet
  • Contesto regolatorio: EMA GxP, AIFA, GDPR per qualsiasi
    dato HCP/paziente che potrebbe transitare su FTP
  • Storia CVE di Pure-FTPd / ProFTPD — il daemon FTP esposto
    è una superficie di attacco, anche con TLS
  • Banner divulga la famiglia di versione + modello di
    privilegio (privsep) a chiunque si connetta

Raccomandazioni (playbook standard sysadmin):

  1. Migrare a SFTP via OpenSSH (port 22) — stesso trasferimento
     file cifrato; daemon ben auditato; chroot per utente
  2. O imporre FTPS-only su port 21 (richiedere AUTH TLS;
     negare ogni connessione FTP plaintext)
  3. Restringere per IP / VPN — se FTP è per partner specifici
     (CRO clinici, vendor regolatori), firewall a quegli IP
  4. Aggiungere fail2ban a livello daemon o OS
  5. Personalizzare il banner — cambiare ServerName in
     pure-ftpd.conf per rimuovere il messaggio "Welcome to
     Pure-FTPd"
  6. Pubblicare security.txt su https://chiesi.com/.well-known/
     security.txt (attualmente non presente)

NON ho tentato login, NON brute-force, NON exploit. Solo un
singolo TCP connect + lettura di 256 byte di banner. Non ho
nessun accesso ai vostri dati — solo al banner pubblico che
annuncia che il servizio è lì.

Divulgazione responsabile per il bene pubblico via Lictor
(open-source, Apache 2.0). Nessuna ricompensa richiesta.

Cordiali saluti,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI

(English summary available on request.)
```

---

## ⚠️ Do NOT do any of the following

- ❌ Attempt FTP login on chiesi.com:21 — unauthorized access
  under Italian Code of Criminal Procedure / EU NIS2
- ❌ Try anonymous-FTP or common usernames (anonymous, chiesi,
  ftp, admin) — same
- ❌ Probe for Pure-FTPd-version-specific CVEs against this host
- ❌ Combine with other disclosures — Chiesi gets its own
  dedicated email
- ❌ Disclose the chiesi.com hostname publicly until Chiesi has
  remediated (60-day CVD window standard in EU/Italy)
