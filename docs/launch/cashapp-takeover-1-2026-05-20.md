# Cash App Bugcrowd Submission #1 — `platform-test.cashstaging.app`

**Submit at:** https://bugcrowd.com/engagements/cashapp/submissions/new
**Max payout:** $18,000 · **Realistic for takeover:** $500-$2,500
**In-scope asset:** `*.cashstaging.app` (Bugcrowd Cash App program, type=website)

---

## Title
```
Subdomain takeover — platform-test.cashstaging.app (Fastly, unknown domain)
```

## VRT category
`Server Security Misconfiguration > Subdomain Takeover`

## Severity
**P2 — High** (Fastly takeover allows arbitrary content on a Cash App-branded subdomain)

## Description (paste into Bugcrowd form)

```
## Summary

`platform-test.cashstaging.app` has a CNAME record pointing to Fastly
(`d.sni.global.fastly.net`), but no Fastly service currently claims this
host. Fastly returns "Fastly error: unknown domain" — the textbook
indicator of an exploitable Fastly takeover.

An attacker can register a free Fastly account, claim this host on their
own Fastly service, and serve arbitrary content from
`https://platform-test.cashstaging.app/` (Fastly issues a valid SSL cert
automatically once the host is added to a configured service).

## Steps to reproduce

1. Verify DNS:
   $ dig +short CNAME platform-test.cashstaging.app
   d.sni.global.fastly.net.

2. Verify takeover signature:
   $ curl -ki https://platform-test.cashstaging.app/
   HTTP/2 500
   server: Varnish
   x-served-by: cache-lin1730079-LIN
   via: 1.1 varnish

   <html>
   <head>
     <title>Fastly error: unknown domain platform-test.cashstaging.app</title>
   </head>
   <body>
     <p>Fastly error: unknown domain: platform-test.cashstaging.app

3. Exploitation: Register at fastly.com, create a free service,
   add `platform-test.cashstaging.app` as a domain on that service.
   Fastly will provision SSL and serve your content from the host.

## Impact

This subdomain is on the `*.cashstaging.app` namespace which is in scope
for Cash App's Bugcrowd program. An attacker can:

- **Phishing**: serve a Cash App look-alike login page from a legitimate-
  looking subdomain. Users have no visual indication this isn't Cash App.
- **Cookie scoping abuse**: if any cookies set on `Domain=.cashstaging.app`
  exist, the attacker can read/set them from the takeover subdomain.
- **OAuth redirect_uri abuse**: if any Cash App application has
  `*.cashstaging.app` in its allowed redirect list, full account takeover
  via OAuth is possible.
- **Content security policy bypass**: Cash App pages that whitelist
  `*.cashstaging.app` would load attacker JavaScript.

## Remediation

One of:
1. Remove the DNS CNAME record entirely if the host is deprecated.
2. Re-claim it on Fastly by adding the host to a current Fastly service.
3. Point it elsewhere.

## Tooling

Discovered via [Lictor](https://lictor-ai.com) automated subdomain
takeover patrol (open-source, Apache 2.0). Lictor enumerated subdomains
via Wayback Machine + Certificate Transparency logs, then verified each
CNAME against ~66 takeover fingerprints from can-i-take-over-xyz.

## References

- can-i-take-over-xyz Fastly entry: https://github.com/EdOverflow/can-i-take-over-xyz#fastly
- HackerOne report #150953 (similar Fastly takeover pattern)
```

## Quick-attach proof

Take a screenshot of the curl output showing `Fastly error: unknown domain` — Bugcrowd loves visual proof.
