# Cash App Bugcrowd Submission #2 — `internal-platform-staging.cashstaging.app`

**Submit at:** https://bugcrowd.com/engagements/cashapp/submissions/new
**Max payout:** $18,000 · **Realistic for takeover:** $500-$2,500
**In-scope asset:** `*.cashstaging.app`

---

## Title
```
Subdomain takeover — internal-platform-staging.cashstaging.app (Fastly, unknown domain)
```

## VRT category
`Server Security Misconfiguration > Subdomain Takeover`

## Severity
**P2 — High** (the word "internal" in the hostname is particularly concerning — suggests this CNAME was previously serving internal Cash App tooling)

## Description (paste into Bugcrowd form)

```
## Summary

`internal-platform-staging.cashstaging.app` has a CNAME record pointing
to Fastly (`d.sni.global.fastly.net`), but no Fastly service currently
claims this host. Fastly returns "Fastly error: unknown domain" — the
textbook indicator of an exploitable Fastly takeover.

The "internal" prefix is particularly concerning — this hostname appears
to have previously served an internal Cash App staging service. The
takeover is therefore especially dangerous for cookie-scoping abuse,
employee-targeted phishing, and OAuth redirect_uri abuse if any internal
Cash App app trusted this host.

## Steps to reproduce

1. Verify DNS:
   $ dig +short CNAME internal-platform-staging.cashstaging.app
   d.sni.global.fastly.net.

2. Verify takeover signature:
   $ curl -ki https://internal-platform-staging.cashstaging.app/
   HTTP/2 500
   server: Varnish
   x-served-by: cache-lin1730022-LIN

   <html>
   <head>
     <title>Fastly error: unknown domain internal-platform-staging.cashstaging.app</title>
   </head>
   <body>
     <p>Fastly error: unknown domain: internal-platform-staging.cashstaging.app

3. Exploitation: Same as Fastly takeover pattern — register a free Fastly
   account, configure a service that claims this host, serve attacker-
   controlled content.

## Impact

Higher than a typical takeover because of the "internal" prefix:

- **Employee-targeted phishing**: Cash App engineers may have
  bookmarks/internal docs/Slack messages pointing to this URL
  expecting it to be a legitimate internal staging tool.
- **OAuth redirect_uri abuse**: internal Cash App tooling commonly
  whitelists `*.cashstaging.app` as a development convenience.
- **Internal API trust**: code that calls
  `https://internal-platform-staging.cashstaging.app/api/...` will hit
  attacker-controlled infrastructure.
- **Cookie scoping**: cookies on `Domain=.cashstaging.app` are
  exfiltrable from this takeover.

## Remediation

Same as submission #1:
1. Remove the DNS CNAME record entirely.
2. Re-claim it on Fastly by adding the host to a current service.
3. Point it elsewhere.

## Note on relationship to submission #1

This was discovered alongside `platform-test.cashstaging.app` (separate
submission). Both share the same Fastly orphan pattern — suggests a
broader DNS hygiene issue worth a wider audit across `*.cashstaging.app`.
I'd recommend checking all CNAMEs in the zone for unclaimed Fastly hosts.

## Tooling

Discovered via [Lictor](https://lictor-ai.com) automated subdomain
takeover patrol (open-source, Apache 2.0).

## References

- can-i-take-over-xyz Fastly: https://github.com/EdOverflow/can-i-take-over-xyz#fastly
```
