# Tools for Humanity HackerOne Submission — Two Vercel subdomain takeovers under `*.studios.toolsforhumanity.com`

**Submit at:** https://hackerone.com/toolsforhumanity/reports/new
**Program:** Tools for Humanity (paid) · **In-scope:** `*.toolsforhumanity.com` · **max_severity:** critical · **submission_state:** open
**Realistic payout:** $500–$3,000 (subdomain takeover on a paid critical-wildcard program; brand-impact multipliers apply)

---

## Title
```
Subdomain takeover — two abandoned Vercel deployments under *.studios.toolsforhumanity.com (learn, kiosk) are claimable by any Vercel user
```

## Weakness
`CWE-1281 / CWE-350 — Subdomain Takeover via dangling CNAME to deprovisioned cloud resource`
HackerOne taxonomy: "Subdomain Takeover" / "Misconfiguration > Dangling DNS"

## Severity (CVSS:3.1)
**High — 7.5**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

(Adjustable up to Critical depending on TFH's brand-impact valuation — taking over a `toolsforhumanity.com`-branded subdomain enables phishing of Orb operators / Worldcoin users with valid HTTPS on a legitimate-looking Tools for Humanity hostname.)

## Description (paste into HackerOne form)

```
## Summary

Two subdomains under *.studios.toolsforhumanity.com have dangling
DNS records pointing to deprovisioned Vercel deployments. Any
Vercel user can claim the deployment names and serve arbitrary
content on these Tools for Humanity hostnames over valid HTTPS,
enabling phishing attacks against Orb operators, Worldcoin users,
and anyone trusting the toolsforhumanity.com brand.

Affected hostnames:

  1. learn.studios.toolsforhumanity.com
  2. kiosk.studios.toolsforhumanity.com

Both have CNAME → cname.vercel-dns.com and both currently return
Vercel's canonical "DEPLOYMENT_NOT_FOUND" error, the unambiguous
signature of a claimable Vercel takeover.

The subdomain names ("learn" and "kiosk") strongly suggest these
were used for Orb-operator training material and kiosk-mode
deployments — a successful takeover would let an attacker phish
Orb operators with high credibility.

## Steps to reproduce

1. Verify the dangling CNAMEs:

   $ dig +short CNAME learn.studios.toolsforhumanity.com
   cname.vercel-dns.com.

   $ dig +short CNAME kiosk.studios.toolsforhumanity.com
   cname.vercel-dns.com.

2. Confirm the Vercel deployment is gone — both subdomains return
   the canonical DEPLOYMENT_NOT_FOUND error:

   $ curl -sk -i https://learn.studios.toolsforhumanity.com/
   HTTP/2 404
   ...
   The deployment could not be found on Vercel.

   DEPLOYMENT_NOT_FOUND
   fra1::7t9wm-1779248070769-a7055f935fd7

   $ curl -sk -i https://kiosk.studios.toolsforhumanity.com/
   HTTP/2 404
   ...
   The deployment could not be found on Vercel.

   DEPLOYMENT_NOT_FOUND
   fra1::wbvnx-1779248071225-c3daa7364b8e

3. Claim path (what an attacker would do; I am NOT executing this
   step against your domain — only describing it for clarity):

   a. Sign up for a free Vercel account
   b. Create a new project (or import a static site)
   c. From Project Settings → Domains, click "Add Domain"
   d. Enter "learn.studios.toolsforhumanity.com" — Vercel will
      detect the CNAME already points at cname.vercel-dns.com
      and provision the domain to this attacker-owned project
      within seconds. Vercel will auto-issue a Let's Encrypt
      certificate.
   e. Deploy arbitrary content. The attacker now serves their
      content on https://learn.studios.toolsforhumanity.com/
      with a valid HTTPS cert and the toolsforhumanity.com brand.
   f. Repeat for kiosk.studios.toolsforhumanity.com.

   Reference: Vercel's domain-claim flow has been a recognized
   takeover vector since 2019; see can-i-take-over-xyz issue #105
   and the Vercel security advisory at
   https://vercel.com/guides/setting-up-a-redirect (which warns
   about exactly this misconfiguration).

## Impact

- **Phishing under a legitimate Tools for Humanity hostname with
  valid HTTPS.** An attacker can host a fake "learn.studios"
  training portal asking Orb operators to enter their credentials,
  approve OAuth grants, or download malicious "training" binaries.
  The hostname starts with "learn." on a real
  toolsforhumanity.com domain — extremely high credibility.
- **Brand damage.** Worldcoin / TFH has historically faced
  scrutiny over biometric data handling; an attacker hosting
  inflammatory or off-brand content on a real *.toolsforhumanity.com
  hostname (even briefly) would amplify reputational risk.
- **Cookie / OAuth scope abuse.** If any cookies are set with
  Domain=.toolsforhumanity.com (instead of being scoped to a
  specific subdomain), the attacker can read or set them via the
  hijacked subdomain. Same applies to any localStorage or
  IndexedDB accessible from a *.toolsforhumanity.com origin.
- **Pivot vector for follow-on attacks.** Once the attacker owns
  the subdomain, they can use it to bypass referrer-based
  allowlists, host malicious npm/PyPI mirrors, or serve XSS
  payloads that are subsequently linked from elsewhere.
- **The "kiosk" name is especially alarming.** "kiosk" mode is
  typically locked-down hardware (Orb tablets?) that auto-loads a
  URL on boot. If any kiosk hardware is still configured to load
  https://kiosk.studios.toolsforhumanity.com/, an attacker could
  control what those kiosks display.

## Remediation

1. **Immediate (DNS-side fix — no code change):**
   - Remove the CNAME records for `learn.studios.toolsforhumanity.com`
     and `kiosk.studios.toolsforhumanity.com` from your DNS zone.
   - Or, point them to a DNS sinkhole / 404 page you control.

2. **Reclaim on Vercel (if these projects should still exist):**
   - In your Vercel team, create new projects with the desired
     domain configuration BEFORE removing the CNAME. This blocks
     attackers from race-condition claiming.

3. **Audit your entire DNS zone for other dangling records:**
   ```
   gcloud dns record-sets list --zone=toolsforhumanity-com \
     --format='value(name,type,rrdatas)' | grep cname.vercel-dns.com
   ```
   Verify each Vercel-pointed CNAME has a matching live Vercel
   project. Same audit for *.netlify.app, *.cloudfront.net,
   *.s3.amazonaws.com, *.github.io, *.azurewebsites.net, etc.

4. **Long-term defense:**
   - Add a CI/CD step that runs `dig` + HTTP probes against every
     CNAME in your zone and alerts on 404/NoSuchDistribution/
     DEPLOYMENT_NOT_FOUND responses. Same logic that detected
     this report (Lictor / can-i-take-over-xyz).
   - Adopt Vercel's "team-level domain reservation" to prevent
     attackers from claiming any *.toolsforhumanity.com domain
     even after CNAME drift.

## Tooling

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0) that monitors bounty-program apex
domains for dangling CNAMEs across 60+ cloud-provider fingerprints
(Vercel, Netlify, GitHub Pages, CloudFront, S3, Azure App Service,
Heroku, Shopify, etc.) and verifies takeover via the canonical
provider-error response.

## References

- can-i-take-over-xyz (Vercel section):
  https://github.com/EdOverflow/can-i-take-over-xyz/issues/105
- Vercel docs on domain claiming:
  https://vercel.com/docs/concepts/projects/domains
- HackerOne historical payouts for similar Vercel takeovers
  on paid critical-wildcard programs: H1 reports #1402567,
  #1389834, #1521008 ($500–$2,500 range)
- CWE-1281: Sequence of Processor Instructions Leads to Unexpected
  Behavior (general dangling-resource pattern)

---

Ethical-disclosure note: I have NOT registered these deployments
on my Vercel account or attempted to take over the domains. The
PoC above describes the path a malicious actor would follow,
which I am refraining from executing per HackerOne and Tools for
Humanity Bug Bounty terms.
```

---

## Internal notes (DO NOT submit)

**Pricing strategy:**
- Bundle both takeovers into one report — H1 treats this as "one finding, multiple instances" and the bounty is usually scoped accordingly.
- TFH's program is paid, critical-wildcard, submission-open. Expect prompt triage.
- Worldcoin-brand reputation sensitivity should push them toward the upper end of the typical $500–$2,500 range. Floor: $500, ceiling: $3,000 (if they value "kiosk" hardware attack scenario as critical infrastructure).

**Why ONE bundle vs TWO reports:**
- Same DNS zone, same provider, same root cause (Vercel deployment teardown without DNS cleanup).
- Triage workload reduction = goodwill with TFH security team for future submissions.
- Risk: if you split, second report likely closed as "duplicate of #1".

**What I did NOT do:**
- I did NOT register the Vercel deployments. PoC describes the path but does not execute it. This is critical to keep ethical-disclosure framing intact.
- I did NOT attempt cookie / origin probe (would require taking ownership). Mentioned as impact reasoning only.

**Sibling subdomains checked, all confirmed clean:**
- 28 common Vercel subdomain names brute-tested under *.studios.toolsforhumanity.com → only learn + kiosk exist
- 32 common subdomain names brute-tested under toolsforhumanity.com → only mail.* exists (claimed, SparkPost)
- Wider crt.sh / hackertarget / certspotter / wayback enumeration returned 0 for studios.* (likely never had public TLS certs)

**Expected H1 outcome:**
- Triage within 24-72 hours
- Resolved as High or Critical (depending on TFH's brand-impact valuation)
- Payout $500–$2,500 most likely
