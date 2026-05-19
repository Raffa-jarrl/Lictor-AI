# LangChain Subdomain Takeover — Disclosure Draft

**Status:** READY TO SEND
**Vulnerability:** Subdomain Takeover (Vercel)
**Affected:** `journal.langchain.com`
**Severity:** High
**Discovered:** 2026-05-19
**Lictor scan ID:** patrol-subdomain-takeover-2026-05-19

---

## Send via (in priority order)

1. **Email:** `security@langchain.dev` (primary, official channel per LangChain security policy)
2. **GitHub Private Vulnerability Reporting:** https://github.com/langchain-ai/langchain/security/advisories/new
3. **CC backup:** post a brief "found a security issue, please check email" issue on a recent thread if no reply in 72h

---

## Email body (copy-paste)

**To:** security@langchain.dev
**Subject:** Subdomain takeover — journal.langchain.com (Vercel, unclaimed)

Hi LangChain Security Team 👋

I'm Raffa, building [Lictor](https://lictor-ai.com) — an open-source security scanner for AI-built apps. Our automated subdomain-takeover patrol surfaced a confirmed exploitable takeover on one of your subdomains. Sharing privately per your responsible-disclosure policy.

## Finding

**Subdomain:** `journal.langchain.com`
**Type:** Vercel subdomain takeover (DNS record pointing at unclaimed Vercel project)

## Verification

```
$ dig +short CNAME journal.langchain.com
cname.vercel-dns.com.

$ curl -ki https://journal.langchain.com/
HTTP/2 404
server: Vercel
x-vercel-error: DEPLOYMENT_NOT_FOUND
x-vercel-id: fra1::t6v89-...

The deployment could not be found on Vercel.
DEPLOYMENT_NOT_FOUND
```

The DNS record points at Vercel's shared CNAME, but no Vercel project currently claims this domain. Vercel returns `DEPLOYMENT_NOT_FOUND` rather than a 200 response.

## Impact

Anyone can claim `journal.langchain.com` by:

1. Creating a free Vercel account
2. Adding `journal.langchain.com` as a custom domain to their Vercel project
3. Vercel automatically issues a valid SSL certificate (Let's Encrypt) for the domain
4. They can then serve arbitrary content from `https://journal.langchain.com/`

Attack scenarios:
- **Phishing**: a credential-stealing form on a legitimate-looking LangChain subdomain
- **Cookie scope abuse**: if `langchain.com` sets cookies on `.langchain.com` (Domain attribute), the attacker can read/set them from the takeover subdomain
- **Malicious package delivery**: install scripts that fetch from a "trusted" LangChain domain
- **SEO poisoning / reputation damage** via content hosted on the real langchain.com namespace
- **OAuth redirect_uri abuse** if any LangChain application has `*.langchain.com` in its allowed redirect list

## Suggested fix

One of:

1. **Remove the DNS record** if the subdomain is no longer needed (recommended if `journal` is a deprecated project)
2. **Re-claim it on Vercel** by adding `journal.langchain.com` to the appropriate Vercel project
3. **Point it elsewhere** (e.g., to a holding page on your primary infrastructure)

To prevent recurrence, consider integrating a takeover monitor (e.g., your own check, or `subjack`/`subdomain-takeover` tools) into CI for any subdomain CNAME changes.

## References

- Vercel takeover writeup: https://hackerone.com/reports/950097 (similar pattern)
- can-i-take-over-xyz Vercel entry: https://github.com/EdOverflow/can-i-take-over-xyz#vercel
- DEPLOYMENT_NOT_FOUND error: Vercel's standard "no project owns this domain" response

## About Lictor

Lictor is open-source (Apache 2.0): https://lictor-ai.com · https://github.com/Raffa-jarrl/Lictor-AI

We run automated scans across public bug-bounty programs and disclose privately. No request from this — happy to help debug or test the fix if useful. If LangChain has a bounty program I'm not aware of, let me know; otherwise consider this a community contribution.

— Raffa
raffa@lictor-ai.com
Lictor AI
