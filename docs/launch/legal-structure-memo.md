> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Lictor Legal Structure — Strategic Memo

**Audience:** Dor (founder), and the lawyers Dor hires.
**Status:** Pre-launch. Decisions need to be locked by Jun 2026 (LLC) and Apr 2027 (Foundation), per `year-plan-2026-2027.md`.
**Not legal advice.** This memo is the *thesis*. Every dated commitment in §8 needs a lawyer to actually execute.

---

## 1. The two-entity thesis

Lictor needs two legal entities, not one. They do different jobs and protect against different failure modes.

**Lictor LLC (commercial).** This is where money moves. It signs customer contracts, collects subscription revenue from Teams, the Course, AaaS, and Enterprise, employs Dor and any future hires, holds the IP for closed-source commercial features (Lictor Studio Pro, Enterprise modules), and processes payments through Paddle/Stripe. The LLC owns the "Lictor" and "Lictor AI" trademarks — for now.

**Lictor Foundation (steward).** This entity exists for one reason: structural protection of the OSS core. It owns the canonical Apache 2.0 repo and the trademark (transferred from the LLC in Apr 2027), receives donations and grants, and answers to a board of directors rather than a single founder. The Foundation cannot be acquired — that's the point.

**How they relate.** The LLC operates under a perpetual royalty-free trademark license from the Foundation, and contributes upstream to the OSS repo like any other contributor (under a CLA — see §3). Commercial features stay in LLC-owned private repos under a separate license (BUSL or proprietary EULA). The pattern is identical to HashiCorp pre-2023 (HashiCorp Inc. + Apache 2.0 Vault), GitLab (GitLab Inc. + Community Edition), and Elastic pre-2021.

**Why both, and not one.** If Lictor only has the LLC, every acquirer scenario becomes a re-licensing fight — the buyer can quietly flip Apache 2.0 to SSPL or BUSL, the community revolts, the asset value evaporates (see Elastic 2021, Redis 2024, HashiCorp 2023). If Lictor only has a Foundation, there's no commercial entity to sell paid features, no clean way to take revenue, and no acquirer can buy it. The two-entity structure monetizes *and* protects.

**The cost of getting this wrong is roughly $500k-$2M of acquisition value.** Acquirers discount messy IP and re-licensing risk heavily.

---

## 2. The jurisdiction question

Dor is in Israel. The realistic options for the commercial entity:

| Jurisdiction | Setup cost | Annual cost | Acquirer-friendly? | Banking | Verdict |
|---|---|---|---|---|---|
| **Delaware LLC** | $500 + lawyer | ~$300 franchise tax + agent | Excellent (US default) | Stripe/Paddle direct | **Recommended primary** |
| **Delaware C-Corp** | Same | ~$400 + reporting | Excellent (VC default) | Same | Convert later if VC route opens |
| **Israeli Ltd. (Ba'm)** | ~$2k | ~$3k accounting | Friction (foreign entity) | Local fine, Stripe OK | Recommended as Israeli **subsidiary** for Dor's employment |
| **UK Ltd.** | ~£500 | ~£2k | Decent | OK | No reason to pick this |
| **Estonian e-Residency OÜ** | ~€500 | ~€2k | Weak (US buyers find it odd) | Wise/Revolut | Founder-aesthetic; not strategic |
| **Singapore Pte Ltd** | ~$2k | ~$3-5k | Decent for Asia-Pac | Strong | Overkill for current scale |
| **Cayman/BVI** | ~$3-5k | ~$3k | Red flag for strategic buyers | Hard | Avoid pre-Series A |

**Recommended structure:** Delaware LLC as the parent commercial entity, with an Israeli Ltd. operating subsidiary that employs Dor and handles day-to-day work. Why:

- **Acquirer-friendly.** US strategic buyers (Snyk, Palo Alto, CrowdStrike, GitLab, Snowflake) strongly prefer Delaware. A Cayman parent or Estonian shell adds diligence friction worth ~10-20% off the offer.
- **Tax-rational for Dor.** Israel has a tax treaty with the US; pass-through LLC income flows to Dor as the beneficial owner and is taxed in Israel. The Israeli subsidiary handles Dor's salary and pension cleanly under Israeli employment law.
- **Conversion-ready.** If Lictor takes VC money in 2027+, the standard move is converting Delaware LLC → Delaware C-Corp (a one-day filing). Starting in Cayman or Estonia makes this messy.
- **Stripe + Paddle + banking all work.** Mercury Bank or Brex accept Delaware LLCs with Israeli founders in 1-2 weeks.

**Confirm with an Israeli accountant familiar with US LLC ownership** that the pass-through treatment doesn't trigger surprise Israeli corporate tax. This is the #1 cross-border gotcha.

---

## 3. IP flow and employment

This is where the expensive mistakes happen. They are all preventable in 2026 and unfixable in 2028.

**Dor's employment agreement (LLC → Dor).** Must include explicit, broad IP assignment: every line of code, document, design, and idea related to Lictor that Dor produces — on or off hours, on any device — is assigned to Lictor LLC. Standard tech-startup boilerplate; any US tech lawyer has the template. Sign by **Jul 1, 2026**.

**The GenerationAI overlap problem.** Dor runs a consulting business (GenerationAI). The employment agreement must define a clear carve-out: GenerationAI keeps client-specific consulting deliverables; Lictor owns anything Lictor-related. The danger is ambiguous projects (e.g., a client engagement that uses Lictor code or generates code that ends up in Lictor). Fix: a written "Inventions Excluded" schedule attached to Dor's employment agreement listing pre-existing GenerationAI IP, plus a forward-looking rule that anything touching the Lictor codebase is Lictor IP regardless of which laptop it was typed on. **An acquirer's diligence lawyer will ask about this in the first hour.**

**Contributor License Agreement (CLA).** Every external contributor signs a CLA before their PR is merged. Use the Apache ICLA template (battle-tested, community-accepted) or EasyCLA via the Linux Foundation. The CLA gives Lictor (and later the Foundation) the right to relicense — without it, the project is stuck on Apache 2.0 forever, including for commercial features that need to stay closed. Publish on the repo by **Jul 15, 2026**.

**License stack.**
- **OSS core (lictor-cli, lictor-agents, lictor-runtime):** Apache 2.0. Permissive, commercial-friendly, the default for security tooling. Don't pick AGPL — it scares enterprise.
- **Lictor Studio Pro, Enterprise modules, Teams-only features:** BUSL 1.1 (Business Source License) with a 4-year conversion to Apache 2.0, or a straightforward proprietary EULA. BUSL is the modern compromise — code is readable, contribution-friendly, but commercial competitors can't host it as SaaS. Sentry, HashiCorp, MariaDB all use this.
- **Course content:** All Rights Reserved with explicit student license (one-seat, no redistribution).

**Trademark filings.** Register "Lictor" and "Lictor AI" as word marks in **US (USPTO), EU (EUIPO), and Israel (Israeli PTO)** by **Sep 1, 2026**. Filing dates matter — first-to-file in most jurisdictions. Budget ~$3k all-in.

---

## 4. Tax and financial structure

**Pass-through vs. C-Corp.** Delaware LLC is pass-through by default — profits flow to Dor (the member) and are taxed at Dor's personal Israeli rate. Cleaner than C-Corp's double taxation (corporate tax + dividend tax). If VC money arrives, the LLC converts to C-Corp because investors don't want pass-through K-1s flowing into their LPs' tax returns.

**Israeli tax for Dor.** Dor is an Israeli tax resident; LLC income is reportable in Israel. Israel/US tax treaty prevents double taxation on most income types, but there are quirks (the LLC is "transparent" in the US, "opaque" in Israel by default — Israeli accountants apply an election to align them). Engage an Israeli accountant who's done this before. **Failure mode:** discovering in 2028 that 3 years of LLC income is subject to a 23% Israeli corporate tax on top of personal income tax.

**US tax obligations.** Even as a non-US-resident LLC member, Dor must file FBAR (if total foreign account balances exceed $10k), Form 5472 (US LLC owned by foreign person — required even with zero income, $25k penalty if missed), and possibly Form 1120 with K-1 distribution. Not optional.

**Sales tax and VAT.** EU VAT on Teams subscriptions is the real exposure — once Lictor sells to one EU customer, it owes VAT in that country. The threshold is **€0** for digital services. This is where Paddle saves Dor's life.

**Stripe vs. Paddle.**
- **Paddle for Teams subscriptions and the Course.** Paddle is the Merchant of Record — they invoice the customer, collect VAT/sales tax in every jurisdiction, file the returns, and remit net to Lictor. Dor never thinks about VAT. Higher take rate (~5%+50¢ vs. Stripe's 2.9%+30¢) but the compliance cost is zero. For B2C/B2B-self-serve, this is non-negotiable.
- **Stripe for AaaS and Enterprise contracts.** These are custom, B2B, invoiced via DocuSign'd MSA. Stripe is fine because the customer pays VAT themselves (B2B reverse-charge).

Open the Paddle account **Aug 1, 2026** — they take 2-3 weeks to verify, and the launch is Oct 6.

---

## 5. The Lictor Foundation question

Harder, slower, more reversible. The decision can wait until early 2027.

**Why a Foundation.**
- **Structural protection.** Once the OSS core and the trademark sit inside the Foundation, no acquirer can quietly relicense — they'd need the Foundation board's approval, which won't come if the board is community-stacked. This is the structural moat that prevented the HashiCorp/Elastic-style community revolt from happening at, say, the Linux Foundation's Kubernetes.
- **Tax-deductible donations.** If structured as US 501(c)(3) charity, corporate and individual donations are deductible — material for getting Google, Anthropic, GitHub, etc. to write $25k-$250k checks for OSS funding programs.
- **Credibility signal.** "Lictor Foundation, governed by an independent board" reads very differently to a Fortune 500 security buyer than "a guy in Tel Aviv with a GitHub repo." Foundations are the structural shorthand for *this won't disappear if the founder quits*.
- **Eligibility for OSS funding programs.** Linux Foundation projects, CNCF sandbox, Apache Incubator, Sovereign Tech Fund — most require a non-profit upstream. There's $100M+/yr of capital floating around looking for credible OSS recipients.

**Why NOT a Foundation.**
- **Setup cost.** $8-15k legal + ~$3-5k/yr ongoing compliance (board minutes, public reporting, Form 990 for 501(c)(3), conflicts-of-interest policies).
- **Real governance.** 501(c)(3) requires a board of at least 3 unrelated directors. No self-dealing. Dor cannot just be "the boss" of the Foundation. Dor can sit on the board, but cannot control it.
- **Commercial friction.** Major decisions about the OSS roadmap that affect community trust technically run through the Foundation board, not the LLC. This is fine for healthy projects; it's a brake on the *bad* founder behaviors that would kill the project anyway.
- **Survivable without one.** Tailwind, Svelte, shadcn/ui, tRPC — none have foundations. They survive because of founder integrity and community trust, not structure. A Foundation is belt-and-suspenders, not a hard requirement.

**Three structural options (lawyer picks one):**
1. **501(c)(3) public charity.** Most rigorous, donations tax-deductible. Best credibility. Slowest setup (~6-12 months for IRS determination letter).
2. **501(c)(6) trade association.** Like Linux Foundation. Less rigorous, donations not deductible but membership dues are. Faster.
3. **Delaware non-stock non-profit corporation.** No federal tax-exempt status. Simplest setup. Apache Foundation pattern (though Apache is technically 501(c)(3)). Convertible to (c)(3) later.

**Recommendation:** Default to option 3 (Delaware non-stock) at incorporation in **Apr 2027**, with a 12-18 month path to filing 501(c)(3) status after enough revenue/donation activity makes the IRS application defensible. Faster, cheaper, structurally identical for acquirer-protection purposes.

**The middle path for now.** Don't incorporate the Foundation in 2026. Instead, write into `CONTRIBUTING.md` and the README:

> *Lictor's core code will be transferred to the Lictor Foundation, an independent non-profit, by April 2027. Until then, the project is stewarded by Lictor LLC under a public commitment to keep the core Apache 2.0 forever.*

That public commitment is binding-enough in the court of community opinion. It gives acquirers comfort (the path is known) and gives Dor 11 months to learn what Foundation shape fits. Reneging would be a brand-ending event — which is the point.

**End state:** Foundation owns the trademark and the OSS repo. LLC licenses the trademark from Foundation under a perpetual, royalty-free, worldwide license, terminable only for material breach. LLC contributes to OSS under CLA like any other contributor. Acquirer buys the LLC — they get the commercial features, the customer contracts, the trademark license, and a seat at the table with the Foundation. They do *not* get to relicense the OSS.

---

## 6. Acquirer perception

How does each structure read to different acquirer types?

**Strategic tech buyer (Snyk, Palo Alto, CrowdStrike, GitLab, Snowflake).** This is the realistic exit and the dominant comp set (per `m-and-a-strategy.md`).
- **LLC alone:** clean, easy fold-in. Highest offer ceiling but no structural commitment to keep OSS alive — buyer can relicense.
- **LLC + Foundation:** ~5-15% offer discount because the buyer "has to negotiate with the Foundation board" for the trademark license and OSS roadmap influence. Smaller offer, more durable asset.
- **Pure Foundation:** unbuyable. The Foundation can't sell itself; it can only hand control of OSS direction to a new board.

**Talent + IP buyer (Anthropic, OpenAI, Google).** Acqui-hire pattern.
- They take either structure. They want Dor and the team; the OSS code is incidental and they're often happy to keep it open.
- Foundation is *less* of a friction here because they don't need to lock up the OSS.

**Private equity / financial buyer (Thoma Bravo, Vista).** Roll-up pattern.
- LLC: fine.
- Foundation: a problem. PE buyers want clean ownership of everything; a Foundation is uncontrollable from their perspective. PE offers will be 20-30% lower or won't materialize.

**Strategic call:** the Foundation announcement is timed *late* (Apr 2027) in the year, after the major content + brand + community trust work has landed. By Apr 2027, OSS community trust is baked in; the Foundation move is *documenting what's already true* rather than imposing structure. If Lictor incorporates the Foundation on day one, it limits acquirer optionality from day one — for a moat that doesn't pay off until the project has $5M+ in implied value.

The current plan (LLC June 2026, Foundation April 2027) **maximizes optionality**: the first 10 months Lictor is fully sellable as a clean LLC; from month 11 onward, the Foundation structure kicks in and the asset becomes more durable but less roll-upable. The crossover is roughly correct.

---

## 7. The lawyer engagement

Do not DIY any of this. Specific recommendations:

**US tech-startup lawyer (specializes in OSS).** Engage by **Aug 1, 2026**. Scope: Delaware LLC formation, Dor employment + IP assignment, CLA setup, BUSL/EULA drafting for paid features, trademark filings. Budget **$3-5k** for the first 6 months. Names to look at: Cooley LLP (gold standard, expensive), Gunderson Dettmer (similar), or boutique OSS-specialist firms like Heather Meeker's group.

**Israeli accountant familiar with US LLC ownership.** Engage by **Sep 1, 2026**. Scope: Israeli tax election for the Delaware LLC, Dor's cross-border income reporting, Israeli subsidiary setup, VAT registration when needed. Budget **~$2-3k/yr**.

**Trademark lawyer (may be same as US lawyer).** For US + EU + IL filings. Budget **~$3k one-time** plus ~$500/yr per jurisdiction renewal. Some firms include this in the startup package.

**Foundation lawyer (different specialty).** Engage by **Feb 1, 2027**. Non-profit law is a separate practice area from corporate law — the corporate lawyer above is not the right person. Names: Adler & Colvin (the 501(c)(3) gold standard), or attorneys who've helped form Linux Foundation projects, Cloud Native Computing Foundation members, etc. Budget **$8-15k one-time** for incorporation + bylaws + 501(c)(3) application.

**Total legal budget through May 2027: ~$15-25k.** Compared to the downside of getting IP assignment wrong (low-tens-of-thousands of dollars off the eventual offer per ambiguous question), this is the cheapest insurance Lictor will ever buy.

---

## 8. Dated commitments

These feed into `year-plan-2026-2027.md`:

| Date | Action |
|---|---|
| **Jun 1, 2026** | Lictor LLC (Delaware) registered |
| **Jun 15, 2026** | Israeli subsidiary registered (pending accountant confirmation) |
| **Jul 1, 2026** | Dor employment agreement + IP assignment + GenerationAI carve-out signed |
| **Jul 15, 2026** | CLA published on the OSS repo (Apache ICLA or EasyCLA) |
| **Aug 1, 2026** | Paddle account opened (verification takes 2-3 weeks; Oct 6 launch requires it live by Sep 15) |
| **Sep 1, 2026** | Trademark filings submitted (US, EU, IL) |
| **Sep 15, 2026** | License stack live: Apache 2.0 OSS + BUSL/EULA on paid features |
| **Feb 1, 2027** | Foundation lawyer engaged |
| **Apr 1, 2027** | Lictor Foundation incorporated (Delaware non-stock; 501(c)(3) path optional) |
| **Apr 15, 2027** | Trademark + canonical OSS repo transferred from LLC to Foundation; perpetual license back to LLC executed |
| **May 1, 2027** | First diligence-ready legal structure — clean data room |

---

## 9. The decisions Dor actually has to make

Most of this memo delegates to lawyers. But three calls are Dor's, not the lawyer's:

1. **Israeli subsidiary, yes or no?** Driven by Dor's preference on Israeli employment law, pension structure, and tax election. The accountant will explain trade-offs; Dor picks. Default recommendation: yes, employs Dor cleanly under Israeli law.

2. **BUSL vs. proprietary EULA for paid features.** BUSL signals "open-ish" and earns community goodwill; EULA is cleaner from an acquirer's perspective. Default: BUSL 1.1 with 4-year Apache conversion — the modern OSS-commercial standard.

3. **Foundation structure (Apr 2027).** Delaware non-stock (fast/cheap) vs. 501(c)(3) (slow/credible). This decision belongs to the Foundation lawyer engaged in Feb 2027, informed by where the project actually is — revenue, donation pipeline, community size. Don't pre-decide.

Everything else: hire the lawyer, follow the dates.
