> **NOTE (May 2026 update):** Course revenue line REMOVED from Lictor's plan. The course at generationai.com is a separate consulting business and is no longer part of this project. References below that mention "Course", "course enrollments", or course-derived revenue should be treated as historical and substituted with zero. Other revenue lines (Teams, AaaS, Enterprise) stand.

# Lictor data room — diligence-ready folder structure

> **Generated:** 2026-05-15
> **Status:** template / placeholder (populate progressively per year plan)
> **Purpose:** the folder structure + checklist + cadence that turns "we run a business" into "we can be audited by an acquirer in 48 hours." The data-room is one of the strongest indicators that a target is *actually* acquisition-ready vs *says it is*.

---

## The strategic principle

Most founders build their data-room in the 6 weeks before a deal. That's too late — items are missing, documents are last-minute, the "we have the records, just need to compile" promise becomes the friction that drops the deal multiple.

Lictor's data-room is built **continuously, in parallel with the operation**. Every month, each section gets its incremental update. By May 2027, when the first acquirer informational meeting happens, the data-room is complete, audit-fresh, and confidence-building.

The data-room is also a *forcing function for Dor*. Maintaining clean financials forces clean books. Maintaining a customer log forces customer-success rigor. The data-room IS the management system, not a separate compliance burden.

---

## The folder structure

```
~/Lictor/docs/business/data-room/
├── README.md                          # this file
├── 00-company/
│   ├── company-overview.md            # 1-page intro
│   ├── org-chart.md                   # Dor + agent crew + contractors
│   ├── entity-registrations/          # cert copies (LLC, Foundation)
│   └── cap-table.md                   # 100% Dor (until something changes)
├── 01-financials/
│   ├── statements/
│   │   ├── 2026-Q3-pnl.pdf           # quarterly P&L
│   │   ├── 2026-Q3-balance-sheet.pdf
│   │   └── 2026-Q3-cash-flow.pdf
│   ├── revenue-streams/
│   │   ├── teams-mrr-history.csv     # monthly Teams MRR snapshots
│   │   ├── course-revenue.csv
│   │   ├── audit-as-a-service.csv
│   │   └── enterprise.csv
│   ├── unit-economics.md              # LTV, CAC, payback, gross margin
│   └── forecasts.md                   # 12 + 24-month projections
├── 02-customers/
│   ├── customer-list.csv              # anonymized for sharing; named for Dor
│   ├── customer-logos.md              # logos with permission for use
│   ├── reference-customers.md         # the 5-7 willing to do calls
│   ├── churn-analysis.md
│   └── nps-csat.md                    # if measured
├── 03-product/
│   ├── architecture-overview.md       # 1-page system diagram
│   ├── roadmap.md                     # link to public ROADMAP.md
│   ├── feature-list.md                # what ships in each product
│   ├── github-stats-monthly.csv       # stars, PRs, issues, contributors
│   └── known-issues.md                # the honest "what's broken" list
├── 04-technology-ip/
│   ├── license-audit.md               # Apache 2.0 OSS + commercial license stack
│   ├── trademark-registrations/       # cert copies (US + EU + IL)
│   ├── oss-dependencies-inventory.md  # generated; updated quarterly
│   ├── cla-records/                   # every contributor's signed CLA
│   ├── employment-ip-assignments/     # Dor's IP assignment + any contractor's
│   └── domain-registrations.md        # all owned domains
├── 05-sales-marketing/
│   ├── pipeline.md                    # if any active deals
│   ├── marketing-analytics-monthly.csv
│   ├── channel-mix.md                 # where revenue comes from
│   ├── press-mentions.md              # cumulative log
│   └── community-signal.md            # GitHub stars, Discord, Twitter, newsletter
├── 06-legal/
│   ├── entity-registrations/          # mirror of 00-company
│   ├── contracts/
│   │   ├── customer-template.md       # standard Teams + Enterprise terms
│   │   ├── vendor-contracts/          # signed copies (Paddle, Stripe, etc.)
│   │   └── partner-agreements/        # any platform partnerships
│   ├── insurance.md                   # what's covered + policy copies
│   ├── disputes.md                    # hopefully empty
│   └── compliance.md                  # SOC2 status, GDPR posture
├── 07-operations/
│   ├── vendor-list.md                 # every paid service
│   ├── critical-processes.md          # how things actually run
│   ├── disaster-recovery.md           # what happens if X breaks
│   ├── security-policy.md             # the meta-security posture (irony noted)
│   └── runbook-index.md               # all the internal docs that aren't here
├── 08-risk/
│   ├── known-risks.md                 # the 12 named risks from year-plan
│   ├── competitive-landscape.md       # link to snyk-gap-analysis.md
│   └── regulatory-exposure.md         # EU AI Act, GDPR, etc.
├── 09-community-content/              # Lictor-specific (acquirers will look hard here)
│   ├── teardown-archive-index.md      # 52+ teardowns by year-end 2027
│   ├── content-metrics-monthly.csv    # video views, newsletter subs, etc.
│   ├── partnership-list.md            # Lovable / Bolt / v0 / etc. integrations
│   └── brand-assets/                  # logos, fonts, color codes
└── 99-archive/                        # superseded versions; nothing deleted
    └── YYYY-MM/                       # snapshots at quarter end
```

---

## Section-by-section: what goes in each + when

### 00 — Company

**What:** the 1-page "here's who we are" overview an acquirer reads first.

**Owner:** Dor.

**When populated:**
- `company-overview.md` — drafted June 2026, updated quarterly
- `org-chart.md` — drafted June 2026, updated when crew expands (Q1 2027 hires)
- `entity-registrations/` — populated June 2026 (LLC) + April 2027 (Foundation)
- `cap-table.md` — drafted June 2026; updated only when something changes

**Diligence-ready when:** all 4 documents exist, dated within 30 days, and any acquirer can read the company overview in 5 minutes.

### 01 — Financials

**What:** the books. Quarterly P&L + balance sheet + cash flow + per-stream revenue history + unit economics + forecasts.

**Owner:** outside accountant (engaged June 2026 per year plan) populates the statements; Dor populates the strategic docs.

**When populated:**
- `statements/` — first set delivered by accountant **end of Q3 2026** (Sep 30); thereafter quarterly within 30 days of quarter-end
- `revenue-streams/*.csv` — Dor updates monthly on the 1st (Teams MRR, Course, AaaS, Enterprise)
- `unit-economics.md` — first calculation **Jan 2027** (after Teams ships); refresh quarterly
- `forecasts.md` — yearly; first iteration Dec 2026 (12-month) and June 2027 (24-month)

**Diligence-ready when:**
- 4+ quarters of statements
- Monthly revenue history with no gaps
- Unit economics calculated against real numbers (not projected)
- Forecast that's been retroactively compared against actuals (acquirers love seeing your previous forecast vs actual)

**Critical:** never co-mingle Lictor and GenerationAI revenue. Separate Stripe / Paddle accounts. Separate bank accounts. Separate ledger in QuickBooks.

### 02 — Customers

**What:** who pays Lictor + how much + how happy.

**Owner:** Dor + Bridge agent for the customer log.

**When populated:**
- `customer-list.csv` — starts the day Teams launches (Dec 15, 2026); updated weekly
- `customer-logos.md` — populate after Q1 2027 when 5+ customers consent to logo use
- `reference-customers.md` — identify by Feb 2027; 5-7 willing
- `churn-analysis.md` — first analysis Apr 2027 (3 months of Teams data)
- `nps-csat.md` — optional; start Feb 2027 if Teams hits 200 subs

**Diligence-ready when:**
- Customer list is current (within 7 days)
- 5+ logo-consented customers
- 3+ reference customers ready to do unscheduled calls
- Churn analysis with > 90 days of data

### 03 — Product

**What:** what Lictor actually is, in technical detail an acquirer's CTO would want.

**Owner:** Dor + dev (C-3PO) agent.

**When populated:**
- `architecture-overview.md` — first draft **July 2026**; refresh quarterly
- `roadmap.md` — symbolic link to public ROADMAP.md
- `feature-list.md` — drafted at launch (Oct 2026); refresh with each product release
- `github-stats-monthly.csv` — populated automatically by a monthly cron (set up June 2026)
- `known-issues.md` — refreshed weekly by Mirror agent's review

**Diligence-ready when:**
- Architecture diagram is current
- Stats CSV has 6+ months of data
- Known-issues list is honest and recent (acquirers spot fake-perfect lists)

### 04 — Technology + IP

**What:** the IP audit. The most carefully-watched section in any tech M&A.

**Owner:** Dor + outside IP lawyer.

**When populated:**
- `license-audit.md` — **drafted June 2026 with lawyer**; refreshed when license stack changes (e.g., when BUSL is added for paid features per legal-structure-memo.md)
- `trademark-registrations/` — files added as filings complete (US + EU + IL ~ Sep 2026)
- `oss-dependencies-inventory.md` — generated by `cargo outdated` + `pnpm audit` + `pip list` exported quarterly
- `cla-records/` — every external contributor's signed CLA. Start logging June 2026.
- `employment-ip-assignments/` — Dor's signed by **July 2026**; contractors' as added.
- `domain-registrations.md` — all 3 domains documented with registration receipts

**Diligence-ready when:**
- Every external code contributor has a signed CLA
- All trademarks registered or filed
- Dependency inventory shows no GPL-licensed deps in commercial features
- Dor's employment + IP assignment exists in writing

**Critical:** acquirers will diligence this section the HARDEST. Missing CLAs are deal-killers. Unclear IP assignment is a deal-killer. Dependencies under aggressive licenses (AGPL) in commercial features = deal-killer.

### 05 — Sales + marketing

**What:** the channel mix + how customers find Lictor.

**Owner:** Dor + Magnet + Bridge agents.

**When populated:**
- `pipeline.md` — start tracking Q1 2027 when AaaS pipeline becomes real
- `marketing-analytics-monthly.csv` — monthly, starting July 2026 (newsletter signups, social followers, GitHub stars)
- `channel-mix.md` — first analysis Q4 2026 (after launch); refresh quarterly
- `press-mentions.md` — running log, starts when first article publishes
- `community-signal.md` — generated weekly by Bridge agent

**Diligence-ready when:**
- Marketing CSV has 6+ months of data
- Channel mix is documented with cost per channel
- Press log includes every meaningful mention

### 06 — Legal

**What:** the boring-but-deal-critical legal stack.

**Owner:** outside lawyer + Dor.

**When populated:**
- `contracts/customer-template.md` — drafted **before Teams launch** (Nov 2026)
- `vendor-contracts/` — added as services are signed up (Paddle, Stripe, hosting, etc.)
- `partner-agreements/` — added when Lovable / Bolt platform partnership signs (Q1-Q2 2027)
- `insurance.md` — E&O insurance considered Q1 2027 once revenue justifies (~$1.5k/yr)
- `disputes.md` — hopefully always empty; populated if needed
- `compliance.md` — GDPR posture documented before Teams launch; SOC2 readiness assessed Q2 2027

**Diligence-ready when:**
- Every customer signed the same standard template
- Vendor contracts complete (Stripe, Paddle, Cloudflare, GitHub, hosting, etc.)
- No open disputes
- GDPR posture is provably handled (privacy policy, DPA template, data-flow diagram)

### 07 — Operations

**What:** the "how does this run if Dor is hit by a bus" section.

**Owner:** Dor.

**When populated:**
- `vendor-list.md` — populated June 2026; updated as services change
- `critical-processes.md` — drafted by Aug 2026 with the agent crew's runbooks
- `disaster-recovery.md` — drafted before launch (Oct 2026); tested quarterly
- `security-policy.md` — drafted before Teams launch; reviewed annually
- `runbook-index.md` — link map to all the agent SOUL files + scripts

**Diligence-ready when:**
- Vendor list current with passwords/access documented (in a password manager, not in this file)
- Critical processes have written runbooks
- Disaster recovery is testable (and tested in Apr 2027)

**For an OSS company, this is one of the strongest signals you can give an acquirer**: "we don't depend on tribal knowledge. Every process is documented. Onboard your engineer in 2 weeks."

### 08 — Risk

**What:** the honest "what could go wrong" register.

**Owner:** Dor.

**When populated:**
- `known-risks.md` — symbolic link to year-plan-2026-2027.md's risk section, refreshed at quarter-end
- `competitive-landscape.md` — symbolic link to snyk-gap-analysis.md, refreshed when Probe's competitive watch finds material moves
- `regulatory-exposure.md` — drafted Sep 2026; refreshed when EU AI Act phase-2 lands

**Diligence-ready when:** acquirers can read the risk register and recognize the same risks they would have flagged themselves. **A "no risks" register is a red flag.** Be honest.

### 09 — Community-content (Lictor-specific)

**What:** the part of Lictor that's unique vs every other software company — the OSS community, the teardown archive, the brand.

**Owner:** Magnet + Bridge + Quill agents (most data auto-generated).

**When populated:**
- `teardown-archive-index.md` — auto-updated as each teardown publishes
- `content-metrics-monthly.csv` — agent-generated monthly
- `partnership-list.md` — manual; updated when partnerships sign
- `brand-assets/` — populated June 2026 with logos, fonts, social handles

**Diligence-ready when:**
- 52+ teardowns archived (per year plan, by mid-2027)
- 12+ months of content metrics
- Brand assets ready for an acquirer's design team to integrate

---

## Diligence-readiness checklist

Use this as the May 2027 readiness gate. Each item is binary: yes / no.

### Financial
- [ ] 4+ quarters of statements (P&L, balance sheet, cash flow) signed off by accountant
- [ ] Revenue history by stream (monthly granularity, no gaps)
- [ ] Unit economics calculated against real numbers
- [ ] 12-month forecast vs 6 months of actuals (prove forecast quality)
- [ ] Bank account separate from GenerationAI
- [ ] Books closed monthly within 7 days of month-end

### Legal + IP
- [ ] LLC + Foundation incorporated (or LLC-only with binding Foundation commitment)
- [ ] Dor's employment agreement + IP assignment signed
- [ ] CLAs on file for every external contributor
- [ ] Trademarks registered in US + EU + IL
- [ ] No GPL/AGPL dependencies in commercial code
- [ ] Standard customer agreement signed by every customer
- [ ] Privacy policy + DPA + cookie policy live

### Customer
- [ ] 500+ paying Teams subs OR equivalent revenue mix
- [ ] 5+ logo-consented customers
- [ ] 3+ reference customers ready for calls
- [ ] Churn analysis with > 6 months of data
- [ ] Customer list current within 7 days

### Product
- [ ] Architecture overview current within 90 days
- [ ] Public roadmap aligned with private direction
- [ ] Known-issues list honest and updated weekly
- [ ] No critical CVEs open against Lictor itself
- [ ] Bug bounty program live with > 5 valid claims paid

### Operations
- [ ] Every vendor documented
- [ ] Critical processes have written runbooks
- [ ] Disaster recovery tested in the last 90 days
- [ ] Password manager + access list current
- [ ] Security policy reviewed in the last 12 months

### Community / brand
- [ ] 52+ teardowns archived
- [ ] 50,000+ GitHub stars (the threshold for "category presence")
- [ ] 25,000+ weekly active skill users
- [ ] 3+ platform partnerships (Lovable, Bolt, v0)
- [ ] At least 1 major-media mention
- [ ] Dor has spoken at 1+ Tier-1 conference

If 90%+ of the above is checked by May 2027, Lictor is diligence-ready at multiples that justify a real conversation.

---

## How to maintain this (the cadence)

Most data-room maintenance is **monthly + quarterly**:

**Monthly (1st of every month, ~2h of Dor's time):**
- Update revenue CSVs (Teams, Course, AaaS, Enterprise)
- Update GitHub stats CSV (auto-generated)
- Refresh customer list
- Update press mentions log
- Add any new vendor contracts

**Quarterly (last week of each quarter, ~1 day with accountant):**
- Statements signed off (P&L, balance sheet, cash flow)
- Architecture overview refresh
- Channel mix analysis
- Risk register review

**Yearly (May, ~3 days):**
- Forecast refresh
- Insurance review
- Compliance posture audit
- Full data-room consistency pass

If maintained on this cadence, the May 2027 readiness audit is *checking the work, not doing the work*. That's the asset.

---

## What this is NOT

- **Not a substitute for due diligence.** The data-room collects the facts. The diligence process verifies them. Acquirers will hire third-party validators (financial, legal, technical) regardless of how clean the data-room looks.
- **Not a marketing artifact.** This is internal. The deck for outside-warmth (investor/acquirer monthly update — see `investor-acquirer-update-template.md`) lives separately.
- **Not optional for "we're just keeping the option open."** If you want optionality, you do this work. If you don't do this work, you don't have optionality — you have hope.

---

## The starter pack (what to populate THIS WEEK)

Don't try to populate everything. Start with these 8 files in June 2026:

1. `00-company/company-overview.md` (1 hour)
2. `00-company/org-chart.md` (30 min)
3. `00-company/cap-table.md` (15 min — 100% Dor, dated)
4. `04-technology-ip/license-audit.md` (1 hour with lawyer)
5. `04-technology-ip/employment-ip-assignments/dor.pdf` (lawyer-prep'd)
6. `04-technology-ip/domain-registrations.md` (30 min)
7. `08-risk/known-risks.md` (symbolic link to year-plan risks)
8. `09-community-content/brand-assets/` (drop existing logos)

That's ~4 hours of work in June. Each subsequent month adds 2-3 files. By May 2027, the structure is fully populated, organically, without ever feeling like a separate compliance project.
