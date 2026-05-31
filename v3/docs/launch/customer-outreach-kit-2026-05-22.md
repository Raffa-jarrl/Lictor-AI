# Lictor — First 50 Customers Outreach Kit
*Generated 2026-05-22 — strategic pivot from "find more vulns" to "find first paying customer"*

---

## 1. Target customer profile

**ICP (Ideal Customer Profile)**: SMB CISO / Head of Security / IT Director at a 50-500 employee company

**Specifically targeting**:
- **Stage**: Series A through D (have budget, not too big for SMB pricing)
- **Vertical**: Fintech, SaaS, healthcare-adjacent, e-commerce, marketplaces
- **Geography**: US East/West Coast, UK, EU, Israel
- **Current security stack**: Either using Tenable/Rapid7 (overpaying ~$30K-$100K) OR running zero external scanning (security-aware but priced out)
- **Trigger events**:
  - Just raised a round (needs SOC 2 fast)
  - Customer asked for security questionnaire (SIG-Lite, CAIQ)
  - Recent industry breach in their vertical (alert-driven)
  - Hired a CISO in the last 6 months (new buyer)

**Anti-ICP** (do NOT pitch):
- Enterprise (>5,000 employees) — wrong sales motion, will demand features we don't have
- Pre-seed / pre-funding — no budget
- Pure-consumer no-IT companies (small retail, restaurants) — no security buyer

---

## 2. Where to find them

| Channel | Effort | Volume | Best for |
|---|---|---|---|
| **LinkedIn Sales Nav search** | $99/mo + 4h to set up | 500+ profiles/week | Title="CISO" OR "Head of Security" OR "IT Director" + Company-size 50-500 + recent funding |
| **CISO Slack communities** | Free, build relationships | ~30 warm intros/quarter | The CISO Network, Security Bsides slacks, Latio, CloudSecurityForum |
| **Founder networks (your YC/EF/etc. batch)** | Free | 20-50 leads | Ask for intros to "the security person at your company" |
| **Conference attendee lists** | $0-$500 | 200-2,000 leads | BSides (free), Defcon, RSA (expensive), SaaStr |
| **Twitter/X security community** | Time investment | Slow but warm | Engage with @SwiftOnSecurity, @SecurityWeekly, individual CISOs |
| **HackerOne / Bugcrowd disclosed reports** | Free, already in our network | High intent | Anyone we already disclosed TO has met us — ask them for an intro |
| **Cold email (Apollo/Hunter)** | $59-$200/mo | 100-500 sends/week | Backup channel; expect 1-2% reply rate |

**Recommended 50-contact strategy**:
- 15 from existing disclosure relationships (warm — we already helped them)
- 15 from your founder/operator network (warm intros)
- 10 from CISO Slack communities (semi-warm, demonstrated interest in security)
- 10 from LinkedIn Sales Nav cold outreach (focused on recent-funding-event signal)

---

## 3. The cold email template (use as starting point, personalize each)

### Subject lines (A/B test 3-4):
- `Found an exposed bucket on {{company}} — also you have 7 more we can scan`
- `We're scanning the security perimeter of every Series B SaaS. {{company}}'s results.`
- `Quick question on your external attack surface monitoring`
- `Replacing Tenable at {{company}}? (We just helped {{similar_company}} cut $40K)`

### Body (template — replace `{{...}}` placeholders):

```
Hi {{first_name}},

I'm Raffa, founder of Lictor — open-source security scanner that's been
disclosing findings to companies in your industry this month. Quick numbers:

  • 90+ disclosures sent in May
  • Found exposed loan data on 3 Google Cloud buckets, RDP exposed on a major
    bank, and ~30 DeFi sourcemap leaks
  • 12 country sites of one Fortune 500 had the same misconfig

Why I'm reaching out: I ran our scanner against {{company}}'s external
perimeter last week and found {{specific_finding_summary}}. Not pitching —
this is yours to fix regardless. Details: https://lictor-ai.com/r/{{ref_code}}

What I'm building: SMB-priced ($7K-15K/year) version of what Tenable charges
$40K-$100K for. Same external attack surface monitoring, plus the disclosure-
coordination workflow we use ourselves (when we find an issue on a vendor of
yours, we handle the reporting upstream).

Worth a 20-minute call this week? I'll bring your scan results and walk
through the 3 highest-risk findings (no slide deck, no sales pitch).

— Raffa
   raffajarrl@gmail.com / lictor-ai.com / github.com/Raffa-jarrl/Lictor-AI
   PS: If you'd rather just want the report and skip the call, reply "send it"
       and I'll email the PDF.
```

**Personalization rule**: never send the same template to two prospects without changing the `{{specific_finding_summary}}` for at least the top 10 prospects. Generic openings = 0% reply rate.

### Warm intro template (when someone introduces you):

```
Hi {{first_name}},

Thanks to {{intro_person}} for the intro.

Quick context: Lictor is the OSS scanner I've been running (90+ disclosures
in May including a $7B DeFi protocol, a major Israeli bank, and 5 GCS buckets
with regulated data). Building the SMB-priced version now and looking for
10-15 design partners.

The pitch: 30-minute call where I share what I find on {{company}}'s external
perimeter. No sales talk. If it's useful, we'd offer Year 1 free in exchange
for a case study / testimonial. After that, $7K-15K/year depending on scope.

What's a good time this week?
— Raffa
```

---

## 4. Discovery call script (30 min, no slide deck)

**First 5 min** — set context, understand them:
- "What's your current external scanning setup?" (gauge incumbent: Tenable / Rapid7 / nothing)
- "What's the most painful security thing on your plate this quarter?" (find the wedge)
- "If a vendor of yours had an exposure that affected you, how would you find out?" (sets up the disclosure-coordination angle)

**Min 5-20** — walk through their findings (live or sent ahead):
- Lead with highest severity finding
- For each: what we found, who's at risk, how to fix, what we'd do for them going forward
- Explicitly NOT pitching — just sharing
- Pause for questions every finding

**Min 20-25** — gauge interest:
- "Would having this monthly be useful?"
- "If yes, what would good monitoring look like for your team?"
- "Who else on your team would care about this?" (find champions)

**Min 25-30** — close or schedule next step:
- If interest: "Here's our design-partner program: Year 1 free, monthly scan + a quarterly review call with me. After Year 1, $7K-15K depending on scope. Want to start with a free month?"
- If lukewarm: "Want me to keep sending you scan deltas monthly via email? No commitment."
- If no: "Anyone in your network who might want this? Happy to intro."

---

## 5. Pricing tiers (draft for /pricing page)

```
LICTOR FREE                        LICTOR PRO                          LICTOR ENTERPRISE
                                                                       (later, when ready)

Self-serve open source             $7,500 / yr  (or $750/mo)          $25K-$100K / yr custom
github.com/Raffa-jarrl/Lictor-AI                                       contact sales

  ✓ All 38 scanner modules         ✓ Everything in Free                ✓ Everything in Pro
  ✓ Apache 2.0 license             ✓ Hosted scanning (we run it for    ✓ Lictor Internal (AD audit,
  ✓ Run on your own infra            you against your domains)           password rotation, network
  ✓ Community support              ✓ Monthly scheduled scans            share enum) — when ready
                                   ✓ PDF report + JSON export          ✓ White-label for MSPs
  Best for:                        ✓ Disclosure-coordination service   ✓ Custom integrations
  - Security researchers             (when we find issue on your        ✓ Dedicated CSM
  - Bug bounty hunters               vendor, we handle reporting)      ✓ SLA-backed support
  - Open-source contributors        ✓ Slack/email alerting on new
                                      critical findings                Best for:
                                    ✓ Per-finding compliance mapping   - 1,000+ employees
                                      (SOC2 / ISO27001 / PCI / HIPAA)  - Multiple subsidiaries
                                                                       - MSP/MSSP partners
                                    Best for:
                                    - 50-500 employee SaaS / fintech
                                    - SOC2/ISO27001 prep
                                    - Replacing Tenable/Rapid7 spend


DESIGN PARTNER PROGRAM (limited, first 10-15 customers)
  - Year 1 free
  - In exchange: quarterly 30-min feedback call + permission to share
    anonymized case study
  - After Year 1: locked-in Pro pricing for 3 years
  - Apply: email raffajarrl@gmail.com with subject "Lictor Design Partner"
```

---

## 6. The 50-contact list — how to build it (TODO for Raffa)

I can't generate the actual contact list (need LinkedIn Sales Nav access + your warm-intro network). But here's the methodology that gets you to 50 in 2-3 hours:

1. **Spreadsheet template** (column: name | company | title | source | warm-or-cold | last-funding | tech-stack-hint | first-touch-date | reply | call-scheduled | converted)

2. **15 from existing disclosure pipeline**: Re-open the disclosures Gmail thread, list everyone who replied. Each one already knows us.

3. **15 from your founder network**: Ping these 5 friends with "intro me to your CISO / Head of Security": [pick 5 founder friends]. Each yields 2-3 leads = 10-15 total.

4. **10 from CISO Slacks**: Join 3-5 Slacks today, lurk a week, then post a "looking for SMB CISOs who want a free perimeter scan in exchange for 30-min feedback call." Naturally yields 5-10 takers.

5. **10 from LinkedIn Sales Nav** (~$99/mo): filter Company-size 50-500 + Recent funding event + Title=CISO/Head of Security. Save 50 profiles. Send connection requests with personalized note. Convert 10 to email.

**Time to 50**: ~1 week of focused effort, 4-8 hours total.

---

## 7. Success metrics for next 30 days

| Metric | Target | Stretch |
|---|---|---|
| Outreach sent | 50 | 100 |
| Reply rate | 8% (4 replies) | 15% (15 replies) |
| Discovery calls booked | 4-8 | 10-15 |
| Design partners signed | 2-3 | 5-7 |
| First paid PO (after design-partner-year-1) | 0 (too early) | 1 |
| Lictor-AI.com /pricing visits | 200+ | 500+ |
| GitHub stars added | +50 | +200 |

If we hit "Target" column: validated demand → invest in productizing → raise seed.
If we miss: re-think ICP or product positioning before more building.

---

## 8. What I'm explicitly NOT doing this month

To enforce focus:

- ❌ Building Lictor Internal (waits till we have External Pro revenue)
- ❌ Building Lictor AI-Ready (waits till Year 2)
- ❌ More crypto/DeFi disclosure hunts (mission accomplished — channel works)
- ❌ Adding new scanners (we have 38, the issue is not scanner count)
- ❌ Conference speaking (waits till v0.2 is shipped + revenue exists)
- ❌ Pitching VCs (waits till we have 5-10 paying customers)

**Do these in 4-8 weeks once we have customer signal, not before.**
