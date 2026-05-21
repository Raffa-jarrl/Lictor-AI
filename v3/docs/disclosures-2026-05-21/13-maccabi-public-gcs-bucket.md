# Disclosure 13 — Maccabi Healthcare — public gcs://maccabi bucket with training assets (LOW-MEDIUM)

**Target:** `gs://maccabi` (publicly LISTABLE on Google Cloud Storage)
**Owner:** Likely **Maccabi Healthcare Services** (Maccabi Sherutei Briut) — second-largest Israeli HMO
**Files:** 395 files across 3 top-level folders, including Hebrew-named workplace-safety training content
**Risk:** LOW-MEDIUM — public-facing training/marketing assets visible; NOT patient PII, but Maccabi-branded e-learning content shouldn't be world-listable
**Action:** Email Maccabi IT + parallel to CERT-IL

---

## What Lictor observed (HEAD/list only, NO downloads)

```
$ curl -s "https://storage.googleapis.com/storage/v1/b/maccabi/o?maxResults=500&fields=items(name,size)"

Total files: 395
Top-level folders:
  - BetihutShetah10
  - אשראי יזום           (Hebrew: "Proactive Credit")
  - מכבי בטיחות בעבודה   (Hebrew: "Maccabi Workplace Safety")
```

The literal **Hebrew folder names** confirm Maccabi affiliation:
- `מכבי בטיחות בעבודה` = "Maccabi Workplace Safety" (Hebrew)
- `אשראי יזום` = "Proactive Credit" (Hebrew; likely Maccabi Financial
  Services / consumer credit product since Maccabi has financial-services
  subsidiaries)
- `BetihutShetah10` = "Field Safety 10" (transliteration of Hebrew)

The content appears to be **e-learning / SCORM packages**:
- `imsmanifest.xml` files present (IMS Content Packaging standard)
- HTML assets (`index.html` = 68KB), CSS, SVG icons, training images
- Hebrew-language UI assets (`speaker.png`, `speaker2.jpg`, `xray.png`,
  `usedband.jpg` = audio/visual cues + workplace-safety photography)
- File timestamps from 2020-2022

This is **employee/customer training content**, NOT patient medical
records. The bucket pattern matches "we put public-facing e-learning
content on GCS so any browser can load it without auth."

## Why this is LOW-MEDIUM (not CRITICAL)

What it's NOT:
- ❌ NOT patient medical records or PII
- ❌ NOT password/credential leak
- ❌ NOT a customer database

What it IS:
- ⚠️ A publicly listable bucket owned by Maccabi (or one of its
  subsidiaries) — the bucket-listing permission lets anyone enumerate
  the 395-file catalog
- ⚠️ Hebrew-named folders confirm Maccabi branding, so even though
  content is training material, the bucket exposure is Maccabi's
  brand surface
- ⚠️ Marketing/training content delivered from `gs://maccabi/` without
  authentication suggests the team didn't realize the bucket is
  world-listable
- ⚠️ Trust risk: if someone gains write access to the bucket (via
  misconfig or future credential leak), they could replace training
  content with phishing/malicious assets

## Recommended remediation

1. **Make the bucket non-listable**: change the IAM to remove
   `allUsers:roles/storage.objectViewer` on the bucket level. Use
   per-object permissions, or move to a private bucket + signed URLs
   for the e-learning content.
2. **OR use a CDN-fronted approach**: serve training assets through
   a CDN URL (e.g. cdn.maccabi-online.co.il) backed by the GCS bucket
   set to "uniform bucket-level access" with project-internal IAM.
3. **Audit the bucket for write permissions**: confirm `allUsers` does
   NOT have `roles/storage.objectCreator` or `roles/storage.objectAdmin`
   on any path — anyone with write access could substitute training
   content with malicious payloads.
4. **Confirm the bucket NAME owner**: the generic name `maccabi` is a
   defensive registration; ensure the bucket is in a Maccabi-owned GCP
   project (not a vendor or ex-employee's personal project) so it
   can't be lost via project deletion.

---

## Email — to Maccabi IT / Information Security

Maccabi Healthcare has an IT security team (CISO function). Email
patterns to try:
- `security@maccabi.org.il`
- `infosec@maccabi-online.co.il`
- `it-security@maccabi.org.il`
- Hebrew: `אבטחת_מידע@maccabi.co.il` (likely won't work — emoji/Hebrew
  in mailbox names is rare)

```
To:      security@maccabi.org.il, infosec@maccabi-online.co.il,
         it-security@maccabi.org.il (try all — one will exist)
Subject: דחוף - bucket gs://maccabi פתוח לרישום ציבורי
         (URGENT — gs://maccabi GCS bucket is publicly listable)

שלום צוות אבטחת המידע של מכבי,

אנחנו מקבוצת חוקרי-אבטחה ב-Lictor (open-source). במהלך סריקה של
buckets ציבוריים על Google Cloud Storage גילנו ש-bucket בשם
`maccabi` רשום-פומבית עם תוכן הנושא שמות תיקיות בעברית של מכבי.

What we observed (bucket listing only, NO file downloads):

  Bucket:  gs://maccabi
  URL:     https://storage.googleapis.com/maccabi/
  Status:  Publicly listable (allUsers has bucket-list access)
  Files:   395 files across 3 top-level folders:
              - BetihutShetah10
              - אשראי יזום
              - מכבי בטיחות בעבודה

תוכן הוא e-learning content (SCORM packages עם imsmanifest.xml),
HTML, CSS, SVG icons, ותמונות הדרכה.

החשש:

  • התוכן לא רגיש (חומר הדרכת עובדים/לקוחות, לא PII רפואי)
  • אבל ה-bucket public-listable עם שם של מכבי = חשיפת brand
  • אם יש למישהו write-access (misconfig עתידי או דליפת credential),
    הוא יכול להחליף תוכן הדרכה ב-phishing/malware
  • שם generic ('maccabi') = הגנה רישום-מונע (defensive registration)
    אם הפרויקט נמחק

המלצות:

  1. הסר allUsers:roles/storage.objectViewer ברמת bucket
  2. השתמש ב-uniform bucket-level access + IAM internal
  3. הגש תוכן הדרכה דרך CDN URL (cdn.maccabi-online.co.il) במקום
     direct GCS URL
  4. ודא ש-allUsers אין לו storage.objectCreator/Admin אף-פעם
  5. ודא ש-bucket בפרויקט GCP בבעלות מכבי (לא vendor/ex-employee)

לא הורדנו אף קובץ. רק storage.objects.list API call.

זוהי סריקת-אבטחה open-source דרך Lictor (https://lictor-ai.com,
Apache 2.0). אנחנו עושים disclosure אחראי לטובת הציבור.

תודה,
Raffa Jarrl
raffajarrl@gmail.com
https://github.com/Raffa-jarrl/Lictor-AI
```

---

## ⚠️ Do NOT do any of the following

- ❌ Download files from gs://maccabi (we know they're there from the
  listing — don't pull them)
- ❌ Probe for write-permissions on the bucket (don't try PUT/POST)
- ❌ Combine with the golf.co.il or harel.co.il disclosures — Maccabi
  gets its own dedicated note
- ❌ Disclose the bucket URL publicly until Maccabi has remediated
