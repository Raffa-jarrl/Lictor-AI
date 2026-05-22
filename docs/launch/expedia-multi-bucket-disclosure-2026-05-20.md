# Expedia HackerOne Submission — Three publicly-listable cloud storage buckets owned by Expedia brands

**Submit at:** https://hackerone.com/expediagroup_bbp/reports/new
**Program:** Expedia Group Bug Bounty (paid) · **In-scope:** `*.carrentals.com`, `*.expedia.com`, `*.hotels.com`, and other Expedia brand apex domains (per CSV scope export 2026-05-20)
**Realistic payout:** $500–$1,500 (3× INFO-level disclosures bundled; one bucket has smoking-gun brand attribution)

---

## Title
```
Three publicly-listable cloud storage buckets named for Expedia brands (carrentals / expedia / expedia-images) — bucket-level OBJECTS_LIST permission granted to allUsers
```

## Weakness
`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor` (H1: "Information Disclosure > Sensitive Data Exposure")

## Severity (CVSS:3.1)
**Low–Medium — 5.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

Three cloud storage buckets named for Expedia brands are publicly
listable without authentication. Two are on Google Cloud Storage,
one is on AWS S3. All three return full object listings to
unauthenticated `LIST` requests.

Smoking-gun attribution evidence: object keys inside the AWS S3
`expedia` bucket include filenames such as `expedia_profile.jpg`,
`expedia_comingsoon.swf`, `expedia_header.swf`, `expedia_whosnext.jpg`
— the literal substring "expedia_" embedded in stored object names.

The `carrentals` GCP bucket contains an HTML file at the key
`Malaga/rent-a-car-in-malaga-airport.html`, which is a
CarRentals.com landing page about renting cars at Malaga Airport.

## Bucket 1 — AWS S3 `expedia` (strongest attribution)

  URL:           https://expedia.s3.amazonaws.com/
  Listable:      yes (XML ListBucketResult)
  Created:       ~2007 (based on LastModified timestamps)
  Contents:      "Who's Next" campaign assets — featured-traveler
                 photo/video/blog flash widgets

Sample object keys (HTTP 200 on LIST as of 2026-05-20 01:10 UTC):

  1_sarah/expedia_profile.jpg
  1_sarah/439x139_sarah_blogs.swf
  1_sarah/439x39_sarah_pic_vid_blog.swf
  1_sarah/map.swf
  2_cheryl/expedia_comingsoon.swf
  2_cheryl/expedia_header.swf
  2_cheryl/expedia_map.swf
  2_cheryl/expedia_whosnext.jpg
  2_cheryl/expedia_profile.jpg
  3_halicue/439x139_halicue_blogs.swf
  ...

Attribution rationale: filenames containing literal "expedia_" plus
the "Who's Next" / featured-traveler concept (Expedia's 2007
"Why I Travel"–era brand campaign) make this an unambiguous Expedia
asset rather than an unrelated coincidentally-named bucket.

## Bucket 2 — GCP Storage `carrentals`

  URL:           https://storage.googleapis.com/storage/v1/b/carrentals/o
  Listable:      yes (JSON storage#objects response)
  Created:       2022-06-07 (first object)

Sample object keys:

  1                                              (1-byte test file, 2023-06-27)
  Malaga/                                        (directory marker)
  Malaga/rent-a-car-in-malaga-airport.html       (CarRentals.com page content)

Attribution rationale: bucket name "carrentals" plus the
HTML key path `Malaga/rent-a-car-in-malaga-airport.html` (a
CarRentals.com SEO landing page) → CarRentals.com (Expedia brand).

## Bucket 3 — GCP Storage `expedia-images`

  URL:           https://storage.googleapis.com/storage/v1/b/expedia-images/o
  Listable:      yes (JSON storage#objects response)
  Created:       2021-07-13
  Project number: 528272295699

Sample object keys (hotel image CDN structure):

  hotels/AT/228335146-5eefc55e_z.jpg   (76,001 bytes)
  hotels/AT/228335147-39c8d3c0_z.jpg   (95,698 bytes)
  hotels/AT/228335147-6dc5613c_z.jpg   (91,102 bytes)
  hotels/AT/228335148-0cd25573_z.jpg   (71,046 bytes)
  ...

The `hotels/{country}/{hotel_id}-{etag}_z.jpg` path structure and
`_z` size suffix match the convention used across Expedia Group
hotel-image infrastructure. Bucket name + path pattern strongly
suggest Expedia-owned. (If Expedia disclaims ownership of this
bucket, please close this finding as out-of-scope — but for the
other two the attribution is unambiguous.)

## Steps to reproduce

  $ curl -sI "https://expedia.s3.amazonaws.com/?max-keys=5"
  HTTP/2 200
  Content-Type: application/xml

  $ curl -sI "https://storage.googleapis.com/storage/v1/b/carrentals/o?maxResults=5"
  HTTP/2 200
  Content-Type: application/json

  $ curl -sI "https://storage.googleapis.com/storage/v1/b/expedia-images/o?maxResults=5"
  HTTP/2 200
  Content-Type: application/json

All three return full object listings to anonymous requests, no
auth required.

## Impact

Per bucket:

- **`expedia` S3** — historical brand assets exposed (Expedia
  "Who's Next" 2007 campaign). Low direct PII risk because content
  is .swf/.jpg/.gif marketing creative, but: (a) the bucket being
  listable means any objects added to it would also be enumerable,
  (b) the bucket has been exposed for ~19 years without remediation,
  (c) it confirms an attacker-visible Expedia-owned bucket they can
  monitor for new uploads.

- **`carrentals` GCP** — minimal current content (test file +
  directory marker + one SEO page), but bucket-level public-LIST
  permission means any future uploads will be exposed.

- **`expedia-images` GCP** — currently contains what appear to be
  hotel images. If this is production image storage rather than a
  test bucket, attackers can enumerate every hotel image ID and
  potentially correlate with internal hotel-management data.

Common to all three:

- **Public read on bucket metadata** — anyone can enumerate object
  names, sizes, timestamps, content types
- **Long exposure window** — buckets created 2007 / 2021 / 2022
  respectively, all still listable today

## Remediation

1. For each bucket, remove the public-LIST IAM bindings:
   - S3: remove `s3:ListBucket` from the bucket policy for principal
     `*` / `Everyone`
   - GCS: remove `allUsers:storage.objectViewer` and
     `allUsers:storage.legacyBucketReader` bindings on the bucket
2. If individual objects need public-read for legitimate use
   (image hosting, etc.), keep object-level public-read but disable
   bucket-level LIST so the keyspace is not enumerable.
3. Consider auditing other Expedia-brand cloud buckets for the
   same misconfig. Patterns worth checking internally:
     gs://hotels-*  gs://*-prod  gs://*-staging
     s3://hotels-*  s3://expedia-*  s3://*-vrbo-*

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor's cloud-blob patrol probes bounty-program
apex domains with 24 common bucket-name patterns × 3 cloud providers
(AWS S3, GCP Cloud Storage, DigitalOcean Spaces), then verifies
attribution by inspecting object-key content for brand-specific
strings before reporting.

## Note on attribution

This report intentionally separates the three buckets by attribution
confidence:

  Bucket 1 (`expedia` S3)        — unambiguous (object keys contain "expedia_")
  Bucket 2 (`carrentals` GCS)    — strong (CarRentals.com SEO content)
  Bucket 3 (`expedia-images` GCS) — likely (name + image-CDN pattern)

If your team determines `expedia-images` is not Expedia-owned
infrastructure, please close just that portion of the finding. The
first two have evidence directly tying the storage to Expedia brand
content and should not be in doubt.

## References

- CWE-200: Information Exposure
- Sample H1 payouts for similar bucket-LIST misconfig: report
  #1100823, #856291
- AWS docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
- GCS docs: https://cloud.google.com/storage/docs/access-control/making-data-public
```

---

## Internal notes (DO NOT submit)

**Why bundling rather than 3 separate reports:**
- Bundling avoids triple-counting against signal:noise ratio for our
  HackerOne profile (3 INFO reports look weaker than 1 high-effort
  pattern disclosure).
- One PR rather than three reduces triager workload — better for
  triager goodwill on the next submission.
- If even one of the three buckets is closed N/A, the other two
  still pay out from the same report.

**Why we left out the hotels.* buckets:**
- `hotels` S3, `hotels-images` S3 (empty), `hotels` DO Space — all
  have generic names that could belong to non-Expedia operators.
  Including them would weaken the credibility of the strong-attribution
  buckets. Better to file ONE clean report than dilute it.

**Why we left out the hotels-images GCP bucket:**
- Contains `sofitel-legend-old-cataract-aswan-egypt` content. Could
  be Sofitel-owned, hotels.com-owned, or a third-party CDN. Skip.

**Expected outcome:**
- Most likely Triage→Resolved as INFO with $200–$500 payout, OR
- Closed as Informative with no bounty (still gets us reputation
  and "thanks" from Expedia Security team)
- Worst case: Closed N/A if Expedia disclaims all 3 (unlikely given
  the "expedia_*.jpg" filenames in bucket 1)
