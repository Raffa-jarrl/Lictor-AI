# Expedia HackerOne Submission — Publicly-listable GCP bucket `carrentals`

**Submit at:** https://hackerone.com/expediagroup_bbp/reports/new
**Program:** Expedia Group Bug Bounty (paid) · **In-scope:** `*.carrentals.com` and `www.carrentals.com` (Expedia-owned brand)
**Realistic payout:** $100–$500 (INFO disclosure — depends on content sensitivity)

---

## Title
```
Publicly-listable Google Cloud Storage bucket "carrentals" associated with Expedia's carrentals.com brand
```

## Weakness
`CWE-200 Exposure of Sensitive Information to an Unauthorized Actor` (or H1's "Information Disclosure > Sensitive Data Exposure")

## Severity (CVSS:3.1)
**Low–Medium — 4.3**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

## Description (paste into HackerOne form)

```
## Summary

The Google Cloud Storage bucket `carrentals` is publicly listable
without authentication. The bucket name pattern + content age suggest
it belongs to Expedia's carrentals.com brand. The full object listing
is accessible via:

  https://storage.googleapis.com/storage/v1/b/carrentals/o

Listable content includes objects like:
  - `1` (1-byte test file from 2023-06-27)
  - `Malaga/` (directory marker from 2022-06-07)
  - Additional objects (see full listing)

## Steps to reproduce

1. Confirm the bucket is publicly listable:

   $ curl -s "https://storage.googleapis.com/storage/v1/b/carrentals/o?maxResults=20"
   {
     "kind": "storage#objects",
     "items": [
       {"id":"carrentals/1/1687846668120722","name":"1",...},
       {"id":"carrentals/Malaga//1654583425765492","name":"Malaga/",...},
       ...
     ]
   }

2. The response confirms public-read on the `OBJECTS_LIST` permission.
   Each object's `mediaLink` is also accessible without auth.

## Impact

- **Public read on bucket metadata** — anyone can enumerate object
  names, sizes, timestamps, and content types
- **Bucket-name confirms Expedia brand ownership** — `carrentals` is
  a unique Expedia-owned brand name
- **Bucket lifespan since 2022** suggests it's been exposed for years
- **Limited sensitive content visible in current listing** — mostly
  test/directory markers — but bucket being listable means future
  uploads will also be exposed

## Remediation

1. **Remove `allUsers:storage.objectViewer` and
   `allUsers:storage.legacyBucketReader` IAM bindings** if the bucket
   doesn't need public access.
2. If the bucket needs public-read for individual objects, use signed
   URLs instead of bucket-level public listing.
3. Audit other Expedia-brand GCP buckets for the same misconfig
   (run `gsutil ls gs://*-prod*`, `gs://*-staging*` patterns
   internally).

## Tooling

Discovered via Lictor (https://lictor-ai.com) — open-source security
scanner (Apache 2.0). Lictor probes bounty-program apex domains with
24 common bucket-name patterns × 3 cloud providers (AWS S3, GCP
Cloud Storage, DigitalOcean Spaces).

## Note

I'm aware this is INFO-level severity. The bucket content appears to
be test data rather than user PII, so I'm flagging it as low-severity
INFO disclosure. Filing because the bucket-name pattern is clearly
Expedia-owned (`carrentals` is an Expedia brand) and it's in-scope per
`*.carrentals.com`.

## References

- CWE-200: Information Exposure
- Sample H1 payouts for similar GCS misconfig: report #1100823, #856291
```
