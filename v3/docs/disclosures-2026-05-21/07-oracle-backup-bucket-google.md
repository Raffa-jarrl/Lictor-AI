# Disclosure 7 — gcs://oracle-backup 31GB Oracle DB dump (CRITICAL)

**Target:** `gs://oracle-backup` (publicly listable on GCS)
**Provider:** Google Cloud Storage
**Owner:** Unknown Oracle Database customer (generic bucket name + .dmp file)
**File:** `bk20190704.dmp` (~31.1 GB, Oracle Data Pump dump from 2019-07-04)
**Plus:** `cc-daily.log`
**Action:** Google Cloud Abuse FORM + Oracle Trust & Safety

---

## Email A — Google Cloud Abuse Form

Open the form (same as atlassian-backup disclosure):

👉 https://support.google.com/code/contact/cloud_platform_report

Fill in:

| Field | Value |
|---|---|
| Abuse type | "Privacy" or "Hosting leaked/sensitive data" |
| URL of abuse | `https://storage.googleapis.com/oracle-backup/` |
| Your email | `raffajarrl@gmail.com` |
| Description | (paste body below) |

**Body to paste in the form:**

```
Hello,

A publicly-listable Google Cloud Storage bucket contains what appears
to be an Oracle Database dump file (~31.1 GB) plus log files:

  Bucket:   gs://oracle-backup
  URL:      https://storage.googleapis.com/oracle-backup/
  Listable: YES (no auth required to list contents)

Observed contents (via list-only + HEAD, NO files downloaded):

  bk20190704.dmp   ~31.1 GB   created 2019-07-04   (Oracle Data Pump dump,
                                                    multi-part 32-component upload,
                                                    MULTI_REGIONAL storage class)
  cc-daily.log     (additional log file)

The bucket name "oracle-backup" is generic — strongly suggests the owner
is NOT Oracle Corporation but an Oracle DATABASE customer who self-hosts
Oracle DB and named their backup bucket with the generic vendor name.
The .dmp extension is the standard Oracle Data Pump export format,
which typically contains:

  - All tables, indexes, views, stored procedures from the source DB
  - Customer records (PII, financial data, business records)
  - Sometimes: hashed passwords stored in user tables
  - Sometimes: API tokens / credentials stored in app config tables

A 31 GB Oracle Data Pump file represents a substantial production
database — the exposure window has been over 6 years (since 2019-07-04).

Request: please use your bucket-owner contact records to reach the
owner immediately. They should make the bucket private and delete
or relocate the dump file. The customer is likely unaware of the
exposure given how long it has been visible.

Discovered via Lictor (https://lictor-ai.com), an open-source security
scanner under Apache 2.0. No files were downloaded; only the bucket
index + file HEAD response were inspected to confirm the exposure
(size/type/timestamps).

This is the THIRD high-volume exposure found by Lictor's typo-bucket
scanner today, after:
  - gs://atlassian-backup (~58 GB self-hosted Atlassian backups, already
    reported to cloud-abuse + Atlassian on 2026-05-21)
  - s3://splunk-production (.env file in self-hosted Splunk customer's
    production bucket, reported to AWS abuse + Splunk on 2026-05-21)

Pattern: enterprise self-hosters typo-name their backup buckets with
generic vendor names. Lictor's catalog of typo'd patterns now includes
149 vendors after this find.

Thank you for prompt attention.

Reporter: Raffa (raffajarrl@gmail.com)
Tool:     https://github.com/Raffa-jarrl/Lictor-AI
```

---

## Email B — Oracle Trust & Safety

To: `secalert_us@oracle.com`
CC: `incidentreport@oracle.com`

Subject:
```
Publicly listable GCS bucket gs://oracle-backup leaking ~31 GB Oracle DB dump (.dmp file)
```

Body:
```
Hello Oracle Security Alert Team,

A Google Cloud Storage bucket containing an Oracle Data Pump dump file
(~31.1 GB) is publicly listable and likely publicly downloadable:

  Bucket:   gs://oracle-backup
  URL:      https://storage.googleapis.com/oracle-backup/
  File:     bk20190704.dmp (~31.1 GB, Oracle Data Pump format)
  Created:  2019-07-04 (exposed for 6+ years)
  Plus:     cc-daily.log

The bucket name "oracle-backup" is generic — strongly suggests an Oracle
Database CUSTOMER (not Oracle Corp) who self-hosts Oracle DB and named
their backup bucket with the generic vendor name. The customer may not
realize the bucket is publicly accessible.

I have separately reported this to Google Cloud Abuse so they can act
on the storage side. I am reaching out to Oracle as well because:

  1. The exposure violates Oracle's database security best practices
     that Oracle publishes for self-hosting customers.
  2. Oracle's customer support records may help identify this customer
     for a private disclosure.
  3. Oracle Data Pump dumps have historically been a vector for major
     downstream incidents (credentials in user tables, customer PII,
     stored procedures with embedded secrets).
  4. Oracle's brand benefits from being seen to help customers secure
     misconfigured deployments.

I have NOT downloaded the .dmp file or any other content. Only the
publicly-accessible bucket directory listing + a HEAD request on the
file were used to confirm the exposure (size, type, timestamps).

Discovered via Lictor (https://lictor-ai.com), an open-source security
scanner (Apache 2.0). Reporting as a public-good responsible disclosure
with no expectation of bounty.

Please let me know if any additional information would help your
investigation.

Thank you,
Raffa
raffajarrl@gmail.com
```

---

## ⚠️ Do NOT do any of the following

- ❌ Download the .dmp file (31 GB of unauthorized data access)
- ❌ Try to identify the customer via the file contents
- ❌ Post the bucket URL publicly until Google + Oracle have closed it
- ❌ Open the cc-daily.log either (may contain access patterns / credentials)
