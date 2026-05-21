# Disclosure 5 of 5 — Google Cloud Storage abuse report (URGENT — 58 GB exposure)

**Target:** `gs://atlassian-backup` (publicly listable)
**Provider:** Google Cloud Storage (storage.googleapis.com)
**Owner:** Unknown self-hosted Atlassian customer (bucket name typo "atlassain")
**Action:** Email Google Cloud abuse + Atlassian security in parallel

---

## Email to Google Cloud Abuse

To: `cloud-abuse@google.com`
CC: `security@google.com`

Subject:
```
Publicly listable GCS bucket gs://atlassian-backup leaking ~58 GB of database backups
```

Body:
```
Hello,

A publicly-listable Google Cloud Storage bucket appears to be leaking
customer database backups for self-hosted Atlassian software
(Bitbucket / Confluence / Jira / Postgres):

  Bucket:   gs://atlassian-backup
  URL:      https://storage.googleapis.com/atlassian-backup/
  Listable: YES (no auth required to list contents)

Sample contents observed (via list-only, NO files downloaded):

  atlassain_bitbucket_backup_20240821.sql        ~1.87 GB
  atlassain_bitbucket_backup_20240826.sql        ~1.87 GB
  atlassain_confluence_backup_20240821.sql      ~26.94 GB
  atlassain_confluence_backup_20240822.sql      ~27.19 GB
  atlassain_jira_backup_20240821.sql             ~1.04 GB
  atlassain_jira_backup_20240826.sql             ~1.04 GB
  atlassain_jira_backup_20240827.sql             ~1.87 GB
  atlassain_postgres_backup_20240821.sql         ~3.4 KB
  (truncated — more files exist beyond first 8)

Note the bucket name typo "atlassain" (vs "atlassian") — this strongly
suggests the bucket owner is NOT Atlassian Corporation but an
Atlassian customer who self-hosts the suite and misspelled the
bucket name when creating it. The typo also means standard GCP
abuse-tools targeting "atlassian*" bucket patterns may have missed it.

Confluence database backups in particular typically contain:
  - All internal company documentation (likely credentials, partner
    contracts, customer PII)
  - Wiki pages with engineering runbooks
  - Often, embedded API keys / tokens in page content

Bitbucket backups contain all source code repositories the customer
self-hosts.

Jira backups contain all tickets — bug reports, feature designs,
customer support escalations, often with PII attached.

Request: please use your bucket-owner contact records to reach the
owner immediately and have them either (a) make the bucket private,
(b) delete the publicly-visible objects, or both. The customer is
likely unaware of the exposure.

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0). No files were downloaded; only the
bucket index was listed to confirm the exposure. The lictor tool is
designed to surface exactly this class of "well-meaning customer
misconfiguration" so it can be responsibly disclosed before being
actively exploited.

Thank you for your prompt attention to this.

---

Reporter: Raffa (raffajarrl@gmail.com)
Tool:     https://github.com/Raffa-jarrl/Lictor-AI
Found via: GCP bucket-name brute scanner against bounty-corpus-adjacent name patterns
```

---

## Email to Atlassian Trust & Safety

To: `security@atlassian.com`
CC: `trust@atlassian.com`

Subject:
```
Self-hosted Atlassian customer's database backups exposed on public GCS — 58 GB
```

Body:
```
Hello Atlassian Trust & Safety,

A Google Cloud Storage bucket containing what appears to be self-hosted
Atlassian suite database backups is publicly listable (and likely
publicly downloadable):

  Bucket:  gs://atlassian-backup
  URL:     https://storage.googleapis.com/atlassian-backup/
  Owner:   Unknown Atlassian customer (typo'd bucket name "atlassain")
  Size:    ~58 GB observed across 8 sample files; more files exist
  Content: bitbucket + confluence + jira + postgres backups, dated 2024-08

Filename pattern:
  atlassain_bitbucket_backup_YYYYMMDD.sql
  atlassain_confluence_backup_YYYYMMDD.sql
  atlassain_jira_backup_YYYYMMDD.sql
  atlassain_postgres_backup_YYYYMMDD.sql

The typo "atlassain" (vs "atlassian") in both the bucket name AND the
filenames strongly suggests the owner is NOT Atlassian Corp but an
Atlassian customer who self-hosts the Data Center / Server editions.

I have separately reported this to Google Cloud Abuse
(cloud-abuse@google.com) so they can act on the storage side. I am
reaching out to Atlassian as well because:

  1. The exposure violates self-hosting best practices Atlassian
     publishes for Data Center customers, and your support records
     may help identify the customer for a private disclosure.
  2. Confluence backups in particular have historically been a
     vector for downstream incidents (credentials in page content,
     embedded API keys, customer PII in space contents).
  3. Atlassian's customer relationship is the most polite channel
     to nudge the customer to lock the bucket down.

I have NOT downloaded any files from the bucket. Only the publicly-
accessible directory listing was inspected to confirm the exposure.

Discovered via Lictor (https://lictor-ai.com), an open-source security
scanner (Apache 2.0). Reporting this as a public-good responsible
disclosure with no expectation of bounty.

Please let me know if any additional information would help your
investigation.

Thank you,
Raffa
raffajarrl@gmail.com
```

---

## Important — do NOT do any of the following

- ❌ Download any of the .sql backup files — that's unauthorized data access
- ❌ Try to identify the customer via the file contents
- ❌ Post the bucket URL publicly (until Google/Atlassian have closed the exposure)
- ❌ Mention the exposure on Twitter/HN/Reddit before closure (could attract bad actors)

After Google + Atlassian have confirmed they've reached the owner and the bucket is private:
- ✅ Write a Lictor case study (anonymized) about the find — useful for the open-source community
- ✅ Add the "self-hoster typo bucket" pattern to Lictor's fingerprint database (other Atlassian self-hosters may have similar typo'd buckets)
