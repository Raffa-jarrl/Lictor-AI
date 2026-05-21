# Disclosure 6 of 6 — splunk-production S3 bucket with .env exposed (CRITICAL)

**Target:** `s3://splunk-production` (publicly listable)
**Provider:** AWS S3
**Owner:** Unknown Splunk customer or independent project (typo'd / generic bucket name)
**Sample file detected:** `.env` (environment variables file — likely contains credentials)
**Action:** Email AWS Trust & Safety + Splunk security in parallel — URGENT

---

## Why this is critical

A publicly-listable `.env` file in a production bucket means an attacker can download environment variables. `.env` files typically contain:
- Database credentials (Postgres / MongoDB / Redis connection strings with passwords)
- AWS keys (often AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
- 3rd-party API keys (Stripe, Twilio, SendGrid, etc.)
- Internal service tokens
- Often: Splunk's own HEC (HTTP Event Collector) tokens or admin credentials

Combined with the bucket name pattern `splunk-production`, this is a self-hosted Splunk customer's production environment — leaking the keys to their entire infrastructure.

---

## Email to AWS Trust & Safety

To: `aws-security@amazon.com`
CC: `trustandsafety@amazon.com`

Subject:
```
Publicly listable S3 bucket s3://splunk-production with .env file exposed
```

Body:
```
Hello,

A publicly-listable AWS S3 bucket contains a .env file in its root,
likely exposing production environment credentials:

  Bucket:   s3://splunk-production
  URL:      https://splunk-production.s3.amazonaws.com/
  Listable: YES (no auth required to list contents)
  First detected file: .env (path: /env)

The bucket name suggests a self-hosted Splunk customer's production
environment. .env files typically contain database credentials, AWS
keys, third-party API tokens, and internal service credentials.

I have NOT downloaded the .env file itself — only the publicly-
accessible bucket index was inspected to confirm the exposure.

Request: please use your bucket-owner records to identify and reach
the owner immediately. They should either (a) make the bucket
private, (b) delete the publicly-visible objects, or both. The
customer may be unaware of the exposure.

Discovered via Lictor (https://lictor-ai.com), an open-source
security scanner (Apache 2.0). Reporting as public-good
responsible disclosure with no expectation of bounty.

Thank you for your prompt attention.

Reporter: Raffa (raffajarrl@gmail.com)
```

---

## Email to Splunk Trust & Safety

To: `security@splunk.com`

Subject:
```
Publicly listable AWS S3 bucket named "splunk-production" with .env file exposed
```

Body:
```
Hello Splunk Security Team,

A publicly-listable AWS S3 bucket is exposing what appears to be a
self-hosted Splunk customer's production environment:

  Bucket:   s3://splunk-production
  URL:      https://splunk-production.s3.amazonaws.com/
  Listable: YES
  Sample file: .env (environment variables file in bucket root)

The bucket name strongly suggests an enterprise Splunk customer's
production environment. .env files in this context typically contain:
  - Splunk HEC (HTTP Event Collector) tokens
  - Splunk admin credentials
  - The customer's broader infrastructure credentials (AWS, DB, etc.)

I have separately reported this to AWS Trust & Safety
(aws-security@amazon.com) so they can act on the storage side. I'm
reaching out to Splunk as well because:

  1. The exposure violates Splunk's self-hosting best practices.
  2. Your customer relationship records may help identify the
     customer for a private disclosure.
  3. Splunk's brand reputation benefits from proactively helping
     customers secure misconfigured deployments.

I have NOT downloaded the .env file. Only the bucket's publicly-
accessible directory listing was inspected to confirm the exposure.

Discovered via Lictor (https://lictor-ai.com), an open-source security
scanner (Apache 2.0). Reporting as a public-good responsible
disclosure with no expectation of bounty.

Please let me know if any additional information would help your
investigation.

Thank you,
Raffa
raffajarrl@gmail.com
```

---

## Two MORE typo-bucket findings (lower urgency)

### Bucket: `s3://prometeus` (AWS S3)
- Typo of "prometheus" (Prometheus monitoring system)
- Contains `img/` directory — likely a Prometheus customer's image assets bucket
- Lower urgency (no credentials visible) but still public-good worth disclosing to Prometheus + AWS

### Bucket: `gs://redis` (GCS)
- No typo — literally named "redis"
- Contains a JSON file `03_05_19.json`
- Could be a Redis user's data export OR a generic "redis" project bucket
- Needs ownership verification before disclosure

Both can wait until splunk-production + atlassian-backup are handled.
