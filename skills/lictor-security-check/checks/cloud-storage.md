# Check — Public cloud storage (open buckets)

**What you're looking for:** Cloud storage buckets — Amazon S3, Google Cloud Storage, Azure Blob, Firebase Storage, Supabase Storage — that are set to "anyone on the internet can read" (or worse, "anyone can write"). The classic version: your app uploads user files (profile photos, invoices, ID scans, CSV exports) to a bucket that the AI helpfully made public "so the images would load." Now every file anyone ever uploaded is one URL-guess away from a stranger.

This shows up two ways in a repo: as **infrastructure code** (Terraform, CDK, `serverless.yml`, gcloud/aws CLI scripts that create the bucket) and as **access rules** (Firebase Storage rules, Supabase Storage policies). Both are worth catching before launch.

## How to scan

Buckets get configured in IaC files, deploy scripts, and rules files. Cast a wide net across stacks — people build with anything.

```bash
# Terraform — public S3 ACL / public access block disabled
grep -rEn --include='*.tf' --exclude-dir={node_modules,.terraform} \
  -E 'acl\s*=\s*"public-read(-write)?"|block_public_(acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false|ignore_public_acls\s*=\s*false' \
  . 2>/dev/null

# Terraform — a bucket policy that allows "*" (everyone)
grep -rEn --include='*.tf' --include='*.json' --exclude-dir={node_modules,.terraform} \
  -E '"Principal"\s*:\s*"\*"|"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"|allUsers|allAuthenticatedUsers' \
  . 2>/dev/null

# AWS CDK / Pulumi (TS/Python) — public-read buckets
grep -rEn --include='*.ts' --include='*.js' --include='*.py' --exclude-dir={node_modules,cdk.out} \
  -E 'publicReadAccess\s*:\s*true|PUBLIC_READ|BlockPublicAccess\.(NONE|none)|public_read_access\s*=\s*True' \
  . 2>/dev/null

# serverless.yml / SAM / CloudFormation YAML
grep -rEn --include='*.yml' --include='*.yaml' --include='*.json' --exclude-dir=node_modules \
  -E 'AccessControl:\s*Public(Read|ReadWrite)|PublicAccessBlockConfiguration|BucketPolicy' \
  . 2>/dev/null

# Raw CLI / shell deploy scripts (aws s3, gsutil, az)
grep -rEn --include='*.sh' --include='*.bash' \
  -E 'aws s3 .*--acl public-read|s3api put-bucket-acl|gsutil (iam ch|acl ch).*allUsers|gsutil .*-a public-read|az storage container .*--public-access (blob|container)' \
  . 2>/dev/null

# Firebase Storage rules — wide-open read/write
grep -rEn --include='storage.rules' --include='*.rules' \
  -E 'allow (read|write|read, write)\s*:\s*if\s+true|allow (read|write)\s*;' \
  . 2>/dev/null

# Supabase — a bucket created with public: true, or an "allow all" storage policy
grep -rEn --include='*.ts' --include='*.js' --include='*.sql' --exclude-dir=node_modules \
  -E "createBucket\([^)]*public\s*:\s*true|public\s*:\s*true|storage\.objects.*USING\s*\(true\)|bucket_id\s*=\s*'[^']+'\s*\)\s*;?\s*--?\s*public" \
  . 2>/dev/null
```

Also worth a quick look — the dashboards leave a trail in the repo:
- A `firebase.json` that points to a `storage.rules` file → open that rules file.
- A `supabase/migrations/*.sql` file with `insert into storage.buckets ... 'public', true` → that bucket is world-readable.
- A `.tf`/`cdk`/`serverless.yml` that mentions `bucket`, `Storage`, `Blob` → read it.

## The dangerous patterns

**Pattern 1: public-read S3 bucket in Terraform (MEDIUM → HIGH if it holds user data)**

```hcl
resource "aws_s3_bucket" "uploads" {
  bucket = "myapp-user-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read"          # ← every object readable by anyone
}

# or the modern footgun — turning OFF the safety net:
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = false   # ← all four of these
  block_public_policy     = false   # ← should be true
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```

If that bucket stores anything a user uploaded, this is the whole breach. HIGH severity when the bucket name or surrounding code suggests user content (`uploads`, `documents`, `avatars`, `invoices`, `exports`). MEDIUM if it's genuinely public assets (see "Don't false-positive on").

**Pattern 2: a bucket policy that names `"*"` as the Principal (HIGH)**

```json
{
  "Effect": "Allow",
  "Principal": "*",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::myapp-user-uploads/*"
}
```

`"Principal": "*"` means "anybody, no credentials." Same story on GCS — granting `allUsers` or `allAuthenticatedUsers` the `objectViewer` role makes the bucket public (`allAuthenticatedUsers` means *any Google account on earth*, not just your users — a common trap).

**Pattern 3: public-WRITE — the bad one (CRITICAL)**

```hcl
acl = "public-read-write"
```
```bash
gsutil iam ch allUsers:objectAdmin gs://myapp-uploads
az storage container create -n files --public-access container
```

Public *read* leaks your data. Public *write* hands strangers your storage bill and a place to host malware, phishing pages, or illegal content under your domain. People scan for these and dump warez into them within hours. CRITICAL.

**Pattern 4: Firebase Storage rules left wide open (CRITICAL if write, HIGH if read)**

```javascript
// storage.rules — the Firebase default that everybody forgets to change
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if true;        // ← anyone, anywhere, any file
    }
  }
}
```

`if true` (or `allow read, write;` with no condition) means no login required to read or upload anything. This is the single most common Firebase mistake in vibe-coded apps — the AI scaffolds it open so uploads "just work," and it ships that way.

**Pattern 5: Supabase Storage bucket marked public, or an "allow everything" policy (HIGH)**

```ts
// app code
await supabase.storage.createBucket('documents', { public: true }); // ← world-readable
```
```sql
-- migration: a Row Level Security policy that lets anyone touch any object
create policy "anyone" on storage.objects
  for select using ( true );           -- ← no check at all
```

A `public: true` Supabase bucket serves every object over an unguessable-but-not-secret CDN URL with no auth. Fine for a logo; not fine for `documents`, `kyc`, `receipts`.

## Safe patterns

**Private bucket, presigned URLs for the moments you actually need to share** — this is the pattern you want for user content:

```hcl
# Terraform — locked down, the safe default
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

```ts
// Your app hands out short-lived links instead of making the bucket public
const url = await getSignedUrl(s3, new GetObjectCommand({
  Bucket: "myapp-user-uploads",
  Key: `users/${session.userId}/${fileId}`,
}), { expiresIn: 300 }); // link dies in 5 minutes, scoped to one file
```

**Firebase Storage — gate on the logged-in user owning the path:**

```javascript
match /users/{userId}/{allPaths=**} {
  allow read, write: if request.auth != null && request.auth.uid == userId;
}
```

**Supabase — private bucket + a policy scoped to the owner:**

```ts
await supabase.storage.createBucket('documents', { public: false });
```
```sql
create policy "owner reads own files" on storage.objects
  for select using ( auth.uid() = owner );
```

## Report a finding as

**Title:** "Your file storage is open to the whole internet"

(use this when the bucket holds user content; soften to "...is public" for genuinely-public asset buckets)

**Detail:**
> `storage.rules:6` (or `infra/s3.tf:12`, wherever you found it) makes your file storage readable — and in your case writable — by anyone on the internet, no login required. Right now the rule says `allow read, write: if true`, which is the open-by-default version the AI scaffolds so uploads work during development. It never got tightened before launch.
>
> Files in this bucket are served from URLs like `https://...storage.../users/abc123/passport.jpg`. Those URLs aren't secret-protected — they're just hard to guess. "Hard to guess" stops your grandmother. It does not stop someone running a scanner against your storage, and public buckets get scanned constantly.
>
> **What can go wrong:** Two flavors. *Read-open:* every invoice, ID scan, and profile photo your users ever uploaded is downloadable by a stranger — and there are bots that crawl public buckets all day looking for exactly this. *Write-open* (your case) is worse: a stranger can upload their own files into your storage. That means your AWS bill becomes their free file host, and your domain becomes the place they park malware or a phishing page. People find write-open buckets within hours and they do not leave them empty.
>
> **What to do tonight:**
> 1. **Close it first, ask questions later.** For Firebase, change the rule to require the logged-in user to own the path:
>    ```javascript
>    match /users/{userId}/{allPaths=**} {
>      allow read, write: if request.auth != null
>                         && request.auth.uid == userId;
>    }
>    ```
>    then `firebase deploy --only storage`.
>    For S3/Terraform, set all four `block_public_*` to `true` and re-apply.
>    For Supabase, flip the bucket to `public: false` in the dashboard (Storage → your bucket → Settings) and add an owner-scoped policy.
> 2. **Hand out files with short-lived signed links instead of going public.** Your app generates a URL that works for 5 minutes and only for that one file (see the `getSignedUrl` snippet in the safe-patterns section). The bucket stays private; the user still sees their photo.
> 3. **If it was write-open, check what's already in there.** List the bucket and look for files your app didn't put there — unfamiliar names, `.html`, `.exe`, oversized junk. Delete anything you didn't create. If you find a phishing page, that's a notify-your-provider situation.
> 4. **Verify after deploy:** open one of your file URLs in a private/incognito window where you're logged out. It should say Access Denied (403), not show you the file.

Repeat the report block for each open bucket / rules file you found.

## Don't false-positive on

This check is easy to over-fire. Public buckets are sometimes exactly right. Don't cry wolf on:

- **Buckets that are public *on purpose* and hold only public assets** — a static-site bucket, a CDN origin for `/public/` images, marketing screenshots, blog hero images, downloadable open-source releases, a `favicon`. Public-read is the *correct* setting here. Note it as ⚪ INFO at most, and only if the name/contents are unclear. The tell: bucket names like `cdn`, `assets`, `static`, `public`, `website`, `media-public`.
- **CloudFront / Cloudflare / CDN in front of the bucket.** A common safe setup is a *private* bucket fronted by a CDN with Origin Access Control, where the bucket policy grants access to the CDN service principal — not `"*"`. If the `Principal` is a CloudFront OAC ARN or `cloudfront.amazonaws.com`, that's **not** public. Read the whole policy before flagging.
- **Public *read* of a single, intentionally-shared object** — e.g. a `terms.pdf` or an app icon. Severity LOW/INFO, not HIGH.
- **`block_public_*` set to `false` on a bucket that has no objects and no policy granting public access** — the access block being off is a weaker safety net, but it's not itself a leak. Flag as 🔵 LOW ("your safety net is off") rather than CRITICAL, unless there's also a `"*"` policy or public ACL.
- **Firebase `allow read: if true` on a path that genuinely serves public content** (e.g. `match /public/{file}`) — read-only, public-by-design path. Lower the severity and say why. Still flag `write: if true` regardless of path — public write is almost never intended.
- **Supabase `public: true` on an `avatars`/`logos`/`public-assets` bucket** where that's the documented Supabase quickstart pattern and the files are non-sensitive. The risk lives in *sensitive* public buckets (`documents`, `kyc`, `invoices`), not every public bucket.
- **Example/template/docs files** — `*.example.tf`, `terraform.tfvars.example`, README snippets, `examples/` folders. These aren't deployed. Skip them.
- **Local-dev emulator config** — `firebase emulators` rules, `localstack`, MinIO dev setups, `*.local.tf`. Only flag what ships to production.

When in doubt, the deciding question is: **"does this bucket hold something a user uploaded or something private, and can a logged-out stranger read or write it?"** If yes → flag it. If it's genuinely public marketing assets → at most an INFO heads-up.
