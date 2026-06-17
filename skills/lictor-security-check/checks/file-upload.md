# Check — Insecure file upload

**What you're looking for:** Anywhere your app lets a user upload a file — a profile picture, a CSV import, a PDF, an attachment — and then trusts that file too much. The four ways this goes wrong: (1) you never check the file's type or size, (2) you build the saved path out of the user's filename, (3) you save uploads into a folder your web server hands out to the public — so someone uploads a `.html` or `.php` file and now it runs on your domain, and (4) you hand out "upload straight to my cloud bucket" links that aren't locked down, so anyone can dump anything into your storage.

A file upload feels innocent. It's the part of the app where you hand a stranger a pen and a blank page in your own notebook. The question this check answers is: *how blank, and how much of your notebook?*

## How to scan

Upload handling shows up in route handlers, form parsers, and storage SDK calls. Find the upload entry points first, then read what they do with the file.

```bash
# JS / TS — multer, formidable, busboy, Next.js formData, file writes
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' --exclude-dir={node_modules,.next,dist,build} \
  'multer|formidable|busboy|\.formData\(\)|formData\.get|writeFile|createWriteStream|fs\.(write|append)|\.mv\(|express-fileupload' \
  . 2>/dev/null | head -40

# JS / TS — direct-to-bucket presigned uploads (the unsigned/over-broad kind)
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist,build} \
  'getSignedUrl|createPresignedPost|PutObjectCommand|presigned|createSignedUploadUrl|\.upload\(' \
  . 2>/dev/null | head -40

# Python — Flask/Django/FastAPI uploads + path joins on filenames
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  'request\.files|UploadFile|FileField|ImageField|save\(|os\.path\.join|shutil\.copyfileobj|werkzeug' \
  . 2>/dev/null | head -40

# Go — multipart form reads and file creation
grep -rEn --include='*.go' \
  'FormFile|MultipartForm|ParseMultipartForm|os\.Create|io\.Copy|filepath\.Join' \
  . 2>/dev/null | head -40

# Ruby (Rails / Sinatra) — uploads + send_file
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  'params\[:file\]|ActiveStorage|CarrierWave|Shrine|File\.(open|write)|send_file|tempfile' \
  . 2>/dev/null | head -40

# PHP — the classic $_FILES + move_uploaded_file
grep -rEn --include='*.php' --exclude-dir={vendor} \
  '\$_FILES|move_uploaded_file|file_put_contents|fwrite|UploadedFile' \
  . 2>/dev/null | head -40

# Mobile — Swift / Kotlin / Flutter / React Native uploads
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.tsx' --include='*.jsx' --exclude-dir={node_modules,Pods,build,.gradle} \
  'UIImagePicker|PHPicker|multipart|MultipartBody|ImagePicker|image_picker|file_picker|expo-image-picker|FormData|uploadTask' \
  . 2>/dev/null | head -40
```

Then look at where the bytes land:

```bash
# Is there an upload folder INSIDE the public/static web root? That's the danger zone.
find . -path ./node_modules -prune -o \
  \( -type d \( -name 'uploads' -o -name 'public' -o -name 'static' -o -name 'media' -o -name 'www' \) \) -print 2>/dev/null
```

## The dangerous patterns

**Pattern 1: no type or size limit — anything, any size**

```ts
// Next.js route — accepts whatever, writes it straight to disk
const file = (await req.formData()).get("file") as File;
const bytes = Buffer.from(await file.arrayBuffer());
await fs.writeFile(`./uploads/${file.name}`, bytes);   // ← no type check, no size cap, raw name
```

No `file.type` allowlist means someone uploads an executable, a 4GB file that fills your disk, or an SVG full of JavaScript. No size cap is a one-click denial-of-service. MEDIUM on its own, HIGH the moment that folder is served publicly (see Pattern 3).

**Pattern 2: path traversal via the filename (REAL VULNERABILITY)**

```python
# Flask — the user's filename is glued straight into the path
f = request.files["file"]
f.save(os.path.join(UPLOAD_DIR, f.filename))   # ← filename = "../../app/config.py"
```

The browser doesn't have to send a clean filename. An attacker sends `../../../../etc/cron.d/evil` or `../app/routes/auth.py` as the filename, and your `os.path.join` happily walks out of the upload folder and overwrites a real file. Now they can plant a script, clobber your config, or drop a file the server later executes. HIGH severity — CRITICAL if the destination can lead to code running.

**Pattern 3: executable / HTML upload into a served directory (RCE or stored XSS)**

```php
// PHP — moves the upload into the public web root, keeps the original extension
move_uploaded_file($_FILES["avatar"]["tmp_name"], "public/uploads/" . $_FILES["avatar"]["name"]);
// attacker uploads "shell.php" → then visits yoursite.com/uploads/shell.php → their code runs as you
```

```ts
// Same shape in Node: writing user files into Next.js /public or Express static dir
await fs.writeFile(`./public/uploads/${file.name}`, bytes);
// attacker uploads "x.html" with a <script> → yoursite.com/uploads/x.html runs JS on YOUR domain
```

This is the worst one. On a server that runs PHP/JSP/etc., an uploaded script *executes* — that's remote code execution, full server takeover. On a static host, an uploaded `.html` or `.svg` runs JavaScript *on your own domain*, which means it can read your users' cookies and session — stored cross-site scripting (someone injects code that runs in your users' browsers). CRITICAL when the runtime executes the file; HIGH when it "only" serves HTML/SVG.

**Pattern 4: unsigned / over-broad direct-to-bucket uploads**

```ts
// Supabase / S3 — client uploads straight to storage with a public, unrestricted policy
// supabase storage policy: INSERT allowed for role "anon", no path/size/type constraint
await supabase.storage.from("uploads").upload(userFilename, file);   // anyone, any object key
```

```ts
// S3 presigned POST generated with no content-type or size condition
const post = await createPresignedPost(s3, { Bucket, Key: req.query.key }); // ← key fully attacker-chosen
```

"Upload directly to the bucket so it never touches my server" is a great pattern — but only if the signed URL pins the object key, the content type, and a max size. If the policy lets the `anon` role write any key, an attacker can overwrite other users' files, fill your bucket (your bill), or upload an `index.html` that you later serve. HIGH severity.

## Safe patterns

The shape that's actually safe: validate type and size, ignore the user's filename entirely, store outside the web root (or in a bucket served as an attachment), and pin the constraints on presigned uploads.

```ts
import { randomUUID } from "crypto";
import path from "path";

const ALLOWED = new Map([
  ["image/png", "png"],
  ["image/jpeg", "jpg"],
  ["application/pdf", "pdf"],
]);
const MAX_BYTES = 5 * 1024 * 1024; // 5 MB

const file = (await req.formData()).get("file") as File;

// 1. size cap
if (file.size > MAX_BYTES) return new Response("File too large", { status: 413 });

// 2. type allowlist (and re-sniff the real bytes server-side; don't trust the browser's label alone)
const ext = ALLOWED.get(file.type);
if (!ext) return new Response("Unsupported file type", { status: 415 });

// 3. throw away the user's filename — generate our own, fixed extension
const safeName = `${randomUUID()}.${ext}`;

// 4. store OUTSIDE the public web root
const dest = path.join("/var/app-data/uploads", safeName); // not ./public, not ./static
await fs.writeFile(dest, Buffer.from(await file.arrayBuffer()));
```

Presigned bucket upload, locked down:

```ts
// S3 presigned POST that pins the key prefix, content type, and size — attacker can't pick the key
const post = await createPresignedPost(s3, {
  Bucket,
  Key: `user-uploads/${userId}/${randomUUID()}`,        // server chooses the key
  Conditions: [
    ["content-length-range", 0, 5 * 1024 * 1024],        // max 5 MB
    ["eq", "$Content-Type", "image/png"],                 // one type only
  ],
  Expires: 60,
});
```

For Supabase: scope the storage policy to the user's own folder and a size/type, e.g. `INSERT` allowed only when `auth.uid()::text = (storage.foldername(name))[1]`, never to the bare `anon` role.

And when you serve user files, send `Content-Disposition: attachment` plus `X-Content-Type-Options: nosniff` so the browser downloads them instead of rendering them on your domain.

## Report a finding as

**Title:** "Anyone can upload a file that runs code on your site"

(use this title when Pattern 3 is present; adapt for the others — e.g. "Uploaded filenames can escape your upload folder" for Pattern 2, "Your direct-to-bucket uploads aren't locked down" for Pattern 4)

**Detail:**
> `app/api/avatar/route.ts:12` takes whatever file a user uploads and writes it into `./public/uploads/` using the original filename. There's no type check, no size limit, and that folder is served by your website. Here's what goes wrong:
>
> 1. An attacker opens your "change profile picture" form.
> 2. Instead of a photo, they upload a file called `pwn.html` containing a `<script>` that steals cookies.
> 3. Your app saves it to `public/uploads/pwn.html`.
> 4. They send your logged-in users a link to `yourapp.com/uploads/pwn.html`. The script runs **on your domain**, so it can read your users' session and act as them. (If your server runs PHP or similar, an uploaded `.php` file runs server code directly — that's full server takeover.)
>
> This is a favorite of automated scanners. A file-upload form with no guards gets probed within days of launch.
>
> **What to do tonight:**
> 1. Allowlist the type and cap the size. Reject anything not on the list:
>    ```ts
>    const ALLOWED = new Map([["image/png","png"],["image/jpeg","jpg"]]);
>    if (file.size > 5_000_000) return new Response("Too large", { status: 413 });
>    const ext = ALLOWED.get(file.type);
>    if (!ext) return new Response("Unsupported type", { status: 415 });
>    ```
> 2. Never reuse the user's filename. Generate your own:
>    ```ts
>    const safeName = `${crypto.randomUUID()}.${ext}`;
>    ```
> 3. Store uploads **outside** `public/` / `static/` — somewhere your web server doesn't auto-serve. Hand them back through your own route that checks who's asking and sends `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`.
> 4. Verify after deploy: try uploading a tiny `test.html` file. It should be rejected (415), and `yourapp.com/uploads/test.html` should 404.

Repeat the report block for each upload entry point that's affected.

## Don't false-positive on

- **Uploads that already validate type AND size AND use a server-generated filename AND store outside the web root.** If all four guards are present, this is the correct pattern — note as INFO at most, not a finding. Don't nag a developer who did it right.
- **A pure client-side `accept="image/png"` on an `<input>` with the *server* also validating.** The HTML `accept` attribute is just a file-picker hint and proves nothing on its own — but if the server-side check exists too, the upload is fine. Only flag if the server does no check.
- **Trusted-admin-only import tools.** A CSV importer behind a verified admin/role gate (see the auth check) that writes to a temp dir it parses and deletes is lower risk. Mention it, but don't rate it CRITICAL — the threat model is different when only your own staff can reach it.
- **Managed upload widgets that handle validation for you** — Uploadthing, Cloudinary's signed widget, `next-cloudinary`, Vercel Blob with `@vercel/blob/client` and a server-side `onUploadCompleted` token check. These pin type/size/key for you; confirm the server-side handler exists, then treat as safe.
- **Reading a bundled/static file the developer shipped** (a seed CSV, a fixture, an asset in the repo). That's not a user upload — it's the developer's own file. Not a finding.
- **`os.path.join` / `filepath.Join` on filenames that are already sanitized** — e.g. the code calls `werkzeug.utils.secure_filename(f.filename)` or `path.basename(name)` first, or it ignores the user's name entirely. The join itself isn't the bug; the *unsanitized* name is. Check whether sanitization happens before you flag Pattern 2.
- **Tighten, don't panic, on size-only gaps.** An image upload that checks type and stores safely but forgot a size cap is a real but MEDIUM issue (denial-of-service / disk fill), not a CRITICAL. Rate it for what it is.
