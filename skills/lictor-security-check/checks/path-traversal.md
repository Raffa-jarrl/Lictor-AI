# Check — Path traversal (arbitrary file read / serve)

**What you're looking for:** anywhere your app takes a piece of a request — a URL parameter, a query string, a route token, a JSON body field — and uses it to decide *which file to read off disk and hand back*. If the user gets to steer the path and nothing forces that path to stay inside one folder, they don't just get the file you meant. They send `../../../../etc/passwd`, or `..%2f..%2fapp%2f.env`, or an absolute path like `/etc/shadow`, and your server politely walks up out of your intended folder and reads whatever it wants. Source code. Config with your database password. Other users' uploads. Your `.env`.

There's a sibling check — *Insecure file upload* — that covers the **write** side: a malicious filename escaping your upload folder. This check is the **read/serve** side: a malicious path escaping your "serve a file" handler. They're two doors into the same hallway, and an app often has only one of them guarded.

The mental model: a file-download endpoint is you saying "tell me which file and I'll fetch it for you." That's fine *if you keep a fixed list of files you're willing to fetch, or a fixed room you're willing to look in.* The bug is fetching whatever name comes in, from wherever it points, with no fence.

## How to scan

You're reading the repo, not running it. Find the spots where a request value reaches a filesystem read or a file-serving call, then read each hit to confirm the value isn't fenced in first.

```bash
# JS / TS — serve/read a file from a request-derived path
grep -rEn --include='*.ts' --include='*.js' --include='*.tsx' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E 'sendFile|res\.download|createReadStream|readFileSync|readFile|fs\.promises\.readFile|express\.static' \
  . 2>/dev/null | head -40

# Python — Flask/FastAPI/Django file serving + open() for read
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E 'send_file|send_from_directory|FileResponse|open\s*\(|os\.path\.join|pathlib|\.read_(text|bytes)\(' \
  . 2>/dev/null | head -40

# Go — ServeFile / Open / ReadFile from a request path
grep -rEn --include='*.go' \
  -E 'http\.ServeFile|http\.ServeContent|os\.Open|os\.ReadFile|ioutil\.ReadFile|filepath\.Join' \
  . 2>/dev/null | head -40

# Ruby (Rails / Sinatra) — send_file / File.read from params
grep -rEn --include='*.rb' --exclude-dir={vendor} \
  -E 'send_file|send_data|File\.(read|open|binread)|render\s+file:' \
  . 2>/dev/null | head -40

# PHP — the classic: readfile / include / require / fopen on $_GET
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E 'readfile|file_get_contents|fopen|include|include_once|require|require_once|fpassthru' \
  . 2>/dev/null | head -40

# Mobile — Swift / Kotlin / Flutter / React Native: building a file path from input/deep-link
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.tsx' --include='*.jsx' --exclude-dir={node_modules,Pods,build,.gradle} \
  -E 'contentsOfFile|FileManager|FileInputStream|File\(|RandomAccessFile|RNFS|readAsString|getExternalFilesDir|appendingPathComponent' \
  . 2>/dev/null | head -40
```

Then, for each hit, the one question that decides everything: **does a request value flow into that path, and does anything force the result to stay inside one folder before the read happens?** Trace the path argument backwards. If it traces to `req.query` / `req.params` / `req.body` / a route `:param` / `$_GET` / `request.args` / a deep-link parameter — and the only thing between that input and the read is a string concat or a `join` — you have a finding.

## The dangerous patterns

**Pattern 1: request value handed straight to a file-serve call (JS/TS)**

```ts
// Express — "download whatever file you name"
app.get("/download", (req, res) => {
  res.sendFile(path.join("/var/app/files", req.query.name));  // ← name = "../../etc/passwd"
});

// Next.js route handler — same shape with a stream
export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("file")!;
  const stream = fs.createReadStream(`./storage/${name}`);     // ← ../ walks straight out
  return new Response(stream as any);
}
```

`path.join("/var/app/files", "../../etc/passwd")` resolves to `/etc/passwd`. `join` *normalizes* the `../` — it does not *fence* it. The attacker reads any file the server process can read. HIGH severity; CRITICAL if the reachable files include secrets (`.env`, key files) or source.

**Pattern 2: Flask / FastAPI send_file from a request field (Python)**

```python
# Flask — filename comes from the query string, glued into a path
@app.get("/files")
def files():
    name = request.args["name"]
    return send_file(os.path.join(UPLOAD_DIR, name))     # ← name = "../../app/config.py"

# FastAPI — same with FileResponse
@app.get("/doc/{name}")
def doc(name: str):
    return FileResponse(f"docs/{name}")                  # ← name = "../../../etc/passwd"
```

`send_file` will happily serve whatever the resolved path points at. `send_from_directory` is the safer cousin (it's *designed* to fence) — but only when you pass it a single, validated filename, not a path with `../` still in it. HIGH severity.

**Pattern 3: PHP readfile / include on `$_GET` (read OR code execution)**

```php
// readfile — arbitrary file disclosure (LFI)
$f = $_GET['file'];
readfile("/var/www/downloads/" . $f);            // ← ../../../../etc/passwd

// include / require — this is WORSE: the file gets EXECUTED as PHP
include($_GET['page'] . ".php");                  // ← page=../../../../tmp/uploaded_shell%00
```

`readfile` leaks the file's contents. `include`/`require` *runs* it as PHP — if the attacker can point it at any file they control (an uploaded image with PHP inside, a log they poisoned, a remote URL when `allow_url_include` is on), that's remote code execution, full server takeover. CRITICAL for the `include`/`require` shape; HIGH for `readfile`/`file_get_contents`.

**Pattern 4: Go http.ServeFile with a request path (Go)**

```go
func handler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    http.ServeFile(w, r, filepath.Join("/srv/files", name))  // ← filepath.Join does NOT fence
}
```

Go's standard library has a specific footgun here: `http.ServeFile` *does* reject a path if the **request URL** (`r.URL.Path`) literally contains `..` — but it does **not** protect you when you build the path yourself from a query/body value and pass it as the third argument. `filepath.Join("/srv/files", "../../etc/passwd")` cleans to `/etc/passwd` and serves it. HIGH severity.

**Pattern 5: dynamic static-serving rooted at user input**

```ts
// Express — mounting static serving on an attacker-influenced directory
app.use("/assets", express.static(path.join(BASE, req.params.tenant)));  // tenant = "../../"
```

Static middleware is safe when it points at *one fixed directory*. It becomes traversal when the directory itself is built from request input. HIGH severity.

**Pattern 6: mobile — deep link / IPC value into a local file read**

```kotlin
// Android — a path from an Intent extra read straight off disk and returned/displayed
val rel = intent.getStringExtra("path") ?: ""
val text = File(filesDir, rel).readText()        // ← rel = "../../../../data/data/<otherapp>/..."
```

```swift
// iOS — building a path from a URL scheme parameter
let name = url.queryParameter("doc") ?? ""
let path = docsDir.appendingPathComponent(name)  // ← name = "../Library/Preferences/...plist"
let data = FileManager.default.contents(atPath: path)
```

On mobile the blast radius is the app's sandbox (other apps' data is usually protected by the OS), but reading your own app's private files — tokens, cached PII, the SQLite DB — via a crafted deep link is still a real disclosure, especially when the path comes from an exported activity, a `content://`/custom URL scheme, or a WebView bridge. MEDIUM–HIGH depending on what's reachable and whether the entry point is exported.

## Safe patterns

There are three shapes that are actually safe. Pick whichever fits.

**A — Allowlist: map a token to a fixed set of files (the safest by far).** The user never names a path; they name a *key* you control.

```ts
const FILES: Record<string, string> = {
  invoice: "/var/app/files/invoice-template.pdf",
  terms:   "/var/app/files/terms.pdf",
};
const file = FILES[req.query.doc as string];
if (!file) return res.status(404).end();
res.sendFile(file);   // path is one of yours — never the user's
```

**B — basename + fixed root, then verify you stayed inside.** Strip any directory parts off the input, join it to a fixed base, resolve it, and *confirm the result is still under the base*. The resolve-and-check is the part people skip — and it's the part that matters.

```ts
import path from "path";

const BASE = path.resolve("/var/app/files");

function safeResolve(userName: string): string | null {
  // 1. drop any directory components the user tried to sneak in
  const name = path.basename(userName);            // "../../etc/passwd" -> "passwd"
  // 2. join to the fixed root and fully resolve
  const full = path.resolve(BASE, name);
  // 3. PROVE it's still inside BASE (defends edge cases basename alone misses)
  if (full !== BASE && !full.startsWith(BASE + path.sep)) return null;
  return full;
}

const full = safeResolve(String(req.query.name ?? ""));
if (!full) return res.status(400).end();
res.sendFile(full);
```

```python
# Flask — the framework gives you a fenced helper; pass it a basename, not a path
from werkzeug.utils import secure_filename
from flask import send_from_directory

name = secure_filename(request.args["name"])   # strips ../, slashes, NUL
if not name:
    abort(400)
return send_from_directory(UPLOAD_DIR, name)    # send_from_directory re-checks containment
```

```go
// Go — basename then confirm containment with Rel
base := "/srv/files"
clean := filepath.Join(base, filepath.Base(name))      // Base drops ../ segments
rel, err := filepath.Rel(base, clean)
if err != nil || strings.HasPrefix(rel, "..") {
    http.Error(w, "bad path", http.StatusBadRequest)
    return
}
http.ServeFile(w, r, clean)
```

```php
// PHP — basename + realpath containment check, and never include() user input
$name = basename($_GET['file']);                  // drops directory parts
$full = realpath("/var/www/downloads/" . $name);  // resolves symlinks/.. to a real path or false
$base = realpath("/var/www/downloads");
if ($full === false || strncmp($full, $base . DIRECTORY_SEPARATOR, strlen($base) + 1) !== 0) {
    http.response_code(400); exit;
}
readfile($full);
```

**C — decode first, then check.** Attackers send `..%2f`, `..%252f` (double-encoded), backslashes, and embedded NUL bytes specifically to slip past a naive `if (name.includes(".."))` string check. Don't rely on a substring blocklist. Decode the input *once* into its real form, then apply allowlist (A) or basename-and-resolve (B). The resolve-and-verify approach in B is immune to encoding tricks because it checks the *final resolved path*, not the raw string.

## Report a finding as

**Title:** "Anyone can read any file on your server through the download endpoint"

(use this when Patterns 1/2/4 are present; adapt for the others — e.g. "A page parameter can run attacker code (LFI → RCE)" for the PHP `include` case, "A deep link can read your app's private files" for mobile)

**Detail:**
> `src/routes/download.ts:11` takes the `name` value straight from the request's query string and passes `path.join("/var/app/files", name)` to `res.sendFile`. Nothing forces that path to stay inside `/var/app/files`. Here's what goes wrong:
>
> 1. Your endpoint is meant to serve files like `yourapp.com/download?name=report.pdf`.
> 2. An attacker requests `yourapp.com/download?name=../../../../etc/passwd` (or `..%2f..%2f..%2f.env` to slip past simple filters).
> 3. `path.join` *normalizes* the `../` — it doesn't block it — so the path resolves to a file far outside your folder.
> 4. Your server reads it and hands it back. They just downloaded your `.env` (database password, API keys), your source code, or another user's private upload — no login required.
>
> This is CWE-22, on the 2024 CWE Top 25. Automated scanners probe every `?file=`, `?path=`, `?doc=` parameter for exactly this within days of launch.
>
> **What to do tonight:**
> 1. If you serve a small, fixed set of files, switch to an allowlist — the user names a *key*, not a path, and they can never point anywhere you didn't choose:
>    ```ts
>    const FILES = { report: "/var/app/files/report.pdf", terms: "/var/app/files/terms.pdf" };
>    const file = FILES[String(req.query.doc)];
>    if (!file) return res.status(404).end();
>    res.sendFile(file);
>    ```
> 2. If users genuinely pick from a folder, strip the directory parts and *prove* the result stayed inside your base directory:
>    ```ts
>    const BASE = path.resolve("/var/app/files");
>    const full = path.resolve(BASE, path.basename(String(req.query.name)));
>    if (full !== BASE && !full.startsWith(BASE + path.sep)) return res.status(400).end();
>    res.sendFile(full);
>    ```
> 3. Don't try to fix this with `if (name.includes(".."))`. Attackers send `..%2f`, double-encoded `..%252f`, backslashes, and NUL bytes to walk past string filters. The resolve-and-verify check above is immune because it checks the *final* path.
> 4. Verify after deploy: `curl -i "https://yourapp.com/download?name=../../../../etc/passwd"` should return 400/404, not a file. Try the URL-encoded form (`..%2f..%2f..%2fetc%2fpasswd`) too.

Repeat the report block for each endpoint that builds a file path from request input without fencing it.

## Don't false-positive on

- **Paths that go through `path.basename` / `filepath.Base` / `os.path.basename` before the read.** Stripping the directory components is the core defense — `basename("../../etc/passwd")` is `"passwd"`. If the input is basenamed first, the `../` is already gone. (Belt-and-suspenders containment checks are nice, but basename alone defuses the classic attack — don't flag code that already does it.)
- **`path.resolve` / `realpath` followed by an "is it still inside the base?" check** — `startsWith(BASE + sep)`, `filepath.Rel` + no leading `..`, `strncmp` against the real base. That's the textbook correct fix. Not a finding.
- **`send_from_directory(dir, validated_name)` in Flask, or `secure_filename()` applied first.** `send_from_directory` is *built* to reject traversal, and `secure_filename` strips `../`, slashes, and NUL. When the filename is run through either, it's safe.
- **A token-to-file allowlist / `switch` / map** where the user supplies a key and your code picks the real path. The user never controls the path, so there's nothing to traverse.
- **Static serving of one fixed directory** — `express.static("public")`, `app.mount("/static", StaticFiles(directory="static"))`, `http.FileServer(http.Dir("./public"))` with a *literal* directory. These ship with framework traversal guards and the directory isn't user-controlled. Only flag if the directory itself is built from request input (Pattern 5).
- **Reading a fixed, developer-chosen path** — `fs.readFile("./config/defaults.json")`, `open(settings.TEMPLATE_PATH)`, a constant filename. No user input touches the path, so there's no traversal. (If a *config value* an admin sets feeds the path, that's a much lower-risk, trusted-input case — mention it, don't rate it CRITICAL.)
- **The path comes from a database row or a server-generated id**, not directly from the request — e.g. you look up `file.storage_key` by the row's id and read *that*. The user influences *which row*, but the stored key is yours. (Do still glance at how that key got into the DB — if users could write `../` into it at upload time, the traversal just moved upstream.)
- **Build-time / CLI / scripts that read paths from `argv`** run by the developer on their own machine — a codegen script, a migration runner, a local dev tool. That's the developer reading their own files, not a remote attacker. Not a web-reachable finding.
- **Go `http.ServeFile(w, r, r.URL.Path)`** where the third argument is literally `r.URL.Path` (not a self-built join). The standard library *does* reject `..` in `r.URL.Path` for this exact call. The danger is only when you construct the path yourself from a query/body value (Pattern 4).
