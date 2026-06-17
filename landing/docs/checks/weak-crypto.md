# Check — Weak or broken cryptography

**What you're looking for:** code that *does* encrypt or hash, but uses a recipe that experts threw out years ago — so it gives you the comfortable feeling of security without the actual protection. The four classic mistakes: **(1)** scrambling passwords with MD5/SHA1/SHA256 (or storing them in plain text) instead of a real password hash; **(2)** encrypting data with a broken cipher like DES/RC4, or with AES in "ECB" mode (which leaks the shape of your data); **(3)** baking a fixed IV or salt straight into the code, which quietly cancels out the encryption; and **(4)** generating passwords, reset tokens, session IDs or API keys with a "random" function that isn't actually unpredictable, so an attacker can guess the next one.

This is the *algorithm* layer. A lock can be the wrong kind of lock even when the door, the cookie flags, and the HTTPS are all perfect. None of the other checks look at *which* crypto primitive you picked — this one does.

The reason it bites founders specifically: an AI assistant asked to "hash the password" will very often reach for `crypto.createHash('sha256')` because that's the most common hashing snippet on the internet. It runs, the tests pass, the password column fills with official-looking hex — and the day your database leaks, every one of those passwords falls in minutes on a consumer GPU. It *looked* done.

## How to scan

You're reading the repo. Cast a wide net across stacks, then read the surrounding lines to confirm it's *security* crypto (passwords, encryption, tokens) and not a harmless checksum.

### JavaScript / TypeScript (Node, Next.js, Express, Deno, Bun)

```bash
# Password hashing with a plain digest (MD5/SHA1/SHA256) — look near "password"
grep -rEn --include='*.ts' --include='*.js' --include='*.mjs' \
  --exclude-dir={node_modules,.next,dist,build} \
  "createHash\(\s*['\"](md5|sha1|sha256)['\"]" . 2>/dev/null | head -30

# Broken ciphers + ECB mode
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E "createCipher(iv)?\(\s*['\"](des|des-ede3|rc4|aes-128-ecb|aes-256-ecb)" . 2>/dev/null

# Insecure randomness used for anything security-sensitive
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E "Math\.random\(\)" . 2>/dev/null \
  | grep -iE 'token|secret|password|otp|code|key|id|salt|nonce|session|reset' | head -30

# Is a REAL password hash present at all? (if these are ALL absent but passwords are stored → red flag)
grep -rEn --include='*.ts' --include='*.js' --exclude-dir=node_modules \
  -E "bcrypt|scrypt|argon2|@node-rs/argon2" . 2>/dev/null | head
grep -En '"bcrypt"|"bcryptjs"|"argon2"|"@node-rs/argon2"' package.json 2>/dev/null
```

### Python (Django, Flask, FastAPI, scripts)

```bash
# Plain digests over a password
grep -rEn --include='*.py' \
  -E "hashlib\.(md5|sha1|sha256|new\(\s*['\"](md5|sha1))" . 2>/dev/null \
  | grep -iE 'password|passwd|pwd|secret|token' | head -30

# Broken ciphers / ECB (PyCryptodome, cryptography, pyDes)
grep -rEn --include='*.py' \
  -E "AES\.MODE_ECB|DES\.new|DES3\.new|ARC4|Cipher\([^)]*ECB|modes\.ECB" . 2>/dev/null

# Insecure randomness for secrets (random module instead of secrets/os.urandom)
grep -rEn --include='*.py' \
  -E "random\.(random|randint|choice|getrandbits|sample|randrange)" . 2>/dev/null \
  | grep -iE 'token|secret|password|otp|code|key|salt|nonce|session|reset' | head -30

# Is a real KDF present? (passlib / bcrypt / argon2 / Django hashers)
grep -rEn --include='*.py' -E "bcrypt|argon2|passlib|pbkdf2|make_password|PBKDF2" . 2>/dev/null | head
```

### Go

```bash
# MD5/SHA1 packages imported (read context — checksum vs password)
grep -rEn --include='*.go' -E 'crypto/(md5|sha1|des|rc4)"' . 2>/dev/null
# AES in ECB mode (Go has no ECB in stdlib, so an ECB helper is a manual/imported red flag)
grep -rEn --include='*.go' -E 'NewECBEncrypter|ECBEncrypter|cipher\.NewCBCEncrypter\(' . 2>/dev/null
# math/rand used where crypto/rand belongs
grep -rEn --include='*.go' -E 'math/rand"|rand\.Intn\(|rand\.Int\(|rand\.Read\(' . 2>/dev/null \
  | grep -iE 'token|secret|password|key|salt|nonce|session|otp' | head -30
# Real password hashing present?
grep -rEn --include='*.go' -E 'bcrypt|argon2|scrypt|golang\.org/x/crypto' . 2>/dev/null | head
```

### Ruby (Rails, Sinatra)

```bash
grep -rEn --include='*.rb' \
  -E "Digest::(MD5|SHA1)\.|OpenSSL::Cipher\.new\([^)]*(des|rc4|ecb)|OpenSSL::Cipher::Cipher" . 2>/dev/null
# Insecure randomness — rand / Random for secrets instead of SecureRandom
grep -rEn --include='*.rb' -E "\brand\(|Random\.(rand|new)" . 2>/dev/null \
  | grep -iE 'token|secret|password|otp|code|key|session|reset' | head -30
# has_secure_password / bcrypt present? (Rails default is bcrypt — good)
grep -rEn -E "has_secure_password|bcrypt|argon2" Gemfile app/ 2>/dev/null | head
```

### PHP (Laravel, plain PHP, WordPress)

```bash
grep -rEn --include='*.php' \
  -E "\bmd5\(|\bsha1\(|hash\(\s*['\"](md5|sha1)|mcrypt_|MCRYPT_3DES|MCRYPT_DES|'des-|'rc4'|'aes-128-ecb'" . 2>/dev/null | head -30
# Insecure randomness for tokens (rand/mt_rand/uniqid instead of random_bytes / random_int)
grep -rEn --include='*.php' -E "\b(rand|mt_rand|uniqid)\(" . 2>/dev/null \
  | grep -iE 'token|secret|password|otp|code|key|salt|nonce|session|reset' | head -30
# Real hashing present? (password_hash / Hash::make are correct)
grep -rEn --include='*.php' -E "password_hash\(|password_verify\(|Hash::make" . 2>/dev/null | head
```

### Mobile (Swift / Kotlin / Java / Flutter / React Native)

The most dangerous mobile crypto mistake is **AES/ECB** — it's the textbook "default" in a lot of Android tutorials and AI answers, so it shows up constantly. Right behind it: a **hardcoded IV** (often `new byte[16]`, i.e. all zeros) and using a weak digest to "hash" a password before storing it locally.

```bash
# iOS / Swift — CommonCrypto MD5/SHA1, ECB option, manual DES
grep -rEn --include='*.swift' --include='*.m' \
  -E 'CC_MD5|CC_SHA1|kCCAlgorithmDES|kCCAlgorithm3DES|kCCAlgorithmRC4|kCCOptionECBMode|CryptoSwift' . 2>/dev/null
# Swift insecure randomness for key/token material
grep -rEn --include='*.swift' -E 'arc4random|Int\.random\(|drand48|\.random\(in:' . 2>/dev/null \
  | grep -iE 'key|token|secret|iv|salt|nonce|otp|password' | head -20

# Android / Kotlin / Java — the big one: AES/ECB and broken ciphers
grep -rEn --include='*.kt' --include='*.java' \
  -E 'Cipher\.getInstance\(\s*"(AES|DES|DESede|RC4)(/ECB[^"]*|)"|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"' . 2>/dev/null
# Hardcoded IV / SecretKeySpec from a literal string + java.util.Random for secrets
grep -rEn --include='*.kt' --include='*.java' \
  -E 'IvParameterSpec\(\s*(new\s+byte\[|".*"\.toByteArray)|SecretKeySpec\(\s*".*"\.toByteArray|new\s+java\.util\.Random|\bRandom\(\)' . 2>/dev/null

# Flutter / Dart — encrypt/pointycastle in ECB, weak digests, Random() (non-secure)
grep -rEn --include='*.dart' \
  -E 'AESMode\.ecb|ECBBlockCipher|md5\.convert|sha1\.convert|crypto\.md5|Random\(\)(?!\.secure)' . 2>/dev/null
grep -rEn --include='*.dart' -E '\bRandom\(\)' . 2>/dev/null \
  | grep -iE 'token|secret|password|otp|key|iv|salt|nonce' | head -20

# React Native — CryptoJS MD5/RC4/DES, Math.random for secrets
grep -rEn --exclude-dir=node_modules --include='*.js' --include='*.ts' --include='*.tsx' \
  -E 'CryptoJS\.(MD5|SHA1|RC4|DES|TripleDES)|mode:\s*CryptoJS\.mode\.ECB' . 2>/dev/null
```

## What each primitive should be (so you can give the fix, not just the alarm)

- **Passwords** → a slow, salted password hash built for the job: **argon2id** (best), **scrypt**, or **bcrypt**. Never a bare SHA/MD5, never "salt + SHA256". The slowness is the point — it's what makes a leaked database expensive to crack.
- **Encrypting data** → **AES-256-GCM** (or ChaCha20-Poly1305). GCM is "authenticated" — it both hides the data *and* detects tampering. Avoid plain CBC unless you really know why; never ECB.
- **IV / nonce** → a *fresh random value per message*, generated by the CSPRNG, stored alongside the ciphertext. Never hardcoded, never reused with the same key.
- **Salt** → a *fresh random value per password*, stored with the hash. (bcrypt/argon2 do this for you — another reason to use them.)
- **Tokens, reset codes, session IDs, API keys** → a **CSPRNG**: `crypto.randomBytes` (Node), `secrets.token_urlsafe` (Python), `crypto/rand` (Go), `SecureRandom` (Java/Kotlin), `Random.secure()` (Dart), `SecRandomCopyBytes` (Swift). Never `Math.random()`, `random.random()`, `rand()`, `java.util.Random`, or plain `arc4random` for these.

## The dangerous patterns

**Pattern 1 — passwords hashed with a fast digest (or not at all)** 🔴 **HIGH**

```ts
// Node — looks done, isn't. SHA256 is built to be FAST; that's the opposite of what you want.
const hash = crypto.createHash('sha256').update(password).digest('hex');
```
```python
# Python — same mistake. "Salting" a fast hash doesn't fix the speed problem.
import hashlib
pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
```
```java
// Android — MD5 of a password, stored in SharedPreferences. Two bugs in one line.
String h = bytesToHex(MessageDigest.getInstance("MD5").digest(password.getBytes()));
```
A fast digest can be tried billions of times per second on a GPU. When (not if) your user table leaks, weak/common passwords fall almost instantly, and credential-stuffing against your users' *other* accounts follows. **HIGH.** Plain-text passwords (no hash at all) are **🔴 CRITICAL**.

**Pattern 2 — broken cipher or ECB mode** 🟠 **HIGH**

```java
// Android / Java — the single most common one. ECB encrypts identical blocks identically...
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
```
```python
from Crypto.Cipher import AES, DES
cipher = AES.new(key, AES.MODE_ECB)   # ECB leaks structure
legacy = DES.new(key, DES.MODE_ECB)   # DES is broken outright (56-bit key)
```
ECB encrypts each block independently, so repeated plaintext produces repeated ciphertext — the famous "ECB penguin" where you can still see the image through the encryption. It leaks patterns and enables block-shuffling attacks. DES/3DES/RC4 are broken or deprecated regardless of mode. **HIGH.**

**Pattern 3 — hardcoded IV or salt** 🟠 **HIGH**

```kotlin
// Android — a fixed (here, all-zero) IV. The IV is supposed to be the per-message randomness.
val iv = IvParameterSpec(ByteArray(16))           // 16 zero bytes, every time
val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, key, iv)
```
```ts
const iv = Buffer.from('0000000000000000');        // constant IV across all messages
```
A reused IV (especially with GCM/CTR) can be catastrophic — it can leak the key-stream and let an attacker forge or decrypt messages. A hardcoded salt means every user's password hash uses the same salt, which defeats the salt entirely (one rainbow table cracks everyone). **HIGH.**

**Pattern 4 — insecure randomness for secrets** 🟠 **HIGH**

```ts
// Password-reset token from Math.random() — predictable, low-entropy.
const token = Math.random().toString(36).slice(2);
```
```python
import random
otp = random.randint(100000, 999999)               # random module is NOT cryptographic
```
```java
String sessionId = Long.toHexString(new java.util.Random().nextLong());  // seedable, guessable
```
`Math.random()`, Python's `random`, `java.util.Random`, Ruby's `rand`, PHP's `rand/mt_rand/uniqid` are **not unpredictable** — they're seeded from time/state and an attacker who sees a few outputs can predict the rest. For a reset token or session ID that means account takeover by *guessing the next token*, no breach required. **HIGH** (account-takeover class).

**Pattern 5 — deprecated TLS / cipher pins** 🟡 **MEDIUM**

```js
const agent = new https.Agent({ secureProtocol: 'TLSv1_method' });   // TLS 1.0
```
```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)            # or PROTOCOL_SSLv3
```
```kotlin
ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions(TlsVersion.TLS_1_0)
```
Forcing TLS 1.0/1.1 or SSLv3 (or pinning RC4/3DES cipher suites) re-enables attacks like BEAST/POODLE that modern defaults already closed. Usually someone pinned an old version to make a stubborn legacy endpoint connect. **MEDIUM** — modern default is TLS 1.2+ (prefer 1.3).

## Safe patterns

**Passwords** — use a real KDF, let the library handle salt:

```ts
// Node — argon2id (preferred) or bcrypt
import argon2 from 'argon2';
const hash   = await argon2.hash(password);                 // salt is embedded automatically
const ok     = await argon2.verify(hash, password);
// bcrypt is also fine:  await bcrypt.hash(password, 12)
```
```python
# Python — passlib argon2, or Django's built-in (Argon2/PBKDF2)
from passlib.hash import argon2
hash = argon2.hash(password);  argon2.verify(password, hash)
# Django: from django.contrib.auth.hashers import make_password, check_password
```
```kotlin
// Android — argon2kt / bcrypt; never roll your own from MessageDigest
val hash = Argon2Kt().hash(mode, password.toByteArray(), salt, ...)
```

**Encryption** — AES-GCM with a fresh random IV per message:

```ts
import { randomBytes, createCipheriv } from 'crypto';
const iv = randomBytes(12);                                  // fresh, random, store with ciphertext
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([cipher.update(data), cipher.final()]);
const tag = cipher.getAuthTag();                             // GCM = encrypt + tamper-detect
```
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)                                       # fresh per message
ct = AESGCM(key).encrypt(nonce, data, None)
```

**Random secrets** — always the CSPRNG:

```ts
import { randomBytes } from 'crypto';
const token = randomBytes(32).toString('hex');               // Node
```
```python
import secrets
token = secrets.token_urlsafe(32)                            # Python
```
```go
import "crypto/rand"
b := make([]byte, 32); rand.Read(b)                          // Go: crypto/rand, NOT math/rand
```
```ruby
require 'securerandom'; token = SecureRandom.hex(32)         # Ruby
```
```php
$token = bin2hex(random_bytes(32));                          // PHP 7+
```
```kotlin
val b = ByteArray(32); java.security.SecureRandom().nextBytes(b)   // Android
```
```dart
final rng = Random.secure();                                 // Flutter — note .secure()
```
```swift
var b = [UInt8](repeating: 0, count: 32)
SecRandomCopyBytes(kSecRandomDefault, b.count, &b)           // iOS
```

## Report a finding as

**Title:** "Passwords are scrambled with SHA-256, which a leaked database cracks in minutes"

(adapt per pattern — lead with the one you actually found; the password and reset-token cases are the highest-stakes)

**Detail:**
> 🔴 **HIGH** — Your passwords are hashed with a method built for *speed*, which is exactly backwards for passwords.
>
> In `src/auth/register.ts:18` you store the password with `crypto.createHash('sha256').update(password).digest('hex')`. That runs and looks legitimate — the column fills with proper-looking hex. The problem is invisible until the worst day: SHA-256 is designed to be fast, so an attacker who gets a copy of your user table can try **billions of guesses per second** on a single rented GPU. Common and medium-strength passwords fall in minutes. Because people reuse passwords, the attacker then logs into your users' email and bank with the same credentials.
>
> The fix is to swap one library. A real password hash (argon2id or bcrypt) is *deliberately slow* and salts each password for you, so the same leaked table would take centuries instead of minutes.
>
> **What to do tonight:**
> 1. Install a real hasher and replace the digest:
>    ```ts
>    import argon2 from 'argon2';
>    // on register:
>    const hash = await argon2.hash(password);          // salt handled for you
>    // on login:
>    const ok = await argon2.verify(storedHash, password);
>    ```
> 2. You can't un-hash the old SHA-256 values. Migrate gracefully: keep a `hash_algo` flag per user; on each user's *next successful login*, re-hash their (now-known-correct) password with argon2 and flip the flag. Within a few weeks most users are upgraded; force a reset for the stragglers.
> 3. Grep for the same pattern elsewhere (`createHash`, `hashlib.sha`, `MessageDigest`) — if it appears once it's usually copy-pasted.
>
> If what I found was instead a reset/session token from `Math.random()`, the fix is `crypto.randomBytes(32).toString('hex')` and there's no migration — just generate new tokens going forward. If it was `AES/ECB` or a hardcoded IV, switch to `aes-256-gcm` with a fresh `randomBytes(12)` IV stored next to each ciphertext (snippet in the safe-patterns section).

Write one finding per distinct problem (password hashing, cipher mode, randomness, IV/salt, TLS) — they have different fixes and sometimes different severities. Don't merge them.

## Don't false-positive on

- **MD5/SHA1/SHA256 used as a non-security checksum or key.** ETags, cache keys, content-addressing, file-integrity dedup, deriving a stable color/avatar from a string, Git-style object IDs, `Subresource Integrity` hashes — these aren't protecting a secret and don't need a slow/keyed hash. Read the surrounding lines: if the input is a *file/URL/config blob* and the output is an *identifier or cache key*, it's fine. Only flag when the hashed input is a **password/credential** or the output is used as a **security token/MAC**.
- **A salted bcrypt / scrypt / argon2 call.** That's the correct answer — don't flag it just because a `sha256` appears nearby (libraries often use SHA-256 *inside* a proper construction like HMAC or PBKDF2, which is legitimate). PBKDF2 with a high iteration count and a random salt is an acceptable KDF.
- **HMAC-SHA256 for signatures / webhooks / JWTs.** `crypto.createHmac('sha256', ...)`, `jwt` with `HS256`, Stripe/GitHub webhook signature checks — using SHA-256 *inside HMAC* is correct and recommended. This module is about bare digests over passwords and broken ciphers, not keyed MACs. (Webhook *verification presence* is the webhooks-csrf check's job, not this one.)
- **`Math.random()` / `random.random()` / `rand()` for non-security things.** Picking a random tip to display, jitter/backoff timing, shuffling a carousel, a demo seed, a loading-spinner message, test fixtures, animation. Only flag when the output becomes a **token, OTP, password, session ID, key, IV, salt, nonce, or anything an attacker guessing it would gain access.** Read what the value is *used for*, not just that it's random.
- **AES-CBC done correctly** (random IV per message, with a separate MAC or used inside an authenticated scheme). CBC isn't *broken* the way ECB is. Flag CBC only when paired with a hardcoded/reused IV or no integrity check, and prefer suggesting GCM rather than alarming. **ECB is the unconditional flag.**
- **Test code, fixtures, examples, and migrations seeding fake data.** A hardcoded key/IV in `*.test.*`, `__tests__/`, `spec/`, `examples/`, a seed script, or a doc snippet isn't a production secret. Note it only if a test key looks like it leaked from prod.
- **Third-party / vendored code you didn't write** (`node_modules`, `Pods`, `vendor/`, `.dart_tool`, generated SDKs). The grep excludes most of these already — don't report a weak primitive buried inside a dependency as the founder's bug. If a *dependency* uses broken crypto, that's the dependencies check's lane (a CVE), not this one.
- **MD5 in WordPress / legacy password columns you can't unilaterally change.** WordPress core uses phpass (a salted, stretched hash) by default; a bare `md5()` you see may be theirs, not the site owner's. Confirm it's *the app's own* auth code before flagging, and frame the fix as a migration, not a one-line swap.
- **`arc4random` / `arc4random_uniform` on Apple platforms for non-key randomness.** Despite the "rc4" in the name, modern `arc4random` is actually a CSPRNG on macOS/iOS and is fine for tokens. Only flag the *RC4 cipher* (`kCCAlgorithmRC4`, `CryptoSwift` RC4), not the `arc4random` *RNG*. (Still nudge `SecRandomCopyBytes` for key material, but this is INFO, not HIGH.)
- **TLS version pinning that's already modern.** Pinning `TLSv1.2`/`TLSv1.3` as a *minimum* is good hardening, not a finding. Only flag pins to TLS 1.0/1.1/SSLv3 or explicitly weak cipher suites (RC4/3DES/`NULL`/`EXPORT`).
- **Cookie `Secure`/`HttpOnly`, HSTS, and mobile cleartext-HTTP.** Those are transport/header concerns owned by the security-headers check. This module stops at the *algorithm/primitive* layer — which cipher, which hash, which RNG.
