# Check — Letting users set fields they shouldn't (and handing back fields they shouldn't see)

**What you're looking for:** two mirror-image bugs that both come from the same lazy habit — *treating a database row and a web request as the same shape.*

1. **Over-binding (mass assignment).** A handler takes the whole request body and pushes it straight into a model — `User.update(req.body)`, `Object.assign(record, req.body)`, `{ ...req.body }` into a create/update, a Mongoose/Prisma/Sequelize create with no field list, a Rails `update` with no `.permit`, a Django serializer with `fields = '__all__'`. The form on screen has three fields — name, email, bio — so it *feels* like only three things can change. But the API will happily accept any field the model has. An attacker adds `"role": "admin"` (or `"isAdmin": true`, `"balance": 999999`, `"verified": true`, `"plan": "enterprise"`, `"ownerId": "<someone-else>"`) to the JSON and the server writes it without blinking.

2. **Over-return.** The mirror image: the handler reads a row and serializes the *whole thing* back to the client — `res.json(user)`, `return user.dict()`, JSON of a `SELECT *`. The screen only shows the name and avatar, so nobody notices that the same response also contains `passwordHash`, `resetToken`, `stripeCustomerId`, the user's `isAdmin` flag, or — on a list endpoint — every *other* user's email and phone number.

Both come from skipping the boring step: **deciding explicitly which fields go in, and which fields come out.** AI codegen almost never writes that step, because it doesn't know which of your columns are sensitive. So it ships the model raw in both directions.

The security world calls #1 "mass assignment / over-posting" and the whole class "Broken Object Property Level Authorization" (OWASP API3:2023). Don't say any of that to the user. Say: **"a user can set fields you never meant them to — like making themselves an admin — and your API hands back fields you never meant them to see, like password hashes."**

This is **not** the same as the other access-control checks, so don't let them swallow it:
- [IDOR](./idor.md) is about *which row* you can touch (object-level — "user 42 reads order 43"). This check is about *which fields* of a row you can write or read (property-level). You can have perfect IDOR fencing and still let the owner promote themselves to admin.
- [PII in logs](./logging-pii.md) is about sensitive data leaking into *logs and analytics*. Over-return leaks it straight out the *API response* to the caller.

## How to scan

The smell is a request body (or a DB row) moving **wholesale** in or out — no field list in between. Grep for the wholesale moves, then read each hit and ask the one question: *is there an explicit allowlist of fields, or is the whole blob flowing through?*

```bash
# ── JS / TS: over-binding — whole body into create/update ────────────
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build,coverage,.svelte-kit} \
  -E '\.(create|update|updateOne|findOneAndUpdate|insert|insertOne|save|build|bulkCreate|upsert)\s*\(\s*(\{\s*data\s*:\s*)?(req\.body|request\.body|body|input|data|payload)\b' \
  . 2>/dev/null | head -40

# Object.assign / spread of the raw body into a record
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E 'Object\.assign\([^,]+,\s*(req\.body|request\.body|body|input)\b|\{\s*\.\.\.(req\.body|request\.body|body|input)\b' \
  . 2>/dev/null | head -40

# ── JS / TS: over-return — whole DB object straight to the client ────
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E '(res\.(json|send)|Response\.json|NextResponse\.json|c\.json)\s*\(\s*(user|users|account|customer|record|row|result|rows|data|profile|member)\b' \
  . 2>/dev/null | head -40

# ── Python: over-binding ─────────────────────────────────────────────
# Django/DRF: ModelForm / serializer that takes every field
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E "fields\s*=\s*'__all__'|fields\s*=\s*\(\s*'__all__'|exclude\s*=" . 2>/dev/null | head -40
# Splatting request data into the model constructor / update
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E '\w+\(\*\*(request\.(data|POST|json)|payload|data|body)\)|\.update\(\*\*(request\.(data|POST)|data)\)|\.filter\([^)]*\)\.update\(\*\*' \
  . 2>/dev/null | head -40
# ── Python: over-return — serializing the raw ORM row ────────────────
grep -rEn --include='*.py' --exclude-dir={venv,.venv,__pycache__,site-packages} \
  -E 'jsonify\((\w+\.)?(__dict__|dict\(\))|JsonResponse\(model_to_dict|return\s+\w+\.dict\(\)|\.values\(\)\)|SELECT\s+\*' \
  . 2>/dev/null | head -40

# ── Go: binding the whole body to a struct, then saving it ───────────
grep -rEn --include='*.go' \
  -E 'json\.NewDecoder\([^)]*\)\.Decode\(&|c\.(ShouldBind(JSON)?|Bind(JSON)?)\(&|json\.Unmarshal\(' \
  . 2>/dev/null | head -40
# Updates that write the whole struct (no Select / no field list)
grep -rEn --include='*.go' -E '\.(Save|Updates|Create)\(&?\w+\)' . 2>/dev/null | head -40

# ── Ruby / Rails: update/create with no strong-params permit ─────────
grep -rEn --include='*.rb' --exclude-dir={vendor,tmp} \
  -E '\.(update|update_attributes|create|new|assign_attributes)\(\s*params\b|params\.permit!|params\[:\w+\]\s*\)' \
  . 2>/dev/null | head -40
# ── Ruby: over-return — rendering the bare model ─────────────────────
grep -rEn --include='*.rb' --exclude-dir={vendor,tmp} \
  -E 'render\s+json:\s*@?\w+(\s*$|\.all|\s*\})' . 2>/dev/null | head -40

# ── PHP / Laravel: mass-assignment + raw model JSON ──────────────────
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E '::(create|update|fill|forceFill)\(\s*\$request->(all|input)\(\)|->update\(\s*\$request->all\(\)|protected\s+\$guarded\s*=\s*\[\s*\]' \
  . 2>/dev/null | head -40
grep -rEn --include='*.php' --exclude-dir={vendor} \
  -E 'return\s+\$?\w+;|response\(\)->json\(\$\w+\)|::all\(\)' . 2>/dev/null | head -40

# ── Mobile clients reveal which fields the API trusts ────────────────
# Swift / Kotlin / Dart / RN: a request body assembled from a whole model/dictionary
grep -rEn --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  --include='*.ts' --include='*.tsx' --exclude-dir={node_modules,Pods,build} \
  -E 'JSONEncoder\(\)\.encode\(|Gson\(\)\.toJson\(|jsonEncode\(|httpBody\s*=|body:\s*JSON\.stringify\(\s*\w+\s*\)' \
  . 2>/dev/null | head -40
```

The grep is just the dragnet. The decision is always made by **reading the handler**: does an explicit, named list of fields sit between the request and the database (in), and between the database and the response (out)? If the body or the row flows through *whole*, flag it.

## The dangerous patterns

**Pattern 1 — over-binding: the whole body becomes the update (every stack)**

```ts
// JS/TS — Express / Next.js
await db.user.update({ where: { id: session.user.id }, data: req.body });   // ← any column
Object.assign(user, req.body); await user.save();                            // ← Mongoose, same bug
await User.create({ ...req.body });                                          // ← Sequelize/Prisma create
```
```python
# Django REST Framework
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'        # ← serializer accepts (and exposes) every field, incl. is_staff
# or, by hand:
User.objects.filter(pk=request.user.pk).update(**request.data)              # ← splat the raw body
user = User(**request.data); user.save()
```
```ruby
# Rails — no strong params, or .permit! which permits everything
@user.update(params[:user])        # MassAssignmentSecurity off → role/admin writable
@user.update(params.require(:user).permit!)   # ← .permit! is "permit literally everything"
```
```php
// Laravel — $request->all() into a model whose $guarded is empty
$user->update($request->all());     // ← with `protected $guarded = [];` every column is fillable
User::create($request->all());
```
```go
// Go — decode straight into the model struct, then Save the whole thing
var u User
json.NewDecoder(r.Body).Decode(&u)  // ← attacker sets u.IsAdmin, u.Balance
db.Save(&u)                          // GORM Save writes ALL fields
```

What goes wrong: your edit-profile form posts `{name, bio}`. An attacker opens the network tab (or just `curl`s your API) and sends `{"name":"x","role":"admin"}` — or `isAdmin`, `is_staff`, `verified`, `emailVerified`, `plan`, `credits`, `balance`, `ownerId`, `teamId`, `stripeSubscriptionId`. The server writes whatever column matches. One extra JSON key and they've promoted themselves, marked themselves paid, flipped their own account to verified, or reassigned a record to someone else. No exploit toolkit needed — it's an extra line in a JSON body. **HIGH** (🟠), rising to **CRITICAL** (🔴) when a writable field grants privilege (`role`/`isAdmin`/`is_staff`), money (`balance`/`credits`/`plan`), or trust (`verified`/`emailVerified`), or lets the attacker move a record between accounts (`ownerId`/`userId`/`orgId`).

**Pattern 2 — over-return: the whole row goes back to the caller (every stack)**

```ts
const user = await db.user.findUnique({ where: { id } });   // SELECT * — includes passwordHash, tokens
return Response.json(user);                                  // ← all of it, straight to the browser
// list endpoints are worse — every user's private fields at once:
return Response.json(await db.user.findMany());
```
```python
return jsonify(user.__dict__)            # password_hash, reset_token, stripe_id … all of it
return JsonResponse(list(User.objects.values()))   # every column of every user
```
```ruby
render json: @user            # bare model → every attribute, incl. encrypted_password digest
render json: User.all
```
```php
return response()->json($user);   // Eloquent model → all attributes unless $hidden is set
```

What goes wrong: the screen only renders the display name, so it *looks* fine. But "View Source" / the network tab / `curl` shows the *full* JSON the server actually sent — and that JSON carries `passwordHash`, `resetToken`, `twoFactorSecret`, `stripeCustomerId`, internal flags, soft-delete columns, and, on any list/search endpoint, **other users'** emails, phone numbers, and addresses. The password *hash* alone lets an attacker run an offline cracking attack at their leisure; a leaked reset token can be replayed to take over the account. **HIGH** (🟠), **CRITICAL** (🔴) when the leaked field is a password hash, a session/reset/2FA token, or other users' PII in a list response.

**Why both ship together:** the same handler usually has both halves — it binds `req.body` in, does the work, then returns the model out. Fix is the same shape on both sides: an explicit allowlist.

## Safe patterns

Decide, by name, what goes **in** and what comes **out**. Never let the model and the request be the same shape.

```ts
// JS/TS — validate the input against a schema with named fields (zod here)
const Body = z.object({ name: z.string().max(80), bio: z.string().max(500) }); // role/isAdmin NOT here
const input = Body.parse(await req.json());                 // unknown keys are dropped/rejected
await db.user.update({ where: { id: session.user.id }, data: input });

// …and project the OUTPUT to an explicit field list — never the raw row
const user = await db.user.findUnique({
  where: { id },
  select: { id: true, name: true, bio: true, avatarUrl: true },  // hash/tokens never selected
});
return Response.json(user);
```
```python
# Django REST — name the fields; never '__all__' for a model with sensitive columns
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'bio', 'avatar_url']   # read+write surface, explicit
        read_only_fields = ['id']
# or validate with a Pydantic model that has only the allowed fields, then assign field-by-field.
```
```ruby
# Rails — strong params: a real permit list (NOT .permit!)
def user_params
  params.require(:user).permit(:name, :bio)   # role/admin can never come through
end
@user.update(user_params)
# output: a serializer / only: list
render json: @user.as_json(only: [:id, :name, :bio, :avatar_url])
```
```php
// Laravel — declare $fillable (allowlist) and $hidden (never serialized)
class User extends Model {
  protected $fillable = ['name', 'bio'];                 // only these are mass-assignable
  protected $hidden   = ['password', 'remember_token'];  // never appear in JSON
}
$user->update($request->only(['name', 'bio']));
```
```go
// Go — bind to a small input DTO, copy named fields, update only those columns
type UpdateProfile struct{ Name string `json:"name"`; Bio string `json:"bio"` }
var in UpdateProfile
json.NewDecoder(r.Body).Decode(&in)
db.Model(&user).Select("name", "bio").Updates(User{Name: in.Name, Bio: in.Bio}) // Select() fences the write
```

The rule on both sides: **the request shape and the response shape are their own named types, not the database model.**

## What to report

**Title:** "A user can make themselves an admin (and your API hands back password hashes)"

(adapt to what you actually found — "users can set fields the form never showed, like `role` and `plan`", or "your API returns every column including password hashes", or both)

**Severity:** 🟠 **HIGH** by default. 🔴 **CRITICAL** when over-binding exposes a privilege/money/trust field (`role`, `isAdmin`, `is_staff`, `balance`, `credits`, `plan`, `verified`, `emailVerified`) or lets a record be reassigned across accounts (`ownerId`, `userId`, `orgId`) — or when over-return leaks a password hash, a session/reset/2FA token, or other users' PII in a list response.

**Detail — write it as a story:**

> **Your edit-profile form shows three fields. Your API accepts all of them — and a few you never meant to expose.**
>
> `src/app/api/profile/route.ts:14` updates the logged-in user straight from the request body:
> ```ts
> await db.user.update({ where: { id: session.user.id }, data: req.body });
> ```
> The form on screen only lets someone change their name and bio, so it feels safe. But the API doesn't know about the form — it writes whatever fields the request contains. Your `user` table also has a `role` column and a `plan` column.
>
> **Here's what goes wrong:** an attacker opens their browser's network tab, watches the "Save profile" request go out, and replays it with two extra keys:
> ```bash
> curl -X PATCH https://yourapp.com/api/profile \
>   -H 'cookie: <their own session>' \
>   -d '{"name":"x","role":"admin","plan":"enterprise"}'
> ```
> The server writes `role = admin` and `plan = enterprise` to *their own* account. They didn't break in — they used their normal login and added two words to a JSON body. Now they're an admin on the paid tier, for free.
>
> Then the same handler hands the whole row back: `return Response.json(user)` at line 18. That response — visible in the same network tab — includes `passwordHash`, `resetToken`, and `stripeCustomerId`. The hash lets them crack the password offline; the reset token can be replayed to take over the account outright. On your `/api/users` list endpoint, the same `findMany()` returns those fields for *every* user at once.
>
> **What to do tonight** — name the fields going in, and the fields coming out. Stop using the database model as the request/response shape.
> ```ts
> import { z } from "zod";
>
> const Body = z.object({ name: z.string().max(80), bio: z.string().max(500) }); // role/plan absent on purpose
>
> export async function PATCH(req) {
>   const session = await auth();
>   if (!session) return new Response("Unauthorized", { status: 401 });
>
>   const input = Body.parse(await req.json());         // unknown keys (role, plan…) are dropped
>   const user = await db.user.update({
>     where: { id: session.user.id },
>     data: input,                                       // only name + bio can ever be written
>     select: { id: true, name: true, bio: true, avatarUrl: true },  // and only safe fields come back
>   });
>   return Response.json(user);                          // no hash, no tokens, no internal flags
> }
> ```
> Other stacks, same idea: Rails `params.require(:user).permit(:name, :bio)` + `as_json(only: […])`; Laravel `$fillable` + `$hidden`; Django REST an explicit `fields = […]` (never `'__all__'`); Go a small input DTO + `.Select("name","bio")`.
>
> **Then sweep every other write/return of a model.** If one handler does this, the rest of the same codebase almost certainly does too — every create/update endpoint and every endpoint that returns a user/order/account. The fix is mechanical; do them all in one pass.
>
> **Verify after deploy:** as a normal logged-in test user, `curl` your update endpoint with an extra `"role":"admin"` in the body, then re-fetch your account — the role must be unchanged. And inspect a profile/list response in the network tab: it should contain only the fields you chose, never a `passwordHash`, token, or another user's email.

Repeat the report block per vulnerable handler (or per cluster of identical handlers). If the project uses **Prisma/Sequelize/Mongoose/GORM/Eloquent/ActiveRecord** with no `select`/`permit`/`fillable`/`Select` anywhere, treat that as a strong signal the whole codebase has the pattern — grep once more before you finish.

## What NOT to flag

The whole point of this product is to not cry wolf. Skip these — they look like the bug but aren't:

- **The body is validated against an explicit schema/DTO first.** If a zod/joi/yup/valibot object, a Pydantic/DRF serializer with a named `fields = […]` list, a class-validator DTO (NestJS), or a Go input struct with *only* the allowed fields sits between the request and the database, unknown keys can't get through. Not a finding. (DRF/zod with `passthrough`/`extra="allow"` is the exception — that re-opens the hole.)
- **Strong params with a real `.permit(...)` list.** Rails `params.require(:user).permit(:name, :bio)` is the correct fence. Only flag `.permit!` (permits everything) or `update(params[:user])` with no permit at all.
- **Laravel `$fillable` set to a real allowlist, or `$guarded` listing the sensitive columns.** A model with `protected $fillable = ['name','bio']` is safe. Flag only `$guarded = []` (nothing guarded → everything fillable) or `forceFill`/`->forceCreate` on user input.
- **Django serializer that names its fields** (`fields = ['id','name','bio']`) — safe. The finding is specifically `fields = '__all__'` (or an `exclude` that forgets a sensitive column) on a model that *has* sensitive/privileged columns.
- **The output is already a projection.** A Prisma `select`, a Sequelize `attributes: […]`, a Mongoose `.select('name bio')` / `.select('-password')`, a SQL query naming columns (not `SELECT *`), a Rails `as_json(only: […])` / serializer, a Laravel model with `$hidden` covering the secrets, a Go DTO assembled field-by-field — all of these are the fix. Not a finding.
- **The model has no sensitive or privileged fields.** A `Tag`, `Category`, `Comment` body, or a public `Post` with only `{title, body, slug}` and no auth/money/ownership columns — over-binding/over-returning it exposes nothing that matters. Note as ⚪ INFO at most. The risk is entirely about *which* columns exist; read the model/migration before judging.
- **The whole-object move is on the server's own trusted data, not user input.** Copying an internal record between services, seeding, an admin tool that's *supposed* to set any field (with a verified admin role check present — see [admin paths](./admin-paths.md)), or returning a model to another internal service. The bug needs **attacker-controlled input on the way in**, or **a client/untrusted consumer on the way out**.
- **ORM-level guards already block the dangerous columns.** Sequelize/Objection with field-level `allowNull`/access scopes, a Mongoose schema where `role` has `select: false` and isn't in the update path, an ActiveRecord `attr_readonly :role`. If the sensitive column is provably unwritable/unselectable at the model layer, the inline call is fine.
- **Tests, seeds, fixtures, factories, migrations.** `*.test.*`, `*.spec.*`, `seed.*`, `factories.py`, `fixtures/`, `db/migrate/` — these set every field on purpose and never serve real traffic. Ignore.
- **Mobile client code on its own.** A Swift/Kotlin/Dart/RN app encoding a whole model into a request body just *reveals* the attack surface — the bug is on the **server** that trusts it. Don't flag the client; use it to find which server endpoint to read. (And remember: a mobile binary is trivially decompiled, so "the app only sends name and bio" is never a defense — the server must enforce the allowlist.)
