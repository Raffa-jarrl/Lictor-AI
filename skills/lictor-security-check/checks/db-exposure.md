# Check 4 — Supabase / Firebase exposure

**What you're looking for:** A Supabase or Firebase backend where the security rules (RLS for Supabase, security rules for Firebase) are wide open. The vibe-coded SaaS classic: "the AI told me to use Supabase, I ran the migrations, I never enabled RLS, and now my entire database is readable by anyone who has the anon key — which is in my JavaScript bundle."

## How to scan

```bash
# Find Supabase URLs in the codebase
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  'https://[a-z0-9]{20,}\.supabase\.co' \
  . 2>/dev/null | head -10

# Find Supabase anon key references
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  'NEXT_PUBLIC_SUPABASE_ANON_KEY|VITE_SUPABASE_ANON_KEY|SUPABASE_ANON_KEY' \
  . 2>/dev/null | head -5

# Find Firebase configuration
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  'firebaseConfig|initializeApp\(.*apiKey|firebaseio\.com' \
  . 2>/dev/null | head -10

# Find table queries — these tell you what tables exist
grep -rEn --exclude-dir={node_modules,.next,dist,build,.git} \
  'supabase\s*\.\s*from\(' \
  . 2>/dev/null | head -20
```

## Supabase: how to evaluate RLS

You can't directly verify RLS state from the codebase alone — that lives in Supabase's dashboard. But there are strong signals:

**Signals that RLS is OFF (or wrong):**

- The project uses `supabase.from('users').select()` directly from client code (`'use client'` files, React hooks, `pages/index.tsx`). If RLS were on with a proper anon policy, the query would fail — so if it works, RLS is permissive.
- No `supabase/migrations/*` file contains `ENABLE ROW LEVEL SECURITY` or `CREATE POLICY`.
- The Supabase service-role key (`SUPABASE_SERVICE_ROLE_KEY`) is imported in client code (it shouldn't ever be).

**Signals that RLS is properly configured:**

- Migrations contain `ALTER TABLE x ENABLE ROW LEVEL SECURITY` followed by `CREATE POLICY` statements
- Client queries are wrapped in error handling that distinguishes "not found" from "forbidden"
- A `RLS-CHECKLIST.md` or similar doc exists in the repo

## Report Supabase findings

If client code queries tables without any migration files enabling RLS:

**Title:** "Supabase queries from client code with no RLS migrations found"

**Detail:**
> Your client code (e.g. `src/components/UserList.tsx:23`) calls `supabase.from('users').select('*')` directly. For this to be safe, every table in your Supabase project must have Row Level Security enabled with policies that restrict the `anon` role.
>
> I couldn't find any migrations in this repo that enable RLS (`supabase/migrations/` or `db/migrations/`). That means either:
>
> 1. **RLS is off entirely** — anyone with your anon key (which is in your JS bundle, by design) can run any SELECT against any table. This is the worst case.
> 2. **RLS is configured in the Supabase dashboard but not version-controlled** — better, but fragile. The next dev who runs `supabase db reset` may drop the policies.
>
> **What to do tonight:**
> 1. Open Supabase dashboard → Authentication → Policies. Make sure RLS is ENABLED for every table.
> 2. For tables containing user data (users, profiles, messages, etc.), the policy should be: `auth.uid() = user_id` — only the row's owner can read it.
> 3. For tables that should be globally readable (countries, currencies, public posts), an explicit `SELECT TRUE` policy is fine but make the intent explicit.
> 4. Export your policies to version control: `supabase db dump --schema=public > supabase/schema.sql` and commit.
> 5. Test: open an incognito window, hit your app while logged out, try to load a page that queries Supabase. It should return empty or fail, not return all rows.

## Firebase: how to evaluate rules

Look for `firebase.json` or `firestore.rules` / `database.rules.json`:

```bash
test -f firebase.json && cat firebase.json | head -30
test -f firestore.rules && cat firestore.rules
test -f database.rules.json && cat database.rules.json
```

**RED FLAGS in rules:**

- `allow read, write: if true;` — fully open. CRITICAL.
- `allow read: if true;` — anyone can read everything. CRITICAL.
- `allow read, write;` (no condition) — same as `if true`. CRITICAL.
- Default file from `firebase init` if untouched — usually has `if false` for prod but check.

**SAFE PATTERNS:**

- `allow read, write: if request.auth != null;` — minimum baseline (must be logged in)
- `allow read, write: if request.auth.uid == resource.data.userId;` — only the owner
- Role checks: `request.auth.token.admin == true` for admin-only paths

## Report Firebase findings

If `firestore.rules` or `database.rules.json` contains `if true` for read or write:

**Title:** "Firestore rules allow public read/write to all paths"

**Detail:**
> Your `firestore.rules` (or `database.rules.json`) contains `allow read, write: if true;`. This means anyone on the internet, with no authentication, can:
>
> - Read every document in your Firestore database
> - Write arbitrary data (filling your database, costing you money, defacing your app)
> - Delete documents
>
> **What to do tonight:**
> 1. Open `firestore.rules`. Replace the open `if true` rule with at minimum: `allow read, write: if request.auth != null;`
> 2. For documents that should only be readable by their owner: `allow read: if request.auth.uid == resource.data.userId;`
> 3. Deploy the rules: `firebase deploy --only firestore:rules`
> 4. Verify: from an incognito browser console, run `await firebase.firestore().collection('users').get()`. Should fail.

## Don't false-positive on

- Local Supabase development URLs (`localhost:54321`, `127.0.0.1`) — not a production concern
- `firebase emulator` config — local-only
- Test fixtures that mock Supabase or Firebase
