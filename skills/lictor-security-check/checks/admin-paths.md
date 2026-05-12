# Check 5 — Client-side-only auth gates

**What you're looking for:** Admin pages, settings pages, or any sensitive UI that is "protected" by JavaScript redirecting the user away in `useEffect` — but where the HTML and JavaScript bundle have ALREADY been shipped to the browser. The data was fetched. The user just doesn't see it.

This is the most common vibe-coded SaaS bug after unauthenticated API routes. AI assistants frequently generate "redirect if not logged in" patterns that run *in the browser* instead of on the server, because that's what was in their training data.

## How to scan

```bash
# Find admin / dashboard pages
find . -path ./node_modules -prune -o \
  \( -name 'admin' -type d -o -path '*admin*' -name 'page.tsx' \
     -o -path '*dashboard*' -name 'page.tsx' \
     -o -path '*settings*' -name 'page.tsx' \) \
  -print 2>/dev/null | head -20

# Look for the "redirect via useEffect" anti-pattern
grep -rEn --include='*.tsx' --include='*.jsx' --exclude-dir={node_modules,.next,dist} \
  'useEffect.*router\.(push|replace)|router\.(push|replace).*useEffect' \
  . 2>/dev/null | head -10

# Look for "if (!user) redirect()" patterns in CLIENT components
grep -rEn --include='*.tsx' --include='*.jsx' --exclude-dir={node_modules,.next,dist} \
  -B1 '(if|when)\s*\(\s*!?(user|session|isAuthenticated|isLoggedIn)\s*\)' \
  . 2>/dev/null | head -20
```

## The anti-pattern

In a file that starts with `"use client"` (Next.js) or is a vanilla React component, you'll see:

```tsx
"use client";

export default function AdminPage() {
  const { user } = useUser();

  useEffect(() => {
    if (!user) router.push("/login");
  }, [user]);

  if (!user) return null;

  return <AdminPanel users={users} />;  // <-- ALREADY in the bundle
}
```

**Why this is broken:**

1. The browser downloads the JavaScript bundle for `AdminPage`.
2. That bundle includes the import for `AdminPanel`, which includes its imports, which include the `users` data fetch.
3. The user (attacker) opens DevTools → Network tab → sees the request to fetch users, OR opens Sources → reads the bundled code containing whatever was supposed to be admin-only.
4. The `router.push("/login")` happens. The user is redirected.
5. But they already have the data.

## The correct pattern

Server-render the auth check before the page is sent:

```tsx
// app/admin/page.tsx — NO "use client" at the top
import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";

export default async function AdminPage() {
  const session = await auth();
  if (!session || session.user.role !== "admin") redirect("/login");

  // Data fetch happens server-side; never sent to unauthorized users.
  const users = await db.user.findMany();
  return <AdminPanel users={users} />;
}
```

Or via middleware:

```ts
// middleware.ts
export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/admin")) {
    const session = await getSession(request);
    if (!session) return NextResponse.redirect(new URL("/login", request.url));
  }
}
export const config = { matcher: ["/admin/:path*"] };
```

## Report a finding as

**Title:** "Admin page only protected by client-side redirect"

**Detail:**
> `src/app/admin/page.tsx` is marked `"use client"` and protects itself with `useEffect(() => { if (!user) router.push("/login") })`. This is a client-side-only check.
>
> The problem: when someone navigates to `https://yourapp.com/admin`, your server sends them:
> - The HTML for the admin page
> - The JavaScript bundle containing `AdminPanel` and its imports
> - Often, the initial data fetch is in the bundle too
>
> The user's browser THEN runs the useEffect, sees they're not logged in, and redirects. But the data has already been sent. An attacker who:
> 1. Visits `/admin`
> 2. Opens DevTools → Network → kills the redirect
> 3. Reads the data from the network response, OR reads the JS bundle in Sources
>
> ...gets everything the admin page was supposed to show.
>
> **What to do tonight:**
> 1. Delete the `"use client"` directive from the page file.
> 2. Make the component an `async` server component:
>    ```ts
>    import { redirect } from "next/navigation";
>    import { auth } from "@/lib/auth";  // your auth helper
>
>    export default async function AdminPage() {
>      const session = await auth();
>      if (!session || session.user.role !== "admin") redirect("/login");
>      const data = await db.something.findMany();
>      return <AdminPanel data={data} />;
>    }
>    ```
> 3. Verify: open an incognito window, navigate to `/admin`. You should get a 302 redirect or a Next.js redirect *before* any admin UI HTML reaches you. Use DevTools Network → check the response of the initial document request.
>
> Same fix applies to `/settings`, `/dashboard/admin`, `/account/admin`, and any other sensitive page using the client-side-only pattern.

## Don't false-positive on

- Pages that are CONTENT-only (marketing pages, blog posts) — useEffect redirect here is fine because there's nothing to leak.
- Pages where the only thing rendered is `<Spinner />` until the auth check completes — those don't leak data, just have a UX hiccup. Note in the report but treat as INFO not HIGH.
- Pages that show "Sign in to continue" instead of redirecting — these don't leak.
