/**
 * Server-side auth helper. Pulls the session cookie from `next/headers`
 * and resolves it to an account, or null if not signed in.
 *
 * Use in server components and route handlers:
 *
 *   const session = await getSession();
 *   if (!session) redirect("/");
 */

import { cookies } from "next/headers";
import { SESSION_COOKIE, loadSession } from "./sessions";

export interface ServerSession {
  sessionId: string;
  accountId: string;
  email: string;
}

/**
 * Returns the current request's session, or null if not signed in / invalid.
 *
 * In a server component, this requires Next.js's dynamic API
 * (`cookies()` from "next/headers"). The page will be rendered dynamically
 * for any caller using this helper.
 */
export async function getSession(): Promise<ServerSession | null> {
  const cookieStore = await cookies();
  const cookie = cookieStore.get(SESSION_COOKIE);
  return loadSession(cookie?.value);
}
