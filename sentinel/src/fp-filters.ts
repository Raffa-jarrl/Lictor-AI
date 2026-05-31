/**
 * False-positive filters for @lictor/sentinel.
 *
 * Ported from the Lictor scanner's canonical FP knowledge base
 * (scripts/lictor_fp.py). These are the runtime-relevant classes: strings that
 * MATCH a secret pattern but are public-by-design, so flagging them as a leaked
 * credential is noise. A security tool that cries wolf gets uninstalled — low
 * false-positive rate is the product's moat.
 *
 * Provenance: each class learned from a real disclosure or triager N/A during
 * the 2026-05 Lictor disclosure campaign (e.g. reports.remax.co.il Sentry DSN,
 * Firebase public-config guidance). Keep in lockstep with scripts/lictor_fp.py.
 */

/**
 * Secret values that are PUBLIC BY DESIGN — intended to ship in client-side code.
 * Matching one of these is not a leak.
 */
const PUBLIC_BY_DESIGN_VALUE = [
  // Sentry DSN — the browser SDK requires the DSN in client JS (https://docs.sentry.io)
  /^https:\/\/[a-f0-9]+@[a-z0-9.-]+\.ingest\.sentry\.io\/\d+$/i,
  /^https:\/\/[a-f0-9]+@(?:o\d+\.)?sentry\.io\/\d+$/i,
  // NOTE: Stripe pk_live_/pk_test_ are deliberately NOT suppressed here — Sentinel
  // flags them at "info" severity (awareness that a Stripe key is in the prompt,
  // even the public half). That's more useful than silent suppression.
  // Google Analytics / GTM / Measurement IDs — public identifiers
  /^(?:G-[A-Z0-9]{8,}|UA-\d{4,}-\d+|GTM-[A-Z0-9]{4,})$/,
  // Mapbox public token
  /^pk\.[A-Za-z0-9._-]{50,}$/,
  // reCAPTCHA site key (public half)
  /^6L[A-Za-z0-9_-]{38}$/,
];

/**
 * Env-var name prefixes whose values are inlined into the client bundle by the
 * build tool — public by framework design, never a server secret.
 */
const PUBLIC_ENV_PREFIX =
  /(?:^|[^A-Z_])(VITE_|NEXT_PUBLIC_|REACT_APP_|GATSBY_|PUBLIC_|VUE_APP_|EXPO_PUBLIC_|NG_)[A-Z0-9_]*\s*[:=]/;

/**
 * Returns true if the matched secret value is public-by-design and should NOT
 * be treated as a leaked credential.
 */
export function isPublicByDesignValue(value: string): boolean {
  return PUBLIC_BY_DESIGN_VALUE.some((re) => re.test(value));
}

/**
 * Returns true if the matched value appears immediately after a public env-var
 * prefix in the surrounding text (e.g. `VITE_API_KEY=AIza...`), meaning it's a
 * build-time public value, not a server secret.
 *
 * `context` is a small window of text around the match (caller supplies ~40
 * chars before the match).
 */
export function isPublicEnvContext(context: string): boolean {
  return PUBLIC_ENV_PREFIX.test(context);
}

/**
 * Firebase web config: the `apiKey` field in a firebaseConfig object is NOT a
 * secret (Firebase docs are explicit). Detect the surrounding firebaseConfig
 * shape so an `AIza...` key inside it isn't flagged as a leaked Google API key.
 */
export function isFirebasePublicConfig(context: string): boolean {
  return /(firebaseConfig|apiKey\s*[:=]\s*["'])/.test(context);
}

/**
 * Top-level: given a matched secret value and the text window around it, decide
 * whether this match is a known false positive that should be suppressed.
 * Returns { fp: boolean, reason?: string }.
 */
export function isFalsePositiveSecret(
  value: string,
  context: string,
): { fp: boolean; reason?: string } {
  if (isPublicByDesignValue(value)) {
    return { fp: true, reason: "public-by-design value (Sentry DSN / pk_live / analytics ID)" };
  }
  if (isPublicEnvContext(context)) {
    return { fp: true, reason: "public build-time env prefix (VITE_/NEXT_PUBLIC_/etc)" };
  }
  if (isFirebasePublicConfig(context) && /^AIza/.test(value)) {
    return { fp: true, reason: "Firebase web config apiKey (public per Firebase docs)" };
  }
  return { fp: false };
}
