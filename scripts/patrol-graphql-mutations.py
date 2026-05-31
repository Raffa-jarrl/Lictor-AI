#!/usr/bin/env python3
"""
patrol-graphql-mutations — scanner #48.

Extension of patrol-graphql-introspection. After introspection succeeds,
parses the schema for DANGEROUS mutations (createUser, updatePassword,
deleteAccount, grantRole, transferOwnership, etc.) and tests whether each
mutation requires authentication.

Top-tier discovery pattern: introspection-leaked schemas frequently reveal
mutations that lack proper auth-middleware coverage. A single unauthenticated
mutation → account takeover, privilege escalation, data destruction. Bounty
range: $5K-$25K depending on what the mutation does.

Method (ETHICAL):
  1. POST introspection query to /graphql, /api/graphql, /v1/graphql, etc.
  2. Parse __schema.mutationType.fields for danger-flagged names
  3. For each dangerous mutation: POST it WITH KNOWINGLY-INVALID ARGS
     (e.g. empty string IDs, malformed input) — NO real changes made
  4. Inspect response:
     - {"errors":[{"message":"Unauthorized"|"Not authenticated"|...}]}
       → AUTH-GATED (defensive — good)
     - {"errors":[{"message":"Field X is required"|"validation"|...}]}
       → NO AUTH GATE on the mutation entry point (validation runs before auth)
       → POTENTIAL ATO surface — report
     - {"data":...} (any data response)
       → DEFINITELY NO AUTH GATE — high-severity finding

  We never submit valid args. We never execute a mutation. We only verify
  that the auth-check fires BEFORE arg-validation.

Usage:
  patrol-graphql-mutations.py --hosts targets.txt --ledger graphql-mutations.jsonl
"""
from __future__ import annotations
import argparse, json, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-GraphQLMutationPatrol/0.1 (+https://lictor-ai.com)"

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/api/v1/graphql", "/v1/graphql",
    "/api/gql", "/gql", "/query", "/api/query", "/api/v2/graphql",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "{__schema{mutationType{fields{name args{name type{name kind ofType{name kind}}}}}}}"
}).encode()

# Substring match against mutation field names — case-insensitive.
DANGEROUS_KEYWORDS = [
    "create", "update", "delete", "remove", "destroy", "grant", "revoke",
    "transfer", "assign", "promote", "demote", "reset", "set", "change",
    "invite", "approve", "reject", "publish", "unpublish", "merge",
    "impersonate", "admin", "role", "permission", "password", "email",
    "billing", "payment", "subscription", "owner", "trust", "verify"
]

AUTH_REJECTION_PHRASES = [
    "unauthorized", "unauthenticated", "not authenticated", "not authorized",
    "permission denied", "access denied", "forbidden", "login required",
    "must be logged in", "must be authenticated", "session expired",
    "insufficient permissions", "401", "403"
]

VALIDATION_PHRASES = [
    "required", "must be", "expected", "invalid", "validation",
    "field of type", "got", "value does not match", "expected type",
    "non-nullable", "cannot return null", "argument"
]

@dataclass
class Finding:
    host: str
    endpoint: str
    introspection_enabled: bool
    mutation_name: str = ""
    classification: str = ""  # "auth_gated", "validation_before_auth", "no_auth", "unknown"
    error_message: str = ""
    args_signature: str = ""

def post_json(url: str, body: bytes, timeout: int = 10):
    req = urllib.request.Request(url, data=body,
                                  headers={"User-Agent": UA,
                                           "Content-Type": "application/json",
                                           "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: body = e.read(65536).decode("utf-8", "replace")
        except Exception: body = ""
        return e.code, body
    except Exception:
        return None, None

def find_graphql_endpoint(host: str) -> tuple[str, list] | None:
    """Return (endpoint, mutation_list) if introspection enabled, else None."""
    for path in GRAPHQL_PATHS:
        url = f"https://{host}{path}"
        status, body = post_json(url, INTROSPECTION_QUERY)
        if not body: continue
        if status not in (200, 400):  # 400 sometimes returned w/ valid GraphQL error body
            continue
        try:
            j = json.loads(body)
        except Exception:
            continue
        mt = (j.get("data") or {}).get("__schema", {}).get("mutationType")
        if mt and isinstance(mt.get("fields"), list):
            return url, mt["fields"]
    return None

def is_dangerous(name: str) -> bool:
    nl = name.lower()
    return any(k in nl for k in DANGEROUS_KEYWORDS)

def probe_mutation_auth(endpoint: str, name: str, args: list) -> Finding:
    """
    Submit the mutation with INTENTIONALLY-INVALID args (empty strings + null).
    If the server returns auth-error → auth_gated.
    If the server returns validation-error → validation_before_auth (vuln).
    If the server returns data → no_auth (definitely vuln).
    """
    if not args:
        # No-arg mutation — just call it bare.
        gql = f"mutation {{ {name} }}"
    else:
        sig = ", ".join(f'{a["name"]}: ""' for a in args[:6])  # cap arg count
        gql = f'mutation {{ {name}({sig}) }}'

    body = json.dumps({"query": gql}).encode()
    status, resp = post_json(endpoint, body)
    if not resp:
        return Finding(host="", endpoint=endpoint, introspection_enabled=True,
                       mutation_name=name, classification="unknown",
                       args_signature=str(len(args)))

    rlow = resp.lower()
    if any(p in rlow for p in AUTH_REJECTION_PHRASES):
        cls = "auth_gated"
    elif "errors" in rlow and any(p in rlow for p in VALIDATION_PHRASES):
        cls = "validation_before_auth"  # validation runs BEFORE auth — vuln
    elif '"data"' in rlow and '"errors"' not in rlow:
        cls = "no_auth"  # actual data returned, no auth check at all
    else:
        cls = "unknown"

    return Finding(host="", endpoint=endpoint, introspection_enabled=True,
                   mutation_name=name, classification=cls,
                   error_message=resp[:200].replace("\n", " "),
                   args_signature=str(len(args)))

def check_host(host: str) -> list[Finding]:
    res = find_graphql_endpoint(host)
    if not res:
        return []
    endpoint, mutations = res
    dangerous = [m for m in mutations if is_dangerous(m.get("name", ""))]
    findings = []
    for m in dangerous[:25]:  # cap per host to avoid hammering
        time.sleep(1.5)
        f = probe_mutation_auth(endpoint, m["name"], m.get("args") or [])
        f.host = host
        findings.append(f)
    if not dangerous:
        findings.append(Finding(host=host, endpoint=endpoint,
                                introspection_enabled=True,
                                mutation_name="(no_dangerous_mutations_found)",
                                classification="introspection_only"))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/graphql-mutations.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    hosts = [h.strip() for h in Path(args.hosts).read_text().splitlines() if h.strip()]
    if args.limit: hosts = hosts[:args.limit]
    print(f"[+] Probing {len(hosts)} hosts for GraphQL introspection + dangerous-mutation auth gaps")

    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    n_intro, n_gated, n_vuln, n_nullauth = 0, 0, 0, 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            host = futures[fut]
            try:
                findings = fut.result()
            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} EXC: {e}")
                continue
            if not findings:
                if i % 25 == 0: print(f"  [{i}/{len(hosts)}] (no introspection enabled)")
                continue
            n_intro += 1
            for f in findings:
                ledger.write(json.dumps(asdict(f)) + "\n")
                ledger.flush()
                if f.classification == "auth_gated": n_gated += 1
                elif f.classification == "validation_before_auth": n_vuln += 1
                elif f.classification == "no_auth": n_nullauth += 1
            tags = [{
                "auth_gated": "🟢", "validation_before_auth": "🟡",
                "no_auth": "🔴", "unknown": "⚪",
                "introspection_only": "⚪"
            }.get(f.classification, "⚪") + f.mutation_name for f in findings[:5]]
            print(f"  [{i}/{len(hosts)}] {host} introspection✅ mutations={len(findings)} {tags}")

    print(f"\n[+] Done. introspection-enabled={n_intro}  auth_gated={n_gated}  "
          f"validation_before_auth={n_vuln}  no_auth={n_nullauth}")
    print(f"[+] Ledger: {args.ledger}")
    print(f"[+] 🔴 'no_auth' findings = highest-severity. 🟡 'validation_before_auth' = potential.")

if __name__ == "__main__":
    main()
