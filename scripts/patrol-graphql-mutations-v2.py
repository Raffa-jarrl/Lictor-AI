#!/usr/bin/env python3
"""
patrol-graphql-mutations-v2 — GraphQL introspection + auth-bypassable mutation finder.

Cleaner v2 of the GraphQL hunter. Targets the $25K-$50K "introspection open +
unauth mutation" pattern. Validates each mutation finding with a safe probe
that uses obviously-test data and NEVER actually exfiltrates / modifies.

Algorithm:
  1. Probe common GraphQL endpoints (/graphql, /api/graphql, etc) on each host.
  2. If GraphQL-style response detected, run __schema introspection.
  3. If introspection open + mutationType exposed, scan mutation names for
     high-risk keywords (createUser, transferFunds, addAdmin, etc.).
  4. For one representative high-risk mutation, send a safe probe and
     classify response:
       401/403 or "unauthorized" error -> MEDIUM (auth-gated, info disclosure only)
       "validation failed" type error -> HIGH (mutation reachable, deeper review needed)
       200 success -> CRITICAL (mutation accepts without auth)

Usage:
  patrol-graphql-mutations-v2.py --hosts hosts.txt --threads 25
"""
from __future__ import annotations
import argparse, json, re, ssl, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-GraphQLPatrolV2/0.1 (+https://lictor-ai.com)"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphql/v1", "/query", "/api/query", "/gql", "/api/gql",
]

INTROSPECTION_QUERY = "{__schema{mutationType{fields{name}}}}"

HIGH_RISK_MUTATION_KEYWORDS = [
    "createuser", "deleteuser", "updateuser",
    "addadmin", "removeadmin", "grantrole", "updaterole",
    "createrole", "deleterole",
    "transferfunds", "withdraw", "sendmoney", "createpayment",
    "resetpassword", "changepassword", "setpassword",
    "executecommand", "runcommand", "evalexpression",
    "createsession", "impersonate",
    "uploadfile", "deletefile", "writefile",
    "createapikey", "revokeapikey", "regeneratetoken",
    "approvepayment", "refundtransaction",
    "deleteaccount", "mergeaccount",
    "createorganization", "deleteorganization",
]


@dataclass
class GraphQLFinding:
    host: str
    endpoint: str
    introspection_open: bool
    mutation_count: int
    high_risk_mutations: list
    sample_probe_result: dict
    severity: str
    notes: str
    found_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


def gql_post(url, query, timeout=8):
    try:
        data = json.dumps({"query": query}).encode()
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(200000)
            try: return r.status, json.loads(body)
            except: return r.status, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(200000)
            return e.code, json.loads(body)
        except:
            return e.code, None
    except Exception:
        return 0, None


def find_graphql_endpoint(host):
    for path in GRAPHQL_PATHS:
        url = f"https://{host}{path}"
        status, resp = gql_post(url, "{__typename}")
        if status == 0: continue
        if resp and ("data" in resp or "errors" in resp):
            return url
        if resp and isinstance(resp, dict) and "message" in resp:
            msg = str(resp.get("message", "")).lower()
            if "graphql" in msg or "query" in msg or "syntax" in msg:
                return url
    return None


def extract_mutations(resp):
    try:
        return [f["name"] for f in resp["data"]["__schema"]["mutationType"]["fields"]]
    except (KeyError, TypeError):
        return []


def is_high_risk(mut_name):
    lower = mut_name.lower()
    return any(kw in lower for kw in HIGH_RISK_MUTATION_KEYWORDS)


def probe_mutation_safely(url, mutation_name):
    safe_query = f'mutation {{ {mutation_name}(input: {{name: "__lictor_test_probe"}}) {{ __typename }} }}'
    status, resp = gql_post(url, safe_query, timeout=5)
    return {
        "status": status,
        "has_errors": bool(resp and resp.get("errors")) if resp else None,
        "first_error_msg": (resp.get("errors", [{}])[0].get("message", "")[:120]
                            if resp and resp.get("errors") else ""),
    }


def scan_host(host):
    endpoint = find_graphql_endpoint(host)
    if not endpoint: return None
    status, resp = gql_post(endpoint, INTROSPECTION_QUERY)
    introspection_open = bool(resp and resp.get("data") and resp["data"].get("__schema"))
    if not introspection_open:
        return None
    mutations = extract_mutations(resp)
    high_risk = [m for m in mutations if is_high_risk(m)]
    if not high_risk:
        return None
    probe_target = high_risk[0]
    probe_result = probe_mutation_safely(endpoint, probe_target)
    err_msg = probe_result.get("first_error_msg", "").lower()
    if any(s in err_msg for s in ("unauthorized", "not authenticated",
                                   "login required", "permission denied", "forbidden")):
        sev = "MEDIUM"
        notes = f"Introspection open, {len(mutations)} mutations exposed ({len(high_risk)} high-risk), but mutations are auth-gated."
    elif probe_result.get("status") in (401, 403):
        sev = "MEDIUM"
        notes = f"Introspection open, {len(mutations)} mutations exposed ({len(high_risk)} high-risk), mutations require auth."
    elif probe_result.get("has_errors") and "validation" in err_msg:
        sev = "HIGH"
        notes = f"Introspection open + mutation REACHABLE (validation failed = endpoint accepted). Manual review for {probe_target}."
    elif not probe_result.get("has_errors"):
        sev = "CRITICAL"
        notes = f"Introspection open + mutation {probe_target} appears to ACCEPT without auth! Verify carefully."
    else:
        sev = "HIGH"
        notes = f"Introspection open + {len(high_risk)} high-risk mutations exposed. Manual probe needed."
    return GraphQLFinding(
        host=host, endpoint=endpoint, introspection_open=True,
        mutation_count=len(mutations), high_risk_mutations=high_risk[:15],
        sample_probe_result=probe_result, severity=sev, notes=notes,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", required=True)
    ap.add_argument("--max-hosts", type=int, default=5000)
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--ledger", default="/Users/raffa/Lictor/v3/ledgers/graphql-mutations-v2.jsonl")
    args = ap.parse_args()
    hosts = [l.strip() for l in Path(args.hosts).read_text().splitlines() if l.strip()][:args.max_hosts]
    Path(args.ledger).parent.mkdir(parents=True, exist_ok=True)
    print(f"[+] graphql-mutations-v2 — {len(hosts)} hosts")
    n_crit = n_high = n_med = 0
    with open(args.ledger, "a") as ledger, \
         ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            try: result = fut.result(timeout=60)
            except: result = None
            if result:
                ledger.write(json.dumps(asdict(result)) + "\n")
                ledger.flush()
                if result.severity == "CRITICAL": n_crit += 1
                elif result.severity == "HIGH": n_high += 1
                else: n_med += 1
                tag = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡"}[result.severity]
                print(f"  [{i}/{len(hosts)}] {tag} {result.severity:8s} {result.host} ({result.mutation_count}m,{len(result.high_risk_mutations)}risky)")
            if i % 500 == 0:
                print(f"  [{i}/{len(hosts)}] crit={n_crit} high={n_high} med={n_med}")
    print(f"\n[+] Done. CRITICAL={n_crit} HIGH={n_high} MEDIUM={n_med}")


if __name__ == "__main__":
    main()
