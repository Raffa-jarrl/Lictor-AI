"""GraphQL introspection scanner — probes /graphql + variants and checks if introspection is enabled.

GraphQL introspection is the schema-exposure feature meant for dev tools. Leaving
it on in production lets attackers map the entire data model, find hidden mutations,
identify auth-bypass paths, etc.

Ethical: sends ONE introspection query per endpoint. Records only: schema field count
+ presence of suspicious mutation names (deleteUser, adminLogin, refund, etc.).
NEVER queries actual data records.
"""
import urllib.request, urllib.error, ssl, json, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-GraphQL/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "graphql-introspection.jsonl"

# Common GraphQL endpoint paths
GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/v1/graphql", "/api/graphql",
    "/v2/graphql", "/v3/graphql", "/query", "/api/query",
    "/gql", "/api/gql",
]

# Minimal introspection query — asks for __schema.types[].name only
INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name } queryType { name } mutationType { name } } }"
}).encode()

# Distinctive mutation/query names that indicate sensitive ops
SENSITIVE_FIELD_NAMES = re.compile(
    r'\b(deleteUser|removeUser|banUser|adminLogin|impersonate|'
    r'refund|chargeCard|createPayment|sendMoney|transfer|withdraw|'
    r'createApiKey|generateToken|resetPassword|changeEmail|'
    r'updateRole|grantPermission|deleteAccount|exportData|'
    r'allUsers|listUsers|getAllUsers|adminUsers|secretKey|'
    r'privateKey|password|creditCard|ssn)\b',
    re.I
)

def fetch_post(url, body, timeout=8):
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, data=body, headers={
            "User-Agent": UA,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(20000)
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(5000)
        except: return e.code, b""
    except Exception:
        return None, b""


def scan_host(host):
    findings = []
    for scheme in ("https", "http"):
        for path in GRAPHQL_PATHS:
            url = f"{scheme}://{host}{path}"
            st, body = fetch_post(url, INTROSPECTION_QUERY)
            if st != 200 or not body: continue
            # Must be JSON
            try:
                data = json.loads(body)
            except: continue
            # Has __schema key in data.data?
            schema = data.get("data", {}).get("__schema") if isinstance(data, dict) else None
            if not schema or "types" not in schema: continue
            # Real introspection enabled!
            types = schema.get("types", [])
            type_names = [t.get("name","") for t in types if isinstance(t, dict)]
            type_count = len(type_names)
            mutation_type = schema.get("mutationType") or {}
            mutation_name = mutation_type.get("name") if isinstance(mutation_type, dict) else None
            # Sensitive field detection in type names
            sensitive_hits = [n for n in type_names if SENSITIVE_FIELD_NAMES.search(n)]
            print(f"  🔴 GRAPHQL-INTROSPECT  {host}{path}  types={type_count}  mutation={mutation_name}  sensitive={len(sensitive_hits)}", flush=True)
            if sensitive_hits:
                print(f"      sensitive: {sensitive_hits[:8]}", flush=True)
            findings.append({
                "type": "graphql-introspection-enabled",
                "host": host, "path": path, "scheme": scheme,
                "type_count": type_count,
                "mutation_type_name": mutation_name,
                "sensitive_field_hits": sensitive_hits[:20],
                "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })
            return findings  # one path is enough per host
    return findings


import sys
with open(sys.argv[1]) as f:
    hosts = [l.strip() for l in f if l.strip()][:int(sys.argv[2]) if len(sys.argv) > 2 else 10000]
print(f"[+] GraphQL introspection scan — {len(hosts)} hosts × {len(GRAPHQL_PATHS)} paths (POST one introspection query per endpoint)", flush=True)
print(f"[+] Ethical: introspection query only (asks schema metadata, not data records)", flush=True)
all_findings = []
completed = 0
with ThreadPoolExecutor(max_workers=25) as pool:
    futures = {pool.submit(scan_host, h): h for h in hosts}
    for fut in as_completed(futures):
        completed += 1
        if completed % 250 == 0:
            print(f"  [{completed}/{len(hosts)}] hosts checked, {len(all_findings)} introspection-enabled", flush=True)
        try:
            r = fut.result(timeout=30)
            if r: all_findings.extend(r)
        except Exception:
            pass

print(f"\n[+] GraphQL scan complete: {len(all_findings)} introspection-enabled endpoints", flush=True)
sensitive_n = sum(1 for f in all_findings if f.get("sensitive_field_hits"))
print(f"[+] {sensitive_n} of those have SENSITIVE field names in schema (admin/payment/PII ops)", flush=True)
if all_findings:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        for fi in all_findings: f.write(json.dumps(fi) + "\n")
    print(f"[+] Wrote to {LEDGER}", flush=True)
