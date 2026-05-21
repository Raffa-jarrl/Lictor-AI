#!/usr/bin/env python3
"""
Lictor v3 — typo-bucket MEGA scanner (200+ vendors, run for hours)

The "find another atlassian-backup / splunk-production" hunter at scale.

Strategy: massively expand the vendor list across every SaaS / enterprise
category, every plausible suffix, every cloud provider where buckets exist.
Conservative — only flags buckets that are publicly-listable AND contain
at least one key.

Run:
  python3 patrol-typo-buckets-mega.py                    # full mega run (~6+ hours)
  python3 patrol-typo-buckets-mega.py --vendor databricks
  python3 patrol-typo-buckets-mega.py --workers 40
"""
from __future__ import annotations
import argparse, json, re, ssl, sys, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-v3-TypoBucketMega/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / "Lictor" / "v3" / "ledgers" / "typo-bucket-candidates.jsonl"

# 100+ vendors across every SaaS/enterprise category. Each maps to ~5-10 typo variants.
VENDOR_TYPOS = {
    # Data infra & analytics
    "atlassian":   ["atlassain", "attlasian", "atlsasian", "attlassian", "atlassion", "atalssian", "atlasian", "altassian"],
    "snowflake":   ["snowfake", "snwflake", "snowflk", "snowfaker", "snwflk"],
    "databricks":  ["databriks", "databrcks", "datbricks", "datbricks", "databrickss"],
    "tableau":     ["tablau", "tableu", "tableo", "tablaeu"],
    "looker":      ["lookr", "lookerr", "lookr-data"],
    "dbt":         ["dbtt", "dbtcloud", "dbtcore"],
    "airflow":     ["airflw", "airflo", "arflow", "airfloww"],
    "kafka":       ["kakfa", "kfka", "kafa", "kaffka", "kafkaa"],
    "hadoop":      ["hadop", "hadoopp", "hadoo", "hadoof"],
    "spark":       ["sprk", "sparcc", "spakr", "sparkk"],
    "fivetran":    ["fivtran", "fivetrn", "fivetrans"],
    "segment":     ["segmnt", "segemnt", "segmentt"],
    "mixpanel":    ["mxpanel", "mixpnel", "mixpanl"],
    "amplitude":   ["amplitde", "amptd", "amplitudee"],
    "metabase":    ["metbase", "metabse"],
    "elasticsearch":["elastcsearch", "elasticserch", "elastiserch", "esearch"],
    "elastic":     ["elstic", "elstc", "elasticc"],
    "kibana":      ["kibna", "kibanaa", "kibna"],
    "logstash":    ["logstsh", "logsash", "logstah"],

    # Databases
    "postgres":    ["postgress", "postres", "postrges", "pgsql", "psql"],
    "mongodb":     ["mongdb", "mongbd", "monogo", "monodb", "mngo"],
    "redis":       ["reedis", "rdis", "redss"],
    "mysql":       ["mysl", "mysql", "myslq"],
    "mariadb":     ["mariad", "marriad", "mariaddb"],
    "cassandra":   ["casandra", "cassendra"],
    "couchbase":   ["couchbas", "couchbasee", "ccouchbase"],
    "neo4j":       ["neo4", "neo4j", "neo-4j"],
    "clickhouse":  ["clickhose", "clikhouse", "clickhouseee"],
    "cockroachdb": ["cockroachdbb", "crdb"],
    "rabbitmq":    ["rbbitmq", "rabittmq", "rabbtmq", "rabbtmqq"],

    # DevOps / Infrastructure
    "jenkins":     ["jenkns", "jeenkins", "jnkins", "jenkinns", "jenkis"],
    "gitlab":      ["gitlb", "gitlabs", "gtilab", "gtlab", "gilab"],
    "github":      ["gthub", "githb", "gitub"],
    "bitbucket":   ["bitbuket", "bitbukcet", "bitbuckt", "bitbckt"],
    "gerrit":      ["gerit", "gerritt"],
    "kubernetes":  ["kubernets", "kuberntes", "kuberenetes", "kubrnetes", "k8s"],
    "docker":      ["dockr", "dockerr", "dockerregistry"],
    "circleci":    ["circci", "circlci", "circle-ci"],
    "travis":      ["travisci", "travis-ci"],
    "drone":       ["dronee", "droneci", "drone-ci"],
    "concourse":   ["concrse", "concours"],
    "buildkite":   ["buildkit", "buildkitt"],
    "argocd":      ["argo-cd", "argocdd"],
    "flux":        ["fluxcd", "flux2"],
    "ansible":     ["ansibe", "ansibll", "ansiblee"],
    "puppet":      ["pupet", "puppett"],
    "chef":        ["cheff", "chefdk"],
    "saltstack":   ["saltstck", "salt-stack"],
    "terraform":   ["teraform", "terrafrm", "terraforme"],
    "consul":      ["counsul", "concul", "consl"],
    "vault":       ["valt", "vaullt", "vault-cloud"],
    "nomad":       ["nomd", "nommad", "nomad-cloud"],

    # Monitoring & observability
    "prometheus":  ["prometeus", "promethus", "prometheous", "promethes"],
    "grafana":     ["grfana", "grafna", "grafanna", "grafanaa", "grafan"],
    "datadog":     ["datdog", "datadogg", "datadg", "datadgg"],
    "newrelic":    ["newrlic", "newreelic", "new-relic"],
    "honeycomb":   ["honycomb", "honeyccomb"],
    "splunk":      ["spunk", "splnk", "splnkr", "splnks", "splunks"],
    "loki":        ["lokii", "lokiiii"],
    "jaeger":      ["jager", "jaegerr"],
    "sumologic":   ["sumolgic", "sumolog"],

    # Security
    "cyberark":    ["cybark", "cybarkark", "cyperark"],
    "sentinelone": ["sentnelone", "sentinelones", "sentinone"],
    "crowdstrike": ["crowstrike", "crowdstr", "crwdstrike"],
    "wiz":         ["wiz-data", "wiz-prod", "wizcloud", "wizsecurity"],
    "snyk":        ["snyk-data", "snyk-prod", "snk", "snykcloud"],
    "tenable":     ["tnable", "tenble", "tenablee"],
    "qualys":      ["qualyss", "qualy", "qaulys"],
    "rapid7":      ["rapid-7", "rapid77"],
    "okta":        ["oktaa", "ocata", "okta-data", "okta-prod"],
    "auth0":       ["auth00", "athu0", "auth-zero", "authzero"],
    "duo":         ["duosec", "duo-security"],
    "yubico":      ["yubic", "yubikey"],
    "1password":   ["1passwrd", "onepassword", "1pass"],
    "lastpass":    ["lstpass", "last-pass"],
    "bitwarden":   ["bitwardn", "bit-warden"],
    "hashicorp":   ["hasicorp", "hashcorp", "hashicrp"],

    # Identity & access
    "jumpcloud":   ["jumpclod", "jumpcoud", "jumpcld"],
    "saviynt":     ["savynt", "saviyntt"],
    "beyondtrust": ["beyondtrst", "beondtrust"],
    "delinea":     ["delinia", "delineaa"],
    "ping":        ["pingidentity", "ping-identity", "pingid"],
    "forgerock":   ["forge-rock", "forgrock"],
    "centrify":    ["cntrify", "centerify"],

    # Productivity / collab
    "notion":      ["notio", "notionn", "ntion"],
    "slack":       ["slak", "slck", "slackk"],
    "asana":       ["asanaa", "asna", "assana"],
    "monday":      ["mondayy", "monay"],
    "trello":      ["trelo", "trllo"],
    "clickup":     ["clikup", "click-up"],
    "linear":      ["linerr", "lineaer"],
    "jira":        ["jria", "jirra", "jiraa", "jirah"],
    "confluence":  ["conflunce", "confleunce", "confulence", "conflueence", "conflug"],
    "miro":        ["miroo", "miorr"],
    "figma":       ["figmaa", "figmaaa"],
    "airtable":    ["airtbl", "airtablle"],
    "coda":        ["codaa", "codaaa"],

    # CRM / sales
    "salesforce":  ["salseforce", "salesforse", "salesfoce", "salesforece", "sfdc"],
    "hubspot":     ["hubsot", "hubspott", "hub-spot"],
    "zendesk":     ["zendes", "zendisk", "zendssk"],
    "freshworks":  ["freshwrks", "freshwoks"],
    "intercom":    ["inercom", "interom"],
    "pipedrive":   ["pipdrive", "pipedrve"],
    "zoho":        ["zhho", "zoh"],

    # Marketing
    "mailchimp":   ["mailchmp", "mailchmip", "mail-chimp"],
    "sendgrid":    ["sengrid", "sendgrd", "send-grid"],
    "klaviyo":     ["klavio", "klaviiyo"],
    "mailgun":     ["mailgn", "mail-gun"],
    "twilio":      ["twillio", "twlio", "twilo", "twillo"],
    "intercom-data":["intrcom-data"],

    # Finance
    "stripe":      ["stipe", "strpe", "stripee", "stripp"],
    "paypal":      ["paypall", "papyal", "pay-pal"],
    "plaid":       ["plad", "plaiid"],
    "square":      ["squar", "squaree"],
    "adyen":       ["adyn", "adyens"],
    "chargebee":   ["chargbe", "chargebbe"],
    "recurly":     ["recrly", "recurlyy"],

    # Communication
    "discord":     ["discrod", "discord-bot"],
    "telegram":    ["telgrm", "tlegram"],
    "whatsapp":    ["wtsapp", "whatap"],

    # Storage / backup
    "dropbox":     ["dropbx", "dropboxx"],
    "box":         ["boxx", "box-data"],
    "onedrive":    ["one-drive", "oneddrive"],
    "wetransfer":  ["wetransf", "wetransfr"],

    # Vendor giants
    "oracle":      ["oracl", "oarcle", "ocrale", "orcl"],
    "ibm":         ["iibm", "ibm-data", "ibm-prod", "ibm-cloud"],
    "sap":         ["sapdata", "saperp", "sapprod", "sapp"],
    "vmware":      ["vmwre", "vmwere", "vware", "vmwarre"],
    "cisco":       ["csico", "ciscoo", "cisko", "cico"],
    "juniper":     ["junpier", "juniprr", "junipr"],
    "fortinet":    ["fortnet", "fortinte", "fortinte"],
    "paloalto":    ["paloato", "palaoto"],
    "microsoft":   ["mcrosoft", "mcrsft", "microft"],
    "amazon":      ["amzon", "amzn", "amazoncloud"],
    "google":      ["gogle", "gooogle", "googlecloud"],

    # Open source projects
    "wordpress":   ["wordpres", "wp", "wordpresss"],
    "drupal":      ["druple", "drupall"],
    "magento":     ["magneto", "magent"],
    "shopify":     ["shopfy", "shopifyy"],
    "woocommerce": ["wocom", "woo-commerce"],
    "joomla":      ["jomla", "joomlla"],

    # Devtools
    "sentry":      ["sntry", "senrty"],
    "rollbar":     ["rolbar", "rollbarr"],
    "bugsnag":     ["bugsng", "bugnag"],
    "logrocket":   ["logrocet", "log-rocket"],
    "fullstory":   ["fullstry", "full-story"],

    # Generic but useful
    "backup":      ["backups", "bakup", "bcaup"],
    "archive":     ["archives", "arcive", "archve"],
    "data":        ["datas", "dta", "dataa"],
}

# 25 suffixes covering every backup / data / environment pattern
SUFFIXES = [
    # Environment
    "-prod", "-production", "-staging", "-stage", "-dev", "-development",
    "-test", "-testing", "-qa", "-uat", "-preprod", "-prerelease",
    # Backup / data
    "-backup", "-backups", "-data", "-db", "-database", "-dump",
    "-snapshot", "-archive", "-archives", "-export", "-exports",
    "-recovery", "-restore", "-migration", "-old", "-legacy",
    "-bak", "-bk", "-tmp", "-temp",
    # Versioning
    "-v1", "-v2", "-v3",
    # Generic
    "-storage", "-files", "-media", "-uploads", "-documents",
    "-reports", "-logs", "-public", "-private",
    # No suffix (vendor name alone)
    "",
]

# 8 cloud-storage providers — covers most enterprise self-hosting choices
PROVIDERS = [
    ("aws-s3",            "https://{name}.s3.amazonaws.com/?list-type=2&max-keys=1"),
    ("aws-s3-alt",        "https://s3.amazonaws.com/{name}/?list-type=2&max-keys=1"),
    ("gcs",               "https://storage.googleapis.com/{name}/?list-type=2&max-keys=1"),
    ("azure-blob",        "https://{name}.blob.core.windows.net/?restype=container&comp=list&maxresults=1"),
    ("do-spaces-nyc3",    "https://{name}.nyc3.digitaloceanspaces.com/?list-type=2&max-keys=1"),
    ("do-spaces-sfo3",    "https://{name}.sfo3.digitaloceanspaces.com/?list-type=2&max-keys=1"),
    ("do-spaces-ams3",    "https://{name}.ams3.digitaloceanspaces.com/?list-type=2&max-keys=1"),
    ("wasabi-us-east-1",  "https://s3.us-east-1.wasabisys.com/{name}/?list-type=2&max-keys=1"),
]


def _fetch(url: str, timeout: int = 4) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2000).decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return 0, ""


def _check_bucket(provider: str, url_template: str, bucket_name: str) -> dict | None:
    url = url_template.format(name=bucket_name)
    status, body = _fetch(url)
    if status != 200:
        return None
    if "<ListBucketResult" not in body and "<EnumerationResults" not in body:
        return None
    keys = re.findall(r'<(?:Key|Name)>([^<]+)</(?:Key|Name)>', body)
    keys = [k for k in keys if k != bucket_name]
    if not keys:
        return None
    return {
        "provider": provider,
        "bucket": bucket_name,
        "url": url,
        "status": status,
        "sample_keys": keys[:5],
        "discovered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _generate_names(vendors: list[str]) -> list[str]:
    names = set()
    for vendor in vendors:
        if vendor not in VENDOR_TYPOS:
            for sfx in SUFFIXES:
                names.add(vendor + sfx)
            continue
        all_variants = [vendor] + VENDOR_TYPOS[vendor]
        for variant in all_variants:
            for sfx in SUFFIXES:
                names.add(variant + sfx)
    return sorted(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", help="Only probe one vendor's typos")
    ap.add_argument("--workers", type=int, default=30)
    args = ap.parse_args()

    vendors = [args.vendor] if args.vendor else list(VENDOR_TYPOS.keys())
    names = _generate_names(vendors)
    print(f"[+] MEGA scan — {len(vendors)} vendors, {len(SUFFIXES)} suffixes, {len(PROVIDERS)} providers", flush=True)
    print(f"[+] Generated {len(names):,} candidate bucket names", flush=True)
    print(f"[+] Total probes: {len(names) * len(PROVIDERS):,}", flush=True)
    print(f"[+] At {args.workers} workers × ~0.5s/probe = ~{len(names) * len(PROVIDERS) / args.workers / 60 / 2:.0f} min ETA", flush=True)

    jobs = [(provider, tmpl, name) for (provider, tmpl) in PROVIDERS for name in names]
    findings = []
    completed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(_check_bucket, p, t, n): (p, n) for p, t, n in jobs}
        for fut in as_completed(futures):
            completed += 1
            if completed % 2000 == 0:
                print(f"  [{completed:,}/{len(jobs):,}] checked, {len(findings)} hits so far", flush=True)
            try:
                result = fut.result(timeout=15)
            except Exception:
                continue
            if result:
                provider = result["provider"]
                bucket = result["bucket"]
                keys = result["sample_keys"]
                print(f"  🟡 BUCKET-HIT  {provider}://{bucket}  ({len(keys)} keys: {', '.join(k[:40] for k in keys[:2])})", flush=True)
                findings.append(result)

    print(f"\n[+] MEGA scan complete: {len(findings)} publicly-listable typo buckets found", flush=True)

    if findings:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with LEDGER.open("a") as f:
            for hit in findings:
                f.write(json.dumps(hit) + "\n")
        print(f"[+] Wrote {len(findings)} entries to {LEDGER}", flush=True)


if __name__ == "__main__":
    main()
