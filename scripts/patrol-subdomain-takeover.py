#!/usr/bin/env python3
"""
patrol-subdomain-takeover — scanner #17.

Discovers dangling subdomain takeovers for bug-bounty companies.

What it does:
  1. For each bounty-program company, pull their public subdomains
     from crt.sh (Certificate Transparency logs)
  2. For each subdomain, resolve DNS — look for CNAMEs pointing at
     known-vulnerable provider patterns (S3, Heroku, GitHub Pages,
     Azure Cloud App, Fastly, Netlify, Vercel, Tumblr, Shopify, etc.)
  3. For each CNAME match, fetch the target URL and check for the
     provider's "not-claimed" fingerprint (e.g., "NoSuchBucket",
     "There isn't a GitHub Pages site here", etc.)
  4. Confirmed takeovers → bounty queue

Why this works for revenue:
  - Bounty programs explicitly accept subdomain takeovers
  - Payouts: $250-$5K per finding
  - Triage is usually fast (1-7 days)
  - Pattern coverage is well-known (https://github.com/EdOverflow/can-i-take-over-xyz)

Cron: 0 6 * * *  (daily, before bounty-hunter)
"""
from __future__ import annotations
import argparse, json, re, socket, subprocess, sys, time, urllib.request, urllib.error, ssl
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

UA = "Lictor-SubdomainPatrol/0.1 (+https://lictor-ai.com)"
LEDGER = Path.home() / ".lictor" / "subdomain-takeover-ledger.jsonl"
OUT_DIR = Path.home() / "Lictor" / "docs" / "launch"

# Fingerprints from can-i-take-over-xyz + manual additions.
# Each entry: (CNAME pattern → response pattern indicating not-claimed)
TAKEOVER_FINGERPRINTS = [
    # === Hosting & CDN ===
    {"provider": "AWS/S3",            "cname_rx": re.compile(r's3[.-].*?\.amazonaws\.com|\.s3-website',     re.I), "body_rx": re.compile(r'(NoSuchBucket|The specified bucket does not exist)', re.I)},
    # CloudFront: only flag genuine "distribution doesn't exist" (Bad request, with no x-amz-cf-id header would be better but we use body only here). The "request could not be satisfied" plus "via: CloudFront" headers means distribution EXISTS — not a takeover. Skip those by requiring the rarer "Bad request" exact wording.
    {"provider": "AWS/CloudFront",    "cname_rx": re.compile(r'cloudfront\.net',                              re.I), "body_rx": re.compile(r"Bad request\.\s*We can't connect to the server for this app", re.I)},
    {"provider": "GitHub Pages",      "cname_rx": re.compile(r'github\.io|githubpages',                      re.I), "body_rx": re.compile(r"There isn't a GitHub Pages site here|For root URLs|Site not Found", re.I)},
    {"provider": "GitLab Pages",      "cname_rx": re.compile(r'gitlab\.io',                                   re.I), "body_rx": re.compile(r"The page you're looking for could not be found", re.I)},
    {"provider": "Heroku",            "cname_rx": re.compile(r'herokuapp\.com|herokudns|herokussl',          re.I), "body_rx": re.compile(r"No such app|There's nothing here|herokucdn", re.I)},
    {"provider": "Fastly",            "cname_rx": re.compile(r'fastly\.net',                                  re.I), "body_rx": re.compile(r"Fastly error: unknown domain", re.I)},
    {"provider": "Bitbucket",         "cname_rx": re.compile(r'bitbucket\.io',                                re.I), "body_rx": re.compile(r"Repository not found", re.I)},
    {"provider": "Surge.sh",          "cname_rx": re.compile(r'surge\.sh',                                    re.I), "body_rx": re.compile(r"project not found", re.I)},
    {"provider": "Vercel",            "cname_rx": re.compile(r'vercel-dns\.com|cname\.vercel-dns|vercel\.app',re.I), "body_rx": re.compile(r"The deployment could not be found|404: NOT_FOUND.*?DEPLOYMENT_NOT_FOUND|This deployment doesn't exist", re.I)},
    {"provider": "Netlify",           "cname_rx": re.compile(r'netlify\.app|netlify\.com',                    re.I), "body_rx": re.compile(r"Not Found - Request ID:", re.I)},
    {"provider": "Cloudflare Pages",  "cname_rx": re.compile(r'pages\.dev',                                   re.I), "body_rx": re.compile(r"The page you are looking for is temporarily unavailable", re.I)},
    {"provider": "Render",            "cname_rx": re.compile(r'onrender\.com|render\.com',                    re.I), "body_rx": re.compile(r"Not Found", re.I)},
    {"provider": "Fly.io",            "cname_rx": re.compile(r'fly\.dev|fly\.io',                             re.I), "body_rx": re.compile(r"app not found|404 Not Found", re.I)},
    {"provider": "DO App Platform",   "cname_rx": re.compile(r'ondigitalocean\.app',                          re.I), "body_rx": re.compile(r"app not found", re.I)},

    # === SaaS / CMS / Blog ===
    {"provider": "Tumblr",            "cname_rx": re.compile(r'domains\.tumblr\.com',                         re.I), "body_rx": re.compile(r"There's nothing here|Whatever you were looking for", re.I)},
    {"provider": "Shopify",           "cname_rx": re.compile(r'myshopify\.com',                               re.I), "body_rx": re.compile(r"Sorry, this shop is currently unavailable", re.I)},
    {"provider": "BigCartel",         "cname_rx": re.compile(r'bigcartel\.com',                               re.I), "body_rx": re.compile(r"<title>404 - Page not found", re.I)},
    {"provider": "Pantheon",          "cname_rx": re.compile(r'pantheonsite\.io|pantheon\.io',                re.I), "body_rx": re.compile(r"The gods are wise, but do not know of the site which you seek|404 not found", re.I)},
    {"provider": "Tilda",             "cname_rx": re.compile(r'tilda\.ws',                                    re.I), "body_rx": re.compile(r"Please renew your subscription", re.I)},
    {"provider": "Ghost",             "cname_rx": re.compile(r'ghost\.io',                                    re.I), "body_rx": re.compile(r"The thing you were looking for is no longer here", re.I)},
    {"provider": "Statuspage",        "cname_rx": re.compile(r'statuspage\.io',                               re.I), "body_rx": re.compile(r"You are being.*redirected.*statuspage", re.I)},
    {"provider": "Unbounce",          "cname_rx": re.compile(r'unbouncepages\.com',                           re.I), "body_rx": re.compile(r"The requested URL was not found|sorry, this page does not exist", re.I)},
    {"provider": "Wordpress",         "cname_rx": re.compile(r'wordpress\.com',                               re.I), "body_rx": re.compile(r"Do you want to register .*?\.wordpress\.com\?", re.I)},
    {"provider": "Tictail",           "cname_rx": re.compile(r'tictail\.com',                                 re.I), "body_rx": re.compile(r"Building a brand of your own", re.I)},
    {"provider": "Strikingly",        "cname_rx": re.compile(r'strikingly\.com|strikinglydns\.com',           re.I), "body_rx": re.compile(r"PAGE NOT FOUND.*?strikingly", re.I)},
    {"provider": "Webflow",           "cname_rx": re.compile(r'proxy.*?\.webflow\.com|proxy-ssl\.webflow',    re.I), "body_rx": re.compile(r"The page you are looking for doesn't exist", re.I)},
    {"provider": "Wix",               "cname_rx": re.compile(r'wixdns\.net|wix\.com',                         re.I), "body_rx": re.compile(r"Looks like this domain isn't connected to a website", re.I)},
    {"provider": "Cargo",             "cname_rx": re.compile(r'cargocollective\.com',                         re.I), "body_rx": re.compile(r"404 Not Found", re.I)},
    {"provider": "Acquia",            "cname_rx": re.compile(r'acquia-sites\.com',                            re.I), "body_rx": re.compile(r"The site you are looking for could not be found", re.I)},
    {"provider": "Squarespace",       "cname_rx": re.compile(r'squarespace\.com|ext\.squarespace',            re.I), "body_rx": re.compile(r"No Such Account", re.I)},
    {"provider": "Smugmug",           "cname_rx": re.compile(r'domains\.smugmug\.com',                        re.I), "body_rx": re.compile(r"Page Not Found", re.I)},

    # === Help/Support/Docs ===
    {"provider": "HelpJuice",         "cname_rx": re.compile(r'helpjuice\.com',                               re.I), "body_rx": re.compile(r"We could not find what you're looking for", re.I)},
    {"provider": "HelpScout",         "cname_rx": re.compile(r'helpscoutdocs\.com',                           re.I), "body_rx": re.compile(r"No settings were found for this company", re.I)},
    {"provider": "GetResponse",       "cname_rx": re.compile(r'getresponse\.com',                             re.I), "body_rx": re.compile(r"With GetResponse Landing Pages, lead", re.I)},
    {"provider": "Smartling",         "cname_rx": re.compile(r'smartling\.com',                               re.I), "body_rx": re.compile(r"Domain is not configured", re.I)},
    {"provider": "Pingdom",           "cname_rx": re.compile(r'stats\.pingdom\.com',                          re.I), "body_rx": re.compile(r"public report page has not been activated", re.I)},
    {"provider": "Zendesk",           "cname_rx": re.compile(r'zendesk\.com',                                 re.I), "body_rx": re.compile(r"Help Center Closed|this help center no longer exists", re.I)},
    {"provider": "UserVoice",         "cname_rx": re.compile(r'uservoice\.com',                               re.I), "body_rx": re.compile(r"This UserVoice subdomain is currently available", re.I)},
    {"provider": "Intercom",          "cname_rx": re.compile(r'custom\.intercom\.help',                       re.I), "body_rx": re.compile(r"This page is reserved for artistic dogs", re.I)},
    {"provider": "Tave",              "cname_rx": re.compile(r'tave\.com',                                    re.I), "body_rx": re.compile(r"<h1>Error 404: Page Not Found</h1>", re.I)},

    # === Email / Marketing ===
    {"provider": "Campaign Monitor",  "cname_rx": re.compile(r'createsend\.com',                              re.I), "body_rx": re.compile(r"Double check the URL or <a href=\"mailto:help@createsend\.com", re.I)},
    {"provider": "Mailgun",           "cname_rx": re.compile(r'mailgun\.org',                                 re.I), "body_rx": re.compile(r"<title>404 Not Found</title>", re.I)},
    {"provider": "SendGrid",          "cname_rx": re.compile(r'sendgrid\.net',                                re.I), "body_rx": re.compile(r"Mail Not Sent", re.I)},

    # === Dev tools / errors / monitoring ===
    {"provider": "Readme.io",         "cname_rx": re.compile(r'readme\.io',                                   re.I), "body_rx": re.compile(r"Project doesnt exist", re.I)},
    {"provider": "Readthedocs",       "cname_rx": re.compile(r'readthedocs\.io|readthedocs\.org',             re.I), "body_rx": re.compile(r"Unknown Domain", re.I)},
    {"provider": "JetBrains Space",   "cname_rx": re.compile(r'jetbrains\.space',                             re.I), "body_rx": re.compile(r"is not a registered", re.I)},
    {"provider": "Launchrock",        "cname_rx": re.compile(r'launchrock\.com',                              re.I), "body_rx": re.compile(r"It looks like you may have taken a wrong turn", re.I)},
    {"provider": "Brightcove",        "cname_rx": re.compile(r'brightcovegallery\.com|bcvp0rtal\.com',        re.I), "body_rx": re.compile(r"<p class=\"bc-gallery-error-code\">Error Code: 404</p>", re.I)},
    {"provider": "Hatena Blog",       "cname_rx": re.compile(r'hatenablog\.com',                              re.I), "body_rx": re.compile(r"404 Blog is not found", re.I)},
    {"provider": "Webhostbox",        "cname_rx": re.compile(r'webhostbox\.net',                              re.I), "body_rx": re.compile(r"The page you were looking for doesn", re.I)},
    {"provider": "Worksites.net",     "cname_rx": re.compile(r'worksites\.net',                               re.I), "body_rx": re.compile(r"Hello! Sorry, but this website is", re.I)},
    {"provider": "Tilda",             "cname_rx": re.compile(r'cdn-tilda\.com',                               re.I), "body_rx": re.compile(r"Please renew your subscription", re.I)},
    {"provider": "WPEngine",          "cname_rx": re.compile(r'wpengine\.com',                                re.I), "body_rx": re.compile(r"The site you were looking for couldn't be found", re.I)},

    # === Generic NXDOMAIN with NS pointing at provider (broad signal) ===
    {"provider": "JetBrains YouTrack","cname_rx": re.compile(r'myjetbrains\.com',                             re.I), "body_rx": re.compile(r"is not a registered InCloud YouTrack", re.I)},
    {"provider": "Pageclip",          "cname_rx": re.compile(r'pageclip\.co',                                 re.I), "body_rx": re.compile(r"The page you're looking for could not be found", re.I)},
    {"provider": "Aha!",              "cname_rx": re.compile(r'ideas\.aha\.io',                               re.I), "body_rx": re.compile(r"There is no portal here", re.I)},
    {"provider": "Anima",             "cname_rx": re.compile(r'animaapp\.com',                                re.I), "body_rx": re.compile(r"If this is your website", re.I)},
    {"provider": "Frontify",          "cname_rx": re.compile(r'frontify\.com',                                re.I), "body_rx": re.compile(r"page not found", re.I)},
    {"provider": "GitBook",           "cname_rx": re.compile(r'gitbook\.io|gitbook\.com',                     re.I), "body_rx": re.compile(r"If you need specifics, contact the person who shared this link", re.I)},
    {"provider": "AfterShip",         "cname_rx": re.compile(r'aftership\.com',                               re.I), "body_rx": re.compile(r"Oops.*?looks like the page is lost", re.I)},

    # === Azure family (NXDOMAIN-based: CNAME resolves but target host returns NXDOMAIN/no-such-app) ===
    {"provider": "Azure/App Service",       "cname_rx": re.compile(r'\.azurewebsites\.net',                       re.I), "body_rx": re.compile(r"Error 404 - Web app not found|<title>404 Web Site not found", re.I)},
    {"provider": "Azure/Trafficmanager",    "cname_rx": re.compile(r'trafficmanager\.net',                        re.I), "body_rx": re.compile(r"<title>This page can.t be displayed|server has not yet been created", re.I)},
    {"provider": "Azure/CloudApp",          "cname_rx": re.compile(r'cloudapp\.(net|azure\.com)',                 re.I), "body_rx": re.compile(r"This page can.t be displayed|404", re.I)},
    {"provider": "Azure/Blob",              "cname_rx": re.compile(r'blob\.core\.windows\.net',                   re.I), "body_rx": re.compile(r"AuthenticationFailed|The specified blob does not exist|ResourceNotFound", re.I)},
    {"provider": "Azure/CDN",               "cname_rx": re.compile(r'azureedge\.net',                             re.I), "body_rx": re.compile(r"ErrorCode>404</ErrorCode|InternetEndpointNotFound", re.I)},
    {"provider": "Azure/DevOps",            "cname_rx": re.compile(r'visualstudio\.com',                          re.I), "body_rx": re.compile(r"Page not found", re.I)},
]

# Domain seeds for bounty-program companies (apex + key subdomains)
BOUNTY_DOMAINS = [
    # === Mid-tier SaaS (less competition, fast triage) ===
    "sentry.io", "posthog.com", "plaid.com", "figma.com", "notion.so",
    "linear.app", "cal.com", "documenso.com", "trigger.dev", "inngest.com",
    "anthropic.com", "openai.com", "langchain.com", "pinecone.io", "weaviate.io",
    "buildkite.com", "circleci.com", "datadoghq.com", "snyk.io", "supabase.com",
    "vercel.com", "netlify.com", "brex.com", "mercury.com", "ramp.com",
    "loom.com", "miro.com", "airtable.com", "retool.com", "vimeo.com",
    "calendly.com", "typeform.com", "hotjar.com", "mixpanel.com", "amplitude.com",
    "segment.com", "fullstory.com", "logrocket.com", "bugsnag.com", "rollbar.com",

    # === AI / ML labs (newer programs, less scanned) ===
    "huggingface.co", "replicate.com", "runpod.io", "modal.com", "cohere.com",
    "stability.ai", "perplexity.ai", "mistral.ai", "together.ai", "fireworks.ai",
    "deepgram.com", "elevenlabs.io", "scale.com", "labelbox.com", "weights.gg",

    # === High-tier classics (large attack surface) ===
    "stripe.com", "shopify.com", "cloudflare.com", "atlassian.com", "discord.com",
    "hashicorp.com", "elastic.co", "mongodb.com", "twilio.com", "github.com",
    "intercom.com", "zendesk.com", "okta.com", "auth0.com", "asana.com",
    "uber.com", "airbnb.com", "spotify.com", "netflix.com", "paypal.com",
    "yelp.com", "gitlab.com", "automattic.com", "wordpress.com", "mozilla.org",
    "yandex.com", "ibm.com", "salesforce.com", "snap.com", "twitch.tv",
    "reddit.com", "coinbase.com", "robinhood.com", "etsy.com", "square.com",

    # === Enterprise / SaaS bigger ===
    "atlassian.net", "slack.com", "dropbox.com", "box.com", "asana.com",
    "monday.com", "smartsheet.com", "freshworks.com", "newrelic.com",
    "pagerduty.com", "splunk.com", "anaplan.com", "tableau.com",
    "workday.com", "servicenow.com", "twilio.com", "veracode.com",

    # === .gov / public sector (small payouts but valid) ===
    "nasa.gov", "cisa.gov", "tts.gsa.gov", "navy.mil", "army.mil",
    "ftc.gov", "irs.gov", "uspto.gov", "doi.gov", "noaa.gov",

    # === Universities / open-source / IBB scope ===
    "stanford.edu", "mit.edu", "berkeley.edu", "harvard.edu", "cmu.edu",
    "kernel.org", "python.org", "nodejs.org", "rust-lang.org", "ruby-lang.org",
    "php.net", "openssl.org", "nginx.com", "apache.org",

    # === H1 top-100 expansion (public programs) ===
    "tesla.com", "ford.com", "toyota.com", "gm.com", "hp.com", "dell.com",
    "lenovo.com", "samsung.com", "asus.com", "lg.com", "panasonic.com",
    "starbucks.com", "mcdonalds.com", "nike.com", "adidas.com", "underarmour.com",
    "walmart.com", "target.com", "homedepot.com", "lowes.com", "costco.com",
    "verizon.com", "att.com", "tmobile.com", "comcast.com", "charter.com",
    "wellsfargo.com", "chase.com", "bankofamerica.com", "citi.com", "americanexpress.com",
    "delta.com", "united.com", "aa.com", "southwest.com", "jetblue.com",
    "marriott.com", "hilton.com", "hyatt.com", "ihg.com", "expedia.com",
    "booking.com", "airbnb.com", "vrbo.com", "kayak.com", "priceline.com",
    "nytimes.com", "wsj.com", "washingtonpost.com", "bloomberg.com", "reuters.com",
    "indeed.com", "glassdoor.com", "ziprecruiter.com", "monster.com",
    "yelp.com", "tripadvisor.com", "opentable.com", "doordash.com", "ubereats.com",
    "instacart.com", "grubhub.com", "postmates.com",
    "wechat.com", "tiktok.com", "snapchat.com", "pinterest.com", "quora.com",
    "medium.com", "substack.com", "wordpress.org",
    "dropbox.com", "box.com", "wetransfer.com",
    "adobe.com", "autodesk.com", "salesforce.com", "oracle.com", "sap.com",
    "slack.com", "zoom.us", "webex.com", "ringcentral.com",
    "gitlab.com", "bitbucket.org", "sourceforge.net",
    "stackoverflow.com", "kaggle.com", "leetcode.com",
    "twitch.tv", "youtube.com",

    # === Open-source / community ===
    "fedoraproject.org", "ubuntu.com", "debian.org", "archlinux.org", "freebsd.org",
    "openbsd.org", "netbsd.org", "gnu.org", "mariadb.org", "postgresql.org",
    "mysql.com", "sqlite.org", "redis.io", "memcached.org",
    "haproxy.org", "varnish-cache.org", "envoy.io",
    "kubernetes.io", "docker.com", "containerd.io",

    # === .gov / public sector expansion ===
    "dod.mil", "af.mil", "uscg.mil", "marines.mil",
    "ed.gov", "energy.gov", "hhs.gov", "dot.gov", "treasury.gov",
    "fbi.gov", "secretservice.gov", "dhs.gov", "ssa.gov",

    # === University programs ===
    "yale.edu", "princeton.edu", "columbia.edu", "upenn.edu", "duke.edu",
    "cornell.edu", "brown.edu", "dartmouth.edu", "nyu.edu", "usc.edu",
    "ucla.edu", "ucsd.edu", "ucsb.edu", "uci.edu",
    "umich.edu", "wisc.edu", "illinois.edu", "purdue.edu",
    "ox.ac.uk", "cam.ac.uk", "imperial.ac.uk", "ucl.ac.uk", "ed.ac.uk",
    "ethz.ch", "epfl.ch", "tum.de",

    # === IMMUNEFI / Crypto / DeFi — pays $10K-$1M ===
    "uniswap.org", "compound.finance", "aave.com", "makerdao.com", "curve.fi",
    "yearn.fi", "synthetix.io", "balancer.fi", "sushi.com", "1inch.io",
    "lido.fi", "rocket-pool.com", "polygon.technology", "arbitrum.io",
    "optimism.io", "starknet.io", "zksync.io", "scroll.io",
    "chainlink.com", "the-graph.com", "filecoin.io", "near.org",
    "solana.com", "avalabs.org", "binance.com", "okx.com", "bybit.com",
    "kraken.com", "gemini.com", "bitfinex.com", "huobi.com",
    "metamask.io", "phantom.app", "rainbow.me", "argent.xyz", "ledger.com",
    "trezor.io", "safe.global", "snapshot.org", "ens.domains",
    "opensea.io", "blur.io", "magiceden.io", "rarible.com",
    "messari.io", "dune.com", "etherscan.io", "blockscan.com",
    "alchemy.com", "infura.io", "moralis.io", "quicknode.com",
    "chainalysis.com", "trmlabs.com", "elliptic.co",
    "circle.com", "tether.to", "makerdao.com", "ondofinance.com",

    # === AI startups (newer programs, less covered) ===
    "character.ai", "anthropic.com", "groq.com", "mistral.ai", "x.ai",
    "wayve.ai", "cresta.com", "jasper.ai", "writer.com", "tome.app",
    "gamma.app", "perplexity.ai", "you.com", "tabnine.com", "codeium.com",
    "cursor.sh", "v0.dev", "bolt.new", "lovable.dev", "windsurf.com",
    "supermaven.com", "warp.dev", "fig.io", "kite.com",
    "midjourney.com", "stability.ai", "runwayml.com", "leonardo.ai",
    "ideogram.ai", "krea.ai", "kling.ai", "luma-ai.com",
    "characterai.com", "replika.com", "chai.ml", "venice.ai",
    "huggingface.co", "wandb.ai", "modal.com", "lambda.ai",
    "ollama.com", "lmstudio.ai", "vllm.ai", "tgi.huggingface.co",

    # === Fintech (modest bounties, plenty of programs) ===
    "wise.com", "revolut.com", "n26.com", "monzo.com", "starlingbank.com",
    "klarna.com", "afterpay.com", "affirm.com", "sezzle.com",
    "venmo.com", "cash.app", "zellepay.com",
    "plaid.com", "modernmd.com", "checkr.com", "alloy.com",
    "marqeta.com", "lithic.com", "treasuryprime.com", "unit.co",
    "fundbox.com", "kabbage.com", "bluevine.com", "ramp.com",
    "divvy.co", "expensify.com", "bill.com", "tipalti.com",
    "remitly.com", "western-union.com", "moneygram.com",

    # === Gaming + Esports (sometimes pay) ===
    "riotgames.com", "ea.com", "activision.com", "blizzard.com",
    "epicgames.com", "unrealengine.com", "unity.com", "supercell.com",
    "rovio.com", "king.com", "zynga.com",
    "valvesoftware.com", "steampowered.com", "steam.tv",
    "playstation.com", "xbox.com", "nintendo.com",

    # === Crypto exchanges / wallets (Immunefi territory) ===
    "binance.com", "coinbase.com", "kraken.com", "ftx.com",
    "bitstamp.net", "gate.io", "kucoin.com", "mexc.com",
    "blockfi.com", "celsius.network", "nexo.com", "ledn.io",

    # === Hosting / Cloud / DevTools (broad surface, often programs) ===
    "vercel.com", "netlify.com", "render.com", "fly.io", "railway.app",
    "vultr.com", "linode.com", "scaleway.com", "ovh.com", "hetzner.com",
    "ovhcloud.com", "akamai.com", "fastly.com", "imperva.com", "f5.com",
    "stripe.com", "square.com", "checkout.com", "adyen.com", "braintreepayments.com",

    # === AI/ML/Data tools ===
    "databricks.com", "snowflake.com", "fivetran.com", "airbyte.com",
    "dbt.com", "preset.io", "looker.com", "metabase.com",
    "n8n.io", "make.com", "zapier.com", "ifttt.com", "automate.io",

    # === Open source SaaS / community projects ===
    "appwrite.io", "pocketbase.io", "directus.io", "strapi.io",
    "ghost.org", "discourse.org", "matrix.org",
    "ory.sh", "auth0.com", "supabase.com", "keycloak.org",
]


@dataclass
class Takeover:
    domain: str
    subdomain: str
    cname: str
    provider: str
    company: str
    confirmed_at: str
    body_snippet: str = ""


def crtsh_subdomains(domain: str, limit: int = 200) -> list[str]:
    """crt.sh (often flaky)."""
    try:
        req = urllib.request.Request(f"https://crt.sh/?q=%25.{domain}&output=json", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    hosts = set()
    for row in data:
        for name in (row.get("name_value", "") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(f".{domain}") and "@" not in name and " " not in name:
                hosts.add(name)
        if len(hosts) >= limit: break
    return sorted(hosts)


def hackertarget_subdomains(domain: str, limit: int = 200) -> list[str]:
    """hackertarget free tier (no key needed, ~100/day rate limit)."""
    try:
        req = urllib.request.Request(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        return []
    hosts = set()
    for line in text.splitlines():
        if "," in line:
            host = line.split(",")[0].strip().lower()
            if host.endswith(f".{domain}") or host == domain:
                hosts.add(host)
        if len(hosts) >= limit: break
    return sorted(hosts)


def wayback_subdomains(domain: str, limit: int = 200) -> list[str]:
    """Wayback Machine CDX — historical/decayed subdomains. Highest takeover-find rate."""
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    hosts = set()
    for row in data[1:]:  # skip header
        if not row: continue
        try:
            from urllib.parse import urlparse
            host = urlparse(row[0]).hostname or ""
            host = host.lower().lstrip("*.")
            if host.endswith(f".{domain}") and "@" not in host:
                parts = host.split(".")
                if len(parts) <= 5:  # skip very deep
                    hosts.add(host)
        except Exception:
            continue
        if len(hosts) >= limit: break
    return sorted(hosts)


def certspotter_subdomains(domain: str, limit: int = 200) -> list[str]:
    """Certspotter CT log API (free, no auth needed)."""
    try:
        req = urllib.request.Request(
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    hosts = set()
    for entry in data:
        for name in entry.get("dns_names", []):
            n = name.strip().lower().lstrip("*.")
            if n.endswith(f".{domain}") and "@" not in n:
                hosts.add(n)
        if len(hosts) >= limit: break
    return sorted(hosts)


def get_subdomains(domain: str, limit: int = 200) -> list[str]:
    """Try all 4 sources, dedupe, return."""
    all_hosts = set()
    for fn, label in [(crtsh_subdomains, "crt.sh"),
                       (hackertarget_subdomains, "hackertarget"),
                       (certspotter_subdomains, "certspotter"),
                       (wayback_subdomains, "wayback")]:
        try:
            hits = fn(domain, limit)
            if hits:
                all_hosts.update(hits)
                print(f"    {label}: {len(hits)}", flush=True)
            else:
                print(f"    {label}: 0", flush=True)
        except Exception as e:
            print(f"    {label}: err {e}", flush=True)
        time.sleep(0.5)
    return sorted(all_hosts)[:limit]


def resolve_cname(host: str) -> str:
    """Get the CNAME target for a hostname (1 query)."""
    try:
        import dns.resolver
        try:
            resp = dns.resolver.resolve(host, "CNAME", lifetime=5)
            return str(resp[0].target).rstrip(".")
        except Exception:
            return ""
    except ImportError:
        # Fallback: use `dig` if available
        try:
            out = subprocess.check_output(["dig", "+short", "CNAME", host], stderr=subprocess.DEVNULL, timeout=5)
            line = out.decode().strip().splitlines()[0] if out.strip() else ""
            return line.rstrip(".")
        except Exception:
            return ""


def fetch_body(host: str) -> str:
    """Fetch http(s)://host and return body snippet (1 request)."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": UA})
            ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                return r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try: return e.read(20000).decode("utf-8", "replace")
            except: pass
        except Exception:
            continue
    return ""


def load_ledger() -> set:
    if not LEDGER.exists(): return set()
    seen = set()
    for line in LEDGER.read_text().splitlines():
        if line.strip():
            try: seen.add(json.loads(line)["subdomain"])
            except: pass
    return seen


def append_ledger(t: Takeover):
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    with LEDGER.open("a") as f:
        f.write(json.dumps(asdict(t)) + "\n")


def check_one(host: str, company: str) -> Takeover | None:
    cname = resolve_cname(host)
    if not cname: return None
    for fp in TAKEOVER_FINGERPRINTS:
        if fp["cname_rx"].search(cname):
            # Found vulnerable-provider CNAME — fetch body to confirm
            body = fetch_body(host)
            if fp["body_rx"].search(body):
                return Takeover(
                    domain=host.split(".", 1)[1] if "." in host else host,
                    subdomain=host, cname=cname, provider=fp["provider"],
                    company=company,
                    confirmed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    body_snippet=body[:200].replace("\n", " "),
                )
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-domains", type=int, default=10, help="how many bounty domains to scan this run")
    ap.add_argument("--max-subs-per-domain", type=int, default=100)
    ap.add_argument("--corpus", default=None,
                    help="Path to a newline-separated apex-domain corpus file. "
                         "If given, overrides BOUNTY_DOMAINS. Use ~/.lictor/bounty-corpus-paid.txt "
                         "for the 2,143 paid-program corpus extracted from H1+BC+Intigriti+YWH.")
    args = ap.parse_args()
    # Override target list if a corpus file is given
    if args.corpus:
        corpus_path = Path(args.corpus).expanduser()
        if corpus_path.exists():
            global BOUNTY_DOMAINS
            BOUNTY_DOMAINS = [l.strip() for l in corpus_path.read_text().splitlines() if l.strip()]
            print(f"[+] Loaded {len(BOUNTY_DOMAINS)} domains from {corpus_path}", flush=True)

    seen = load_ledger()
    print(f"[+] ledger: {len(seen)} prior subdomains scanned")

    targets = BOUNTY_DOMAINS[:args.max_domains]
    confirmed = []
    for ci, domain in enumerate(targets, 1):
        company = domain.replace(".com", "").replace(".io", "").replace(".so", "").replace(".app", "").replace(".dev", "").replace(".co", "")
        print(f"\n[{ci}/{len(targets)}] {domain} — pulling subdomains (3 sources)...", flush=True)
        subs = get_subdomains(domain, args.max_subs_per_domain)
        new_subs = [s for s in subs if s not in seen]
        print(f"  {len(subs)} total, {len(new_subs)} new (after ledger dedup)")
        if not new_subs: continue

        for si, sub in enumerate(new_subs[:args.max_subs_per_domain], 1):
            try:
                t = check_one(sub, company)
                seen.add(sub)
                if t:
                    print(f"  🔴🔴 TAKEOVER  {sub}  →  {t.cname}  ({t.provider})")
                    append_ledger(t)
                    confirmed.append(t)
                else:
                    pass  # too noisy to print each
            except Exception as e:
                pass
            time.sleep(0.15)  # be polite to DNS

        time.sleep(1.5)

    # Summary
    print(f"\n[+] scan complete: {len(confirmed)} NEW takeovers confirmed")
    if confirmed:
        out_path = OUT_DIR / f"takeovers-{datetime.now().strftime('%Y-%m-%d')}-private.md"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            f.write(f"# Subdomain takeovers — {datetime.now().strftime('%Y-%m-%d')}\n\n")
            f.write(f"**Confirmed:** {len(confirmed)}\n\n")
            f.write("| Subdomain | CNAME | Provider | Company |\n|---|---|---|---|\n")
            for t in confirmed:
                f.write(f"| `{t.subdomain}` | `{t.cname}` | **{t.provider}** | {t.company} |\n")
        print(f"    → {out_path}")


if __name__ == "__main__":
    main()
