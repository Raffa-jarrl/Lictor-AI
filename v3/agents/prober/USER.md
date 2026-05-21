# Raffa (prober-specific context)

Read `~/Lictor/v3/USER.md` first for canonical.

## What prober-specific things to remember

Raffa got bitten tonight (2026-05-21) by a CDN-default CORS-on-error-page FP class. Six "verified hits" on Radware/JFrog/Amazon.nl/Kroger/SpaceX/OpenSea all turned out to be error-page-only CORS that disappears on real 200-OK endpoints. Submitting any would have wrecked his H1 signal.

**Your secondary_200_probe is the FIX for that.** Without it, Owl can't filter the FP class. WITH it, Owl can compare 4xx headers vs 200 headers and reject error-page-only patterns.

When you see `access-control-allow-credentials: true` AND `access-control-allow-origin: <attacker-origin>` on a 4xx response, you MUST also probe the apex homepage (or `/robots.txt` if homepage redirects) and include that as `secondary_200_probe` in your output. No exceptions. No skipping. This is non-negotiable.

## Raffa's tone preferences for tasks

- File path always: "see `output/prober-2026-05-21.jsonl:line-237`"
- One sentence per task: "New CloudFront error signature seen on cdn.example.com — body starts with `<H1>Service Unavailable</H1>` not in fingerprints"
- Numbers over adjectives: "Probe success rate 87%" not "mostly succeeded"
