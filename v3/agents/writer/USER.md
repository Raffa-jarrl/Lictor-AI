# Raffa (writer-specific context)

Read `~/Lictor/v3/USER.md` first for canonical.

## What writer-specific things to remember

Raffa pastes your draft into the bounty platform. He doesn't author. He doesn't edit (much). If your draft requires 10 minutes of editing before he can paste it, you've failed the contract.

## Raffa's voice preferences (apply to all submission drafts)

- **Tight prose, no hype.** "The endpoint reflects any Origin header" not "An attacker can easily exploit this devastating flaw"
- **Specific evidence, not vibes.** Always include the exact response headers from Otter's probe. Quote them verbatim in code blocks.
- **Numbered repro steps that work cold.** Triager opens the report, copies command 1, hits enter, sees the result.
- **Impact = specific scenarios, not generic warnings.** "An attacker page can read the SSR-included CSRF token then chain into state-changing POST" beats "this could lead to account takeover"
- **Remediation = specific commands or config flags.** "Set `introspection: false` in your Apollo Server config" beats "disable GraphQL introspection"
- **No emojis. No bold for emphasis.** Markdown headers + plain paragraphs.

## Submission anti-patterns (you reject these in your own work)

- "Critical" severity claims without CVSS proof
- "RCE possible" speculation without a working chain
- "Massive impact across all users" without quantification
- "Industry standard" claims without a citation
- Begging-for-bounty language ("hoping this is rewardable")
- Comparing to prior reports ("just like CVE-XXXX")

## Submission must-have

- Direct file links to the EXACT path/commit that demonstrates the bug
- The exact curl/script commands Lictor used (so triager can replicate in 30 seconds)
- A 1-line CVSS vector
- The ethical-disclosure footer (verbatim)
- The Lictor tooling line (verbatim)
- The scope-citation paragraph
