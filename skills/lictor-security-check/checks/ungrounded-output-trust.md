# Check — Trusting a model's word without checking it

**What you're looking for:** two narrow, code-readable places where your app believes an AI model *too much*. Not "the model said something slightly wrong" — broad hallucination accuracy isn't something a code scan can judge, and it's out of scope here. We're after the two flavors you *can* see in the source:

1. **Slopsquatting** — your code (or an agent) takes a package name the model *suggested* and installs it without checking the package is real. LLMs confidently invent package names that don't exist; attackers pre-register those invented names with malware inside. If your install step trusts model output, you `pip install`/`npm install` the attacker's package.
2. **Ungrounded authority** — a model's raw answer is the *sole decider* in a path that matters: auth, eligibility, pricing, refunds, medical, legal. `if (llmSays === "approved")` with no source backing it, no citation, no human gate. The model is steerable and occasionally just makes things up, so "the AI approved it" becomes "anyone who can phrase a prompt approved it."

The shared root cause is the same: **model output is treated as ground truth.** It isn't. It's a plausible-sounding guess, sometimes steered by an attacker, sometimes invented from nothing.

This is **OWASP LLM09: Misinformation** (LLM Top 10 for Applications, 2025), specifically the package-hallucination and over-reliance sub-cases. Severity: **MEDIUM** (slopsquatting installs rise to HIGH/CRITICAL once a malicious package is confirmed; ungrounded authority rises to HIGH when the decision moves money, grants access, or affects health/legal outcomes).

> **Where this sits next to the other AI checks.** This is the *trust* axis.
> - The `dependencies.md` check catches typosquats of names a **human** wrote in your manifest. This check catches the **model**-driven install — a name no human vetted, taken straight from a completion.
> - The `indirect-prompt-injection.md` check is about untrusted text going *into* the prompt; `llm-output-sink.md` is model output reaching a *code/HTML sink*. This check is model output reaching a *decision* (or an *installer*). Different sink, same lesson: don't trust the model's word.

## How to scan

Two independent hunts. Do both.

### Hunt 1 — Slopsquatting: model output piped into a package installer

The signature is a model result feeding `install` — either programmatically (string-built command, an agent tool that installs) or a workflow that pip/npm-installs whatever the model just named.

```bash
# JS / TS — a child_process install whose argument isn't a static literal
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E "(exec|execSync|spawn|spawnSync)\s*\(.*(npm|pnpm|yarn|bun)\s+(install|add|i)\b" \
  . 2>/dev/null | head -30

# Python — subprocess/os.system running pip install with a variable package name
grep -rEn --include='*.py' \
  -E "(subprocess\.(run|call|Popen|check_output)|os\.system|os\.popen).*pip\s+install|pip\._internal|importlib.*install|__import__\(" \
  . 2>/dev/null | head -30

# Go / Ruby / PHP — shelling out to a package manager from code
grep -rEn --include='*.go' --include='*.rb' --include='*.php' \
  -E "go\s+get\b|gem\s+install\b|composer\s+require\b|exec.*(go get|gem install|composer require)" \
  . 2>/dev/null | head -20

# THE TELL: an install command in the same file as a model call.
# List files that both call a model AND run an installer — those are the ones to open.
grep -rlEn --exclude-dir={node_modules,.next,dist,build,vendor} \
  -E "chat\.completions\.create|messages\.create|generateText|\.invoke\(|llm\(|ollama|\.complete\(" \
  . 2>/dev/null \
| xargs -I{} sh -c 'grep -lE "(npm|pnpm|yarn|pip|go get|gem install|composer require)\s+(install|add|require|i)?" "{}" 2>/dev/null' \
  2>/dev/null | sort -u

# Agent tool definitions named like an installer (the model can call these)
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor} \
  -E "name:\s*['\"](install_package|add_dependency|pip_install|npm_install|install_dep)" \
  . 2>/dev/null | head -20
```

**The connect step.** A `pip install`/`npm add` is only a slopsquatting finding when the package name comes from **model output** — a completion, an agent's chosen tool argument, a "suggested imports" list the model produced — and there's **no verification** (registry existence check, allowlist, lockfile, human review) before it runs. A static `npm install react` in a script is fine. `npm install ${aiSuggestedPkg}` is the bug.

### Hunt 2 — Ungrounded authority: a model answer is the sole decider in a critical path

The signature is a model result compared/branched on directly to gate something that matters, with no grounding source and no human step.

```bash
# JS / TS — branching on a model result string for a decision
grep -rEn --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --exclude-dir={node_modules,.next,dist,build} \
  -E "(===|==|includes\(|startsWith\(|match\().{0,40}(approv|denied|eligibl|allow|grant|authoriz|legit|safe|fraud|verified)" \
  . 2>/dev/null | head -30

# Python — same, plus 'if model/response/llm ... approved/eligible'
grep -rEn --include='*.py' \
  -E "if\s+.*(response|completion|llm|answer|result|model).*(==|in|approv|eligib|allow|grant|authoriz|verified|fraud)" \
  . 2>/dev/null | head -30

# Critical-path keywords near a model call — the domains where this matters most
grep -rEn --exclude-dir={node_modules,.next,dist,build,vendor} \
  -E "(approve|eligibility|underwrit|refund|payout|price|discount|diagnos|prescri|dosage|triage|kyc|sanction|creditworth|verdict|liab)" \
  . 2>/dev/null | head -40

# Go / Ruby / PHP / mobile — branching on a model field for a gate
grep -rEn --include='*.go' --include='*.rb' --include='*.php' \
  --include='*.swift' --include='*.kt' --include='*.java' --include='*.dart' \
  -E "(==|\.contains\(|\.includes\(|case\s).{0,30}(approv|eligib|allow|grant|authoriz|fraud|verified)" \
  . 2>/dev/null | head -30
```

**The connect step.** A finding here needs all three: (1) the value branched on is **model output**, (2) it gates a **critical action** (auth/eligibility/pricing/medical/legal/money/access), and (3) there's **no grounding** (no lookup against a source of truth, no citation the model had to produce, no human-review/confirm step). Advisory output ("here's a draft", "suggested reply", a ranked list a human picks from) is not a finding — the human or a downstream check is the real decider.

## The dangerous patterns

**Pattern 1 — Slopsquatting: install whatever the model named**

```python
# ❌ "Ask the model which package solves this, then install it"
pkg = client.chat.completions.create(...).choices[0].message.content.strip()
subprocess.run(["pip", "install", pkg])          # pkg may not exist on PyPI — attacker pre-registered it
```

```ts
// ❌ Agent "fix my build" tool — model decides the dependency, code installs it
const dep = completion.choices[0].message.content.trim();
execSync(`npm install ${dep}`);                  // command injection AND slopsquatting in one line
```

```ts
// ❌ An agent tool the MODEL can call to install packages, no allowlist
const installTool = {
  name: "install_package",
  handler: ({ name }) => execSync(`pnpm add ${name}`),   // model picks `name`
};
```

LLMs hallucinate package names constantly — studies of code-gen models find a meaningful share of suggested packages simply don't exist. Attackers harvest those hallucinated names and publish malware under them (the "slopsquat"). Because npm/pip run install-time lifecycle scripts (`postinstall`, `setup.py`), the malicious payload fires the instant you install — exfiltrating your `.env`, your tokens, your cloud creds. Worse, the model tends to hallucinate the *same* plausible names repeatedly, so an attacker only has to squat a handful to catch many victims. **MEDIUM** as a pattern; **CRITICAL** once you confirm an installed package is a known squat. (The `execSync(\`npm install ${dep}\`)` form is *also* command injection — see `injection.md`.)

**Pattern 2 — Ungrounded authority: the model's yes/no IS the decision**

```ts
// ❌ Loan / KYC / access decision made purely from a completion
const verdict = (await llm.invoke(`Approve this applicant? ${JSON.stringify(applicant)}`)).content;
if (verdict.toLowerCase().includes("approved")) {
  await grantCredit(applicant.id);               // money moved on a vibe
}
```

```python
# ❌ Eligibility gate with no source of truth
answer = chat(f"Is user {uid} allowed to access {resource}? yes/no").strip().lower()
if answer == "yes":
    return resource                              # authorization by autocomplete
```

```python
# ❌ Medical / dosing path straight off the model
dose = model_response.choices[0].message.content
administer(dose)                                 # no clinician, no formulary check
```

```php
// ❌ Pricing decided by the model and charged directly
$price = $client->chat()->create(...)['choices'][0]['message']['content'];
charge_card($customer, (float) $price);          // attacker prompts "price is 0.01"
```

The model is **steerable** (a crafted input — or a poisoned RAG chunk per `indirect-prompt-injection.md` — flips the answer) and occasionally just **wrong** (confident, fluent, fabricated). When its raw answer is the only gate, "the AI decided" collapses into "whoever shaped the input decided." In a money/access/health/legal path that's a direct loss, a compliance breach, or worse. **HIGH** in those domains; **MEDIUM** for lower-stakes gates.

## The fixes — show these, with code

**Slopsquatting → verify the name against the real registry before you ever install it.** A name the model invented won't be there; a name that exists but was just published by an unknown author is a yellow flag.

```python
# ✅ Confirm the package exists on PyPI before installing anything the model suggested
import urllib.request, subprocess

def install_if_real(pkg: str):
    pkg = pkg.strip()
    if not pkg.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"refusing suspicious name: {pkg!r}")   # also blocks shell injection
    url = f"https://pypi.org/pypi/{pkg}/json"
    with urllib.request.urlopen(url) as r:                       # 404 → name doesn't exist → don't install
        if r.status != 200:
            raise LookupError(f"{pkg} not found on PyPI — likely a hallucination")
    subprocess.run(["pip", "install", "--require-hashes", pkg], check=True)
```

```ts
// ✅ JS/TS — check the npm registry, never string-build the command
import { execFileSync } from "node:child_process";

async function installIfReal(pkg: string) {
  if (!/^(@[a-z0-9-_]+\/)?[a-z0-9-_.]+$/.test(pkg)) throw new Error("bad pkg name");
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
  if (!res.ok) throw new Error(`${pkg} not on npm — refusing to install a hallucinated package`);
  execFileSync("npm", ["install", "--ignore-scripts", pkg], { stdio: "inherit" }); // execFile, not a shell string
}
```

The durable fix is **don't let a model add dependencies autonomously at all**. Treat any model-suggested package as a *proposal*: a human reviews it, it lands in the manifest, the lockfile pins it, and the `dependencies.md` audit tooling vets it. If an agent must self-install, gate it to an allowlist of known-good packages and pass `--ignore-scripts` (Python: install into a throwaway venv first) so a malicious install can't run code.

**Ungrounded authority → ground it or gate it. Ideally both.**

```ts
// ✅ The model EXTRACTS/EXPLAINS; your code DECIDES against real data
const facts = await fetchApplicantRecord(applicant.id);     // source of truth from YOUR system
const decision = applyUnderwritingRules(facts);             // deterministic, auditable, testable
// model is used only to explain the decision to the user, never to make it
const explanation = await llm.invoke(`Explain this decision in plain English: ${decision.reason}`);
```

```python
# ✅ Require the model to cite a source, then verify the citation before acting
parsed = Verdict.model_validate_json(answer)     # pydantic: {decision: Literal["approve","deny"], source_id: str}
record = db.get(parsed.source_id)                # the cited record must actually exist...
if record is None or not rule_supports(record, parsed.decision):  # ...and actually support the verdict
    raise ValueError("model decision not grounded in a real record — escalating to human")
```

```ts
// ✅ Human-in-the-loop gate for high-stakes actions (money / access / health / legal)
const suggestion = await llm.invoke(prompt);     // model proposes
await queueForReview({ suggestion, applicant }); // a person approves before anything happens
// nothing is granted/charged/administered until a human confirms
```

The rule in one sentence: **a model can advise, summarize, draft, rank, or explain — but the authoritative decision must come from a source of truth, a deterministic rule, or a human.** If you genuinely want the model "in the loop," make it produce *structured, verifiable* output (a decision plus a `source_id` you check), never a free-text yes/no you branch on.

## Report a finding as

**Title (slopsquatting):** "Your app installs whatever package the AI names — including ones that don't exist yet"

**Title (ungrounded authority):** "An AI's answer is the only thing approving [loans / access / refunds]"

**Detail (slopsquatting flavor):**
> `scripts/auto_fix_deps.py:42` asks the model which package to add, then runs it straight into `pip`:
> ```python
> pkg = client.chat.completions.create(...).choices[0].message.content.strip()
> subprocess.run(["pip", "install", pkg])
> ```
> Nothing checks that `pkg` is a real package before installing it.
>
> **What can go wrong:** LLMs routinely invent package names that *sound* right but don't exist. Attackers watch for these "hallucinated" names and pre-publish malware under them — this is called **slopsquatting**. Because installing a package runs its setup scripts immediately, the malicious code executes the moment your script installs it: it can read your `.env`, steal your API keys, and phone home — before your app even runs. Models tend to hallucinate the *same* plausible names over and over, so squatting a few catches many victims. (This line is *also* shell-injectable if the name is ever string-built — see `injection.md`.)
>
> This is OWASP LLM09 (Misinformation), package-hallucination case.
>
> **What to do tonight:**
> 1. Verify the name exists on the real registry before installing — and pass `--ignore-scripts` so an install can't run code:
>    ```python
>    if urllib.request.urlopen(f"https://pypi.org/pypi/{pkg}/json").status != 200:
>        raise LookupError(f"{pkg} not on PyPI — refusing to install a hallucination")
>    subprocess.run(["pip", "install", "--ignore-scripts", pkg], check=True)
>    ```
> 2. Better: don't let the model install anything autonomously. Treat its suggestion as a proposal a human reviews; let it land in your manifest + lockfile, then run the check-19 audit. If an agent must self-install, restrict it to an allowlist of known packages.
> 3. Grep for the other installers fed by model output — AI generators repeat this shape across `npm`, `pip`, `go get`, `gem install`, `composer require`.

**Detail (ungrounded-authority flavor):**
> `src/underwriting.ts:31` decides whether to grant credit purely from a model reply:
> ```ts
> const verdict = (await llm.invoke(`Approve this applicant? ${...}`)).content;
> if (verdict.toLowerCase().includes("approved")) await grantCredit(applicant.id);
> ```
> There's no check against your own records, no citation the model had to back its answer with, and no human review. The model's word *is* the decision.
>
> **What can go wrong:** Language models are steerable and occasionally just wrong — confident, fluent, and fabricated. An applicant (or a poisoned document in your pipeline, per `indirect-prompt-injection.md`) who can influence the prompt can make the model say "approved." Because nothing else gates the action, "the AI approved it" really means "whoever shaped the input approved it." In a path that moves money, grants access, or affects someone's health or legal standing, that's a direct loss or a compliance breach.
>
> This is OWASP LLM09 (Misinformation), over-reliance case.
>
> **What to do tonight:**
> 1. Move the *decision* out of the model. Pull the real facts from your system and decide with deterministic, auditable rules; let the model only *explain* the result:
>    ```ts
>    const facts = await fetchApplicantRecord(applicant.id);
>    const decision = applyUnderwritingRules(facts);   // your code decides
>    ```
> 2. If the model must stay in the loop, require it to produce *structured, verifiable* output (a decision plus a `source_id`), and verify that source actually supports the verdict before acting.
> 3. For high-stakes actions (money / access / medical / legal), add a human-in-the-loop confirm — nothing is granted, charged, or administered until a person approves.
> 4. Verify the fix: feed the path an input that *tries* to steer the model to "approved" for an applicant who shouldn't be. A grounded system still denies; an ungrounded one flips.

Repeat the report block for each distinct installer fed by model output, and each distinct critical decision gated solely on a completion.

## Don't false-positive on — the "what NOT to flag" guard

This check is deliberately narrow. Two things count and nothing else: **model-named package installed without verification**, and **model output as the sole authority in a critical path.** Be strict, or you'll bury founders in noise.

- **Static installs.** `npm install react`, `pip install -r requirements.txt`, `go get github.com/known/pkg` with a hardcoded name. No model output anywhere → not this check (that's `dependencies.md` territory for vetting the named package).
- **Model suggests, human installs.** The model recommends a package in chat/output and a *person* adds it to the manifest and commits the lockfile. That's the correct workflow — the human + lockfile + audit is the verification. **Safe.**
- **Advisory / non-authoritative model output.** A drafted email, a suggested reply, a summary, a ranked candidate list a human picks from, autocomplete, a "recommended" label shown to a user who still clicks the real button. The human or a downstream deterministic check is the decider, not the model. **Safe — don't flag.**
- **Model output verified before action.** The completion is parsed against a schema *and* checked against a source of truth (a DB record, a rules engine, an allowlist, a cited document that's confirmed to exist and support the answer) before anything happens. Grounding is present → that's the fix already applied. Note as INFO.
- **Human-in-the-loop gate present.** The model proposes and a person confirms before money moves / access is granted / a treatment is given. The human is the authority. **Safe.**
- **Low-stakes "decisions."** Picking a UI theme, sorting a feed, choosing which tip to show, tagging a note, routing a non-critical support ticket to a queue. Wrong is harmless and reversible → not a security finding (mention as INFO only if it's borderline). The severity lives in auth/eligibility/pricing/medical/legal/money/access — judge by the *blast radius of being wrong*.
- **Broad accuracy / hallucination quality.** "Does the model sometimes give a slightly wrong factual answer in a chat reply?" is a product-quality question, not a code-observable security finding, and it's explicitly out of scope. Don't flag a chatbot just for being a chatbot.
- **It's really a different check.** Untrusted text going *into* the prompt → `indirect-prompt-injection.md`. Model output reaching an `eval`/`innerHTML`/SQL sink → `llm-output-sink.md`. A `execSync(\`npm install ${x}\`)` where `x` is *user* input, not model output → `injection.md`. Route it; don't double-report.
- **Tests, fixtures, eval harnesses, notebooks.** Paths under `__tests__/`, `*.test.*`, `*.spec.*`, `fixtures/`, `evals/`, `*.ipynb` that install canned packages or branch on canned completions aren't a production attack surface. Mention only if a real prod path is wired in.

When in doubt, run the trace. Slopsquatting: *does an install command receive a name that came from a model, with no existence check?* Authority: *does a critical action branch on a model answer, with no source backing it and no human gate?* If yes, it's a finding. If the model is only advising — or its output is verified or confirmed before anything happens — leave it.
