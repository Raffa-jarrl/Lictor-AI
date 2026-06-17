# Check — Untrusted model artifacts & unsafe model loading

**What you're looking for:** the moment your app *loads someone else's machine-learning model* — a `.pt`/`.ckpt`/`.bin` checkpoint, a HuggingFace repo, a fine-tune, a LoRA adapter, an embedding model — and trusts it the way it would trust your own code. A model file is not a passive lump of numbers. The two most common ways to load one (`torch.load` / `pickle.load`, and HuggingFace's `trust_remote_code=True`) will *run code* while they load. So "download this model and use it" can quietly mean "download a stranger's Python and run it as your server." On top of that, most apps pull the model from a hub by a *moving* name (`@main`, `:latest`, no version) with no integrity check — so the model you tested is not guaranteed to be the model that ships. The AI that built your app wrote `model = torch.load("model.bin")` because that's the line in every tutorial; it never asked where the file came from.

This is the supply-chain check for the *weights*, not the packages. Think of it as the same worry as "is this npm package safe?" — except the artifact is a model your code downloads and executes, and your normal dependency scanners never look at it.

### How this is different from the two checks it sits next to

Founders (and graders) mix these up, so be precise:

- **`dependencies.md`** = *installed packages* (npm/pip/Go/etc.). Code you `import`.
- **`unsafe-deserialization.md`** = *request input → live objects*. Bytes from a **stranger hitting your endpoint** (a cookie, a body, an upload) fed to `pickle.loads`/`unserialize`. The attacker is a **web visitor**.
- **THIS check** = *a model/weights artifact → loaded as code*. The dangerous bytes are a **model file or model repo** pulled from a hub or a path, not a live request. The attacker is **whoever published or can tamper with that model**. Same RCE primitive (`pickle`), totally different entry point. If the `pickle.load` you found is reading a `.pkl` from `request.files`, that's `unsafe-deserialization.md` — leave it there. If it's reading `pytorch_model.bin` from a download or a model directory, it's **this** check.

Maps to **OWASP Top 10 for LLM Applications 2025 — LLM03: Supply Chain.** Severity ceiling: 🔴 (arbitrary code execution at load time).

## How to scan

You're reading the repo, not running anything. Grep for the four patterns below, then for each hit look *one step back* at where the artifact comes from. A model loaded from a path **you** control and committed to your repo is fine; the finding is when it comes from a hub, a URL, a user-supplied path, or a moving tag.

### Python — the big one (`torch.load`, `pickle`, `joblib`, and friends)

```bash
# Object-format model loaders (these can execute code while loading)
grep -rEn --include='*.py' \
  -E '\b(torch|th)\.load\s*\(|\bpickle\.(load|loads)\s*\(|\bjoblib\.load\s*\(|\bdill\.(load|loads)\s*\(|\bnumpy\.load\s*\([^)]*allow_pickle\s*=\s*True' \
  . 2>/dev/null
```

For each `torch.load(...)` hit, the question is one flag: **is `weights_only=True` set?** If not, `torch.load` will unpickle arbitrary Python and can run code. (PyTorch ≥ 2.6 flipped the default to `weights_only=True`; older code, and any explicit `weights_only=False`, is still exposed.)

### Python — HuggingFace `trust_remote_code` (executes the repo's own .py)

```bash
# The single most dangerous HF flag — runs custom code shipped IN the model repo
grep -rEn --include='*.py' --include='*.ipynb' \
  -E 'trust_remote_code\s*=\s*True' \
  . 2>/dev/null

# from_pretrained / pipeline / hf_hub_download / snapshot_download calls (check each for a pinned revision)
grep -rEn --include='*.py' --include='*.ipynb' \
  -E '\.from_pretrained\s*\(|(^|[^a-zA-Z_])pipeline\s*\(|hf_hub_download\s*\(|snapshot_download\s*\(|AutoModel|AutoTokenizer|AutoPeftModel|PeftModel\.from_pretrained' \
  . 2>/dev/null
```

`trust_remote_code=True` tells `transformers` to import and run a `.py` file that lives **inside the model repo on the Hub**. On a third-party repo that is, flatly, "run this stranger's code." On a first-party repo you own and control, it's a normal (if sharp) tool.

### Pinning — is the model pinned to an immutable commit, or to a moving name?

```bash
# Find from_pretrained / download calls and check whether a revision/commit is pinned
grep -rEn --include='*.py' --include='*.ipynb' \
  -E "from_pretrained\s*\([^)]*\)|hf_hub_download\s*\([^)]*\)|snapshot_download\s*\([^)]*\)" \
  . 2>/dev/null

# Does the call set revision= / commit= at all?  (absence = pinned to a moving branch, usually @main)
grep -rEn --include='*.py' --include='*.ipynb' \
  -E 'revision\s*=|commit_hash|@[0-9a-f]{7,40}' \
  . 2>/dev/null
```

The smell: `AutoModel.from_pretrained("some-org/some-model")` with **no `revision=`**. That silently means `revision="main"` — whatever the repo owner pushes there next. A pinned call looks like `from_pretrained("some-org/some-model", revision="d3b0...full40hexsha...")` (a commit SHA, not a tag like `v1` or `main`).

### Build-/run-time weight downloads with no integrity hash

```bash
# Dockerfiles, entrypoints, setup scripts pulling weights from a hub/URL
grep -rEn --include='Dockerfile*' --include='*.sh' --include='*.py' --include='*.yaml' --include='*.yml' \
  -E 'huggingface\.co/|hf_hub_download|snapshot_download|wget .*\.(bin|pt|ckpt|safetensors|gguf|onnx|pth)|curl .*\.(bin|pt|ckpt|safetensors|gguf|onnx|pth)|ollama pull|civitai\.com/' \
  . 2>/dev/null
```

A `RUN wget https://.../model.bin` in a Dockerfile with no checksum step means the image you build today and the image you build next month can contain different weights, and nobody would know. Same risk as an unpinned dependency — but for the artifact your model *is*.

### Other stacks (where this shows up, and where it mostly doesn't)

Model loading is overwhelmingly a Python concern, but it leaks into the rest of the stack when an app *serves* an ML feature:

```bash
# JS/TS — transformers.js, ONNX Runtime Web, TF.js loading remote models
grep -rEn --include='*.ts' --include='*.js' --exclude-dir={node_modules,.next,dist} \
  -E "@xenova/transformers|@huggingface/transformers|pipeline\s*\(|env\.allowRemoteModels|ort\.InferenceSession\.create|tf\.loadLayersModel|tf\.loadGraphModel" \
  . 2>/dev/null

# Go — ONNX / GGUF / llama.cpp bindings loading a model path
grep -rEn --include='*.go' \
  -E 'ort\.NewSession|onnxruntime|llama\.LoadModel|gguf|\.LoadModel\s*\(' \
  . 2>/dev/null

# Ruby — Torch.rb / ONNXRuntime gem
grep -rEn --include='*.rb' \
  -E 'Torch\.load|OnnxRuntime::|InferenceSession\.new' \
  . 2>/dev/null

# PHP — rarely loads models directly; usually shells out to a Python worker. Check that worker.
grep -rEn --include='*.php' \
  -E 'exec\s*\(|shell_exec\s*\(|proc_open' . 2>/dev/null | grep -iE 'model|torch|infer|python'
```

**Mobile** is the same story with on-device models — the artifact is bundled or downloaded to the device, and the risk is "did it come from where we think, unmodified":

```bash
# iOS (Swift) — Core ML / on-device LLM model files loaded at runtime
grep -rEn --include='*.swift' \
  -E 'MLModel\(|\.mlmodelc|\.mlpackage|try MLModel|GGUF|llama_load_model|\.gguf' \
  . 2>/dev/null

# Android (Kotlin/Java) — TFLite / ONNX / MediaPipe model files
grep -rEn --include='*.kt' --include='*.java' \
  -E 'Interpreter\(|\.tflite|OrtSession|loadModelFile|MappedByteBuffer|ModelManager' \
  . 2>/dev/null

# Flutter / React Native — TFLite / ONNX / llama plugins, and any runtime model URL
grep -rEn --include='*.dart' --include='*.ts' --include='*.js' --exclude-dir=node_modules \
  -E 'tflite|Tflite|onnxruntime|loadModel|\.gguf|downloadModel|modelUrl' \
  . 2>/dev/null
```

For mobile: a model **shipped inside the app bundle** is part of your signed binary — fine. The finding is a model **downloaded at runtime over the network** (especially over `http://`, or with no signature/hash check) — that download can be swapped on the wire or at the source.

## The patterns, and what each one means

### Pattern 1 — `torch.load` / `pickle.load` on a downloaded checkpoint (RCE at load time)

```python
# Pulls a checkpoint from a hub, then unpickles it — code runs while "loading"
path = hf_hub_download("randoml-org/cool-finetune", "pytorch_model.bin")
state = torch.load(path)          # ← no weights_only=True → arbitrary code can execute
model.load_state_dict(state)
```

A PyTorch checkpoint is a **pickle**. Unpickling can construct any object and call `__reduce__`, which is a documented code-execution path. A malicious model on a hub doesn't need a bug in your app — the act of loading it *is* the exploit. This is exactly how researchers have demonstrated "weaponized" models on public hubs that pop a reverse shell the instant you load them.

**Severity:** 🔴 CRITICAL when the artifact comes from a third party / hub / URL and `weights_only` is not `True`. 🟠 HIGH if the source is semi-trusted (e.g. an internal-but-shared bucket) — still no integrity guarantee.

### Pattern 2 — `trust_remote_code=True` on a third-party repo (runs the repo's Python)

```python
# This imports and executes a .py file that lives in the model repo on the Hub
model = AutoModelForCausalLM.from_pretrained(
    "some-random-user/exotic-arch",
    trust_remote_code=True,        # ← runs stranger-authored code in your process
)
```

`trust_remote_code=True` is not about the weights — it's about the *custom modeling code* shipped alongside them. On a repo you don't control, it is unconditional remote code execution by design. The library even prints a warning; AI-generated code routinely sets it to `True` to make an "exotic" model load without reading why.

**Severity:** 🔴 CRITICAL on any third-party repo. (See "What NOT to flag" for the first-party case.)

### Pattern 3 — Model pinned to a moving name, no revision (silent swap)

```python
# No revision → resolves to "main" → whatever the owner pushes next
embed = SentenceTransformer("some-org/embeddings-v1")          # moving
llm   = AutoModel.from_pretrained("some-org/base", revision="main")  # explicitly moving
lora  = PeftModel.from_pretrained(base, "some-org/adapter")    # adapter, also moving
```

Even a model that's *clean today* is loaded by a name that can point at different bytes tomorrow. If the repo owner's account is compromised, or the repo is transferred, or they push a "harmless update," your next deploy pulls the new bytes with zero review — and if the new bytes are a poisoned pickle, you're back to Pattern 1 with no one having changed a line of your code. Pinning to a 40-char commit SHA makes the artifact immutable: the hash *is* the integrity check.

**Severity:** 🟠 HIGH for an unpinned third-party model/adapter on a load-bearing path. 🟡 MEDIUM if it's pinned to a *tag* (better than `main`, but tags can be re-pointed) rather than a commit SHA.

### Pattern 4 — Build/runtime weight download with no integrity check

```dockerfile
# Image contents drift silently; no checksum means no way to detect tampering
RUN wget -q https://example-cdn.com/models/whisper-large.bin -O /models/whisper.bin
```
```dart
// Mobile: downloading a model at runtime, over the network, unverified
final bytes = await http.get(Uri.parse(modelUrl));   // no hash, maybe even http://
await File('$dir/model.tflite').writeAsBytes(bytes.bodyBytes);
```

This is the "no lockfile for your weights" case. There's no pinned hash, so a man-in-the-middle (on `http://`), a compromised CDN, or a changed source can substitute a different artifact and your build/app accepts it. The fix is the same shape as dependency integrity: download by a known hash (or a hash-addressed name) and verify before use.

**Severity:** 🟠 HIGH over plaintext `http://` or with no verification of a third-party source. 🟡 MEDIUM for HTTPS-from-a-trusted-host-but-no-hash.

## Report a finding as

**Title (Pattern 1 example):** "Your app downloads a stranger's model and runs it as code on load"

**Detail:**
> `app/ml/loader.py:23` downloads `pytorch_model.bin` from the Hub repo `randoml-org/cool-finetune` and loads it with `torch.load(path)` — no `weights_only=True`. A PyTorch checkpoint is a Python *pickle*, and unpickling can execute arbitrary code. So this isn't "load some numbers" — it's "run whatever code the person who published that model decided to bury in it," inside your server process, with your environment variables and your network access.
>
> **What can go wrong:** Public model hubs have hosted proof-of-concept "weaponized" models that open a reverse shell the moment they're loaded. You don't have to be doing anything else wrong — loading the file *is* the exploit. If this model is third-party and unpinned, assume the worst case for what could be loaded.
>
> **What to do tonight:**
> 1. Switch the format. Re-save / re-download as **safetensors** (a data-only format that cannot execute code) and load that instead:
>    ```python
>    from safetensors.torch import load_file
>    state = load_file(path)            # cannot run code, ever
>    model.load_state_dict(state)
>    ```
> 2. If you must load a `.bin`/`.pt`, force the safe path:
>    ```python
>    state = torch.load(path, weights_only=True)   # refuses to unpickle arbitrary objects
>    ```
> 3. Pin the source to an immutable commit so the bytes can't change under you:
>    ```python
>    path = hf_hub_download(
>        "randoml-org/cool-finetune", "model.safetensors",
>        revision="d3b07384d113edec49eaa6238ad5ff00",  # full 40-char commit SHA
>    )
>    ```
> 4. Verify: re-run your model load. Safetensors + `weights_only=True` should still produce the same outputs; if anything *breaks*, that's a sign the old file was relying on the unsafe object path — investigate, don't re-enable it.

---

**Title (Pattern 2 example):** "`trust_remote_code=True` lets a third-party model run its own code in your app"

**Detail:**
> `services/inference.py:11` calls `from_pretrained("some-random-user/exotic-arch", trust_remote_code=True)`. That flag tells `transformers` to download and **run** a Python file that ships inside that model repo on the Hub. You don't own that repo, so this is, plainly, executing a stranger's code in your process — every time the model loads.
>
> **What can go wrong:** Whoever controls that repo (or anyone who compromises their account) can change that bundled `.py` at any time. Your next deploy runs the new version with no review. This is remote code execution dressed up as "just loading a cool new architecture."
>
> **What to do tonight:**
> 1. Prefer a model whose architecture is already supported by `transformers` so you can drop the flag entirely:
>    ```python
>    model = AutoModelForCausalLM.from_pretrained("mistralai/Mistral-7B-v0.3")  # no trust_remote_code
>    ```
> 2. If you genuinely need a custom-arch model, do **not** set `trust_remote_code=True` on a repo you don't control. Fork it, **read the custom modeling code**, host your reviewed copy under an org you own, and load that — pinned to a commit:
>    ```python
>    from_pretrained("your-org/exotic-arch-reviewed", revision="<commit-sha>", trust_remote_code=True)
>    ```
> 3. Grep the whole repo for other `trust_remote_code=True` and apply the same rule to each.

---

**Title (Pattern 3 example):** "Your model isn't pinned — a future push could swap it without you noticing"

**Detail:**
> `app/embeddings.py:7` loads `SentenceTransformer("some-org/embeddings-v1")` with no `revision=`. With no revision, it resolves to the repo's `main` branch — meaning you get whatever bytes the repo owner has pushed there at deploy time, not a fixed version you reviewed.
>
> **What can go wrong:** The model may be perfectly fine today. But if that account is compromised or the repo changes hands, your *next deploy* silently pulls different weights — potentially a poisoned checkpoint that runs code on load (see Pattern 1). Nothing in your codebase changed, so nothing flags it. Pinning to a commit SHA makes the artifact immutable: if the bytes change, the hash won't resolve.
>
> **What to do tonight:**
> 1. Pin every model / adapter / tokenizer load to a full 40-character commit SHA (find it on the Hub repo's "commits" page):
>    ```python
>    SentenceTransformer("some-org/embeddings-v1", revision="a1b2c3d4...full40hex...")
>    ```
> 2. Treat the SHA like a lockfile entry — bump it deliberately, in a reviewed commit, not automatically.
> 3. While you're there, prefer the `.safetensors` artifact in the repo over `pytorch_model.bin`.

## Don't false-positive on

- **`torch.load(..., weights_only=True)`** — this is the *safe* path; it refuses to unpickle arbitrary objects. Not a finding. (PyTorch ≥ 2.6 makes this the default, so a bare `torch.load` on a known-new pin is also fine — but you usually can't prove the version from the repo, so prefer to confirm the flag is present.)
- **safetensors / GGUF / ONNX / plain `numpy.load` without `allow_pickle=True`** — these are data-only formats that can't execute code. Loading them is fine regardless of source. Don't flag `load_file(...)` from `safetensors`.
- **Pinned revisions with a commit SHA** — `from_pretrained(..., revision="<40-hex>")` is the *fix*, not a finding. (A *tag* like `v1.0` is better than `main` but can be re-pointed — note it as LOW at most, not HIGH.)
- **`trust_remote_code=True` on a repo the team owns and controls** — if the org/namespace is the user's own (matches their HF org, or it's a local path under their repo), this is a deliberate, legitimate choice for their own custom architecture. Note it as INFO and move on. The finding is specifically third-party repos.
- **Models committed into the repo / bundled in the app binary** — a `.pt`/`.tflite`/`.mlmodelc` checked into the project or shipped inside a signed mobile bundle came from the developer and is covered by code review and signing. The risk is *downloaded* artifacts, not vendored ones. (If a vendored `.bin` is huge and clearly third-party, you can note "consider safetensors + provenance," but it's not a CRITICAL.)
- **Local development paths** — `torch.load("./checkpoints/epoch_12.pt")` on a file the user trained themselves locally is fine; it's their own artifact. Only escalate when the path is fed from a download, a URL, a hub name, or user input.
- **`pickle.load` reading a *request*** (upload, cookie, body) — that's **`unsafe-deserialization.md`**, a different entry point. Don't double-report it here; if you found it via the grep above, hand it to that check.
- **Plain dependency installs** (`pip install transformers`, a model *library* in `requirements.txt`) — that's **`dependencies.md`**. This check is about the *weights artifact* a hub call pulls at load time, not the package that does the loading.
- **`pipeline("sentiment-analysis")` with no explicit model** that resolves to a well-known default from a first-party org (e.g. the HF default models) — note the implicit, unpinned default as LOW/INFO and recommend pinning, but it isn't a CRITICAL like an arbitrary third-party `trust_remote_code` load.
