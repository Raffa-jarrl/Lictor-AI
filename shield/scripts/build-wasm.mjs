// Build lictor-core to WASM, then run a post-build size-optimization pass
// using whichever wasm-opt is on PATH (binaryen 119+ recommended; the one
// wasm-pack bundles is older than rustc's bulk-memory output and crashes).
//
// Usage: pnpm wasm  (or `node shield/scripts/build-wasm.mjs`)

import { execSync, spawnSync } from "node:child_process";
import { existsSync, statSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const shieldDir = join(__dirname, "..");
const coreDir = join(shieldDir, "..", "core");
const wasmDir = join(shieldDir, "wasm");
const wasmFile = join(wasmDir, "lictor_core_bg.wasm");

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", shell: false, ...opts });
  if (r.status !== 0) {
    console.error(`✗ ${cmd} ${args.join(" ")} failed (exit ${r.status})`);
    process.exit(r.status ?? 1);
  }
}

function which(cmd) {
  try {
    return execSync(`command -v ${cmd}`, { encoding: "utf8" }).trim();
  } catch {
    return null;
  }
}

function sizeKb(file) {
  return Math.round(statSync(file).size / 1024);
}

// 1. wasm-pack build
console.log("→ wasm-pack build (lictor-core, --features wasm)");
run("wasm-pack", [
  "build",
  "--target", "web",
  "--out-dir", wasmDir,
  "--no-default-features",
  "--features", "wasm",
], { cwd: coreDir });

if (!existsSync(wasmFile)) {
  console.error(`✗ ${wasmFile} not produced — wasm-pack output unexpected`);
  process.exit(1);
}

const before = sizeKb(wasmFile);

// 2. wasm-opt size pass (skipped gracefully if wasm-opt isn't installed)
const wasmOpt = which("wasm-opt");
if (!wasmOpt) {
  console.log("⚠  wasm-opt not on PATH — skipping size optimization.");
  console.log(`   Install: brew install binaryen   (or build from source)`);
  console.log(`   Final WASM: ${before} KB`);
  process.exit(0);
}

console.log(`→ wasm-opt -Oz (size pass) — was ${before} KB`);
const tmp = wasmFile + ".opt";
run(wasmOpt, [
  "-Oz",
  "--enable-bulk-memory",
  "--strip-debug",
  "--strip-producers",
  "--strip-target-features",
  wasmFile,
  "-o", tmp,
]);
renameSync(tmp, wasmFile);
const after = sizeKb(wasmFile);
const saved = before - after;
const pct = Math.round((saved / before) * 100);
console.log(`✓ optimized: ${after} KB  (saved ${saved} KB, -${pct}%)`);
