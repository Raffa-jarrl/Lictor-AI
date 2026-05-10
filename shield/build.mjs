// Build script for Lictor Shield (Chrome MV3 extension).
//
// Three esbuild bundles:
//   - content.ts → dist/content.js   (content script, runs in page context)
//   - background.ts → dist/background.js   (service worker)
//   - popup/popup.ts → dist/popup/popup.js
//
// Plus copies for manifest, popup HTML/CSS, and the WASM bundle.

import { build, context } from "esbuild";
import { cp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = __dirname;
const dist = join(root, "dist");
const watch = process.argv.includes("--watch");

const common = {
  bundle: true,
  format: "esm",
  target: "chrome121",
  minify: !watch,
  sourcemap: watch ? "inline" : false,
  logLevel: "info",
  loader: { ".wasm": "file" },
};

const entries = [
  { in: "src/content.ts",       out: "content.js" },
  { in: "src/background.ts",    out: "background.js" },
  { in: "src/popup/popup.ts",   out: "popup/popup.js" },
];

async function clean() {
  if (existsSync(dist)) await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });
  await mkdir(join(dist, "popup"), { recursive: true });
  await mkdir(join(dist, "wasm"), { recursive: true });
  await mkdir(join(dist, "assets"), { recursive: true });
}

async function copyStatic() {
  // manifest
  await cp(join(root, "manifest.json"), join(dist, "manifest.json"));
  // popup html + css
  await cp(join(root, "src/popup/popup.html"), join(dist, "popup/popup.html"));
  await cp(join(root, "src/popup/popup.css"), join(dist, "popup/popup.css"));

  // WASM (built by `pnpm wasm` / `npm run wasm`)
  const wasmDir = join(root, "wasm");
  if (!existsSync(wasmDir)) {
    console.warn("⚠  shield/wasm/ is empty. Run `npm run wasm` (or `pnpm wasm`) first.");
  } else {
    for (const f of ["lictor_core.js", "lictor_core.d.ts", "lictor_core_bg.wasm", "lictor_core_bg.wasm.d.ts"]) {
      const src = join(wasmDir, f);
      if (existsSync(src)) await cp(src, join(dist, "wasm", f));
    }
  }

  // Icons (if rendered). We ship a one-pixel transparent PNG so the
  // manifest validates even before a real designer pass — Chrome accepts
  // it. Replace with rendered helmet logos before Web Store submission.
  const oneByOnePng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
    "base64"
  );
  for (const size of [16, 32, 48, 128]) {
    await writeFile(join(dist, "assets", `icon-${size}.png`), oneByOnePng);
  }
}

async function buildAll() {
  await clean();
  await copyStatic();

  const opts = entries.map((e) => ({
    ...common,
    entryPoints: [join(root, e.in)],
    outfile: join(dist, e.out),
  }));

  if (watch) {
    const ctxs = await Promise.all(opts.map(context));
    await Promise.all(ctxs.map((c) => c.watch()));
    console.log("🔁 watching for changes…");
  } else {
    await Promise.all(opts.map(build));
    console.log(`✅ built to ${dist}`);
    console.log(`   load this directory in chrome://extensions (Developer Mode → Load unpacked)`);
  }
}

buildAll().catch((e) => {
  console.error(e);
  process.exit(1);
});
