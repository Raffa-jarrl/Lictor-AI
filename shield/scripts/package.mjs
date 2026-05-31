// Package script for Lictor Shield (Chrome MV3 extension).
//
// 1. Runs the normal build (build.mjs → dist/).
// 2. Zips the *contents* of dist/ (not the dist/ folder itself) into
//    lictor-shield-<version>.zip at the shield/ root.
//
// Chrome's "Load unpacked" / packed install expects manifest.json at the
// archive root, so we cd into dist/ before zipping.

import { spawnSync } from "node:child_process";
import { readFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const dist = join(root, "dist");

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} exited with ${r.status ?? r.signal}`);
  }
}

async function main() {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const version = pkg.version;
  if (!version) throw new Error("No version field in package.json");

  const zipName = `lictor-shield-${version}.zip`;
  const zipPath = join(root, zipName);

  // 1. Build dist/
  run(process.execPath, [join(root, "build.mjs")]);

  if (!existsSync(join(dist, "manifest.json"))) {
    throw new Error("Build did not produce dist/manifest.json — aborting package.");
  }

  // 2. Remove any stale zip, then zip the contents of dist/.
  if (existsSync(zipPath)) await rm(zipPath);

  // -r recurse, -X strip extra file attributes, run from inside dist/ so
  // paths in the archive are relative to dist/ (manifest.json at root).
  run("zip", ["-r", "-X", zipPath, "."], { cwd: dist });

  const { size } = await stat(zipPath);
  console.log(`\n✅ packaged ${zipName} (${(size / 1024).toFixed(1)} KB)`);
  console.log(`   ${zipPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
