/**
 * Command implementations — shells out to the `lictor` CLI binary.
 *
 * In v0.1.0-pre.0 we depend on the user having `lictor-cli` installed (one
 * line: `cargo install lictor-cli`). In v0.2 we bundle the lictor-core
 * WASM into the extension itself so there's no CLI dependency.
 */

import * as vscode from "vscode";
import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as path from "path";
import type { AuditDocument } from "./types";

const execAsync = promisify(exec);

const AUDIT_TIMEOUT_MS = 90_000; // 90 seconds — generous; most audits finish under 10s

/**
 * Run the Lictor audit against the entire workspace root.
 * Returns the parsed AUDIT.json or null if cancelled.
 */
export async function auditWorkspace(): Promise<AuditDocument | null> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("No workspace open.");
    return null;
  }
  const root = folders[0].uri.fsPath;
  return runLictor(root);
}

/**
 * Run the Lictor audit against a single file.
 * Returns the parsed AUDIT.json or null.
 */
export async function auditFile(uri: vscode.Uri): Promise<AuditDocument | null> {
  return runLictor(uri.fsPath);
}

/**
 * Read an AUDIT.json file from disk and parse it.
 * Used for importing output from Snyk / Semgrep / Trivy / other tools that
 * also emit the spec format.
 */
export async function importAuditJson(): Promise<AuditDocument | null> {
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: { "AUDIT.json": ["json"] },
    title: "Import AUDIT.json from another security tool",
  });
  if (!picked || picked.length === 0) return null;

  const content = fs.readFileSync(picked[0].fsPath, "utf-8");
  const doc = JSON.parse(content) as AuditDocument;

  if (!doc.spec_version || !doc.findings) {
    throw new Error("File doesn't look like a valid AUDIT.json document.");
  }
  return doc;
}

/**
 * Write the current AuditDocument to disk.
 * Returns the chosen file path.
 */
export async function exportFindings(doc: AuditDocument): Promise<string> {
  const folders = vscode.workspace.workspaceFolders;
  const defaultUri = folders
    ? vscode.Uri.file(path.join(folders[0].uri.fsPath, `lictor-audit-${new Date().toISOString().slice(0, 10)}.json`))
    : undefined;

  const target = await vscode.window.showSaveDialog({
    defaultUri,
    filters: { "AUDIT.json": ["json"] },
    title: "Export Lictor findings as AUDIT.json",
  });
  if (!target) throw new Error("Export cancelled");

  fs.writeFileSync(target.fsPath, JSON.stringify(doc, null, 2));
  return target.fsPath;
}

// ── Internals ────────────────────────────────────────────────────────────

async function runLictor(target: string): Promise<AuditDocument | null> {
  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Running Lictor audit on ${path.basename(target)}…`,
      cancellable: false,
    },
    async () => {
      try {
        const { stdout } = await execAsync(
          `lictor audit "${target}" --format json --offline`,
          { timeout: AUDIT_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 },
        );
        return JSON.parse(stdout) as AuditDocument;
      } catch (err: any) {
        // exit code 1 = audit found findings (still has valid JSON output)
        if (err.stdout) {
          try {
            return JSON.parse(err.stdout) as AuditDocument;
          } catch {
            // fall through to error
          }
        }
        if (err.code === "ENOENT") {
          throw new Error(
            "The `lictor` CLI isn't on your PATH. Install with: cargo install lictor-cli",
          );
        }
        throw new Error(err.message ?? String(err));
      }
    },
  );
}
