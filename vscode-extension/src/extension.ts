/**
 * Lictor VS Code extension — entry point.
 *
 * v0.1.0-pre.0 ships with the command surface + Problems panel integration.
 * The audit engine itself shells out to the `lictor` CLI (installed via
 * `cargo install lictor-cli` or via the bundled WASM core in v0.2).
 *
 * See docs/launch/vscode-extension-mvp-spec.md for the full v0.1 scope.
 */

import * as vscode from "vscode";
import { exec } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs";

import { FindingsProvider } from "./findingsProvider";
import { auditWorkspace, auditFile, importAuditJson, exportFindings } from "./commands";
import type { AuditDocument } from "./types";

const execAsync = promisify(exec);

// Module-level state — Lictor's findings cache + diagnostics collection.
let diagnosticsCollection: vscode.DiagnosticCollection;
let findingsProvider: FindingsProvider;
let currentDocument: AuditDocument | null = null;

export async function activate(context: vscode.ExtensionContext) {
  console.log("Lictor extension activated.");

  // Verify lictor-cli is available (warn but don't fail)
  await checkLictorCli();

  // Diagnostic collection — surfaces findings in the Problems panel
  diagnosticsCollection = vscode.languages.createDiagnosticCollection("lictor");
  context.subscriptions.push(diagnosticsCollection);

  // Sidebar tree view
  findingsProvider = new FindingsProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("lictor.findingsView", findingsProvider),
  );

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("lictor.auditWorkspace", async () => {
      try {
        const doc = await auditWorkspace();
        if (doc) {
          currentDocument = doc;
          updateDiagnostics(doc);
          findingsProvider.refresh(doc);
          showSummary(doc);
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Lictor audit failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }),

    vscode.commands.registerCommand("lictor.auditFile", async (uri?: vscode.Uri) => {
      const target = uri ?? vscode.window.activeTextEditor?.document.uri;
      if (!target) {
        vscode.window.showWarningMessage("No file selected for audit.");
        return;
      }
      try {
        const doc = await auditFile(target);
        if (doc) {
          currentDocument = doc;
          updateDiagnostics(doc);
          findingsProvider.refresh(doc);
          showSummary(doc);
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Lictor audit failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }),

    vscode.commands.registerCommand("lictor.importAuditJson", async () => {
      try {
        const doc = await importAuditJson();
        if (doc) {
          currentDocument = doc;
          updateDiagnostics(doc);
          findingsProvider.refresh(doc);
          vscode.window.showInformationMessage(
            `Imported ${doc.findings.length} findings from ${doc.tool.name}.`,
          );
        }
      } catch (e) {
        vscode.window.showErrorMessage(`Import failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }),

    vscode.commands.registerCommand("lictor.exportFindings", async () => {
      if (!currentDocument) {
        vscode.window.showWarningMessage("No findings to export. Run an audit first.");
        return;
      }
      try {
        const path = await exportFindings(currentDocument);
        vscode.window.showInformationMessage(`Exported to ${path}`);
      } catch (e) {
        vscode.window.showErrorMessage(`Export failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }),

    vscode.commands.registerCommand("lictor.explainFinding", async () => {
      // v0.1.0-pre.0: hand off to Claude Code skill if available, else show finding details
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const line = editor.selection.active.line + 1;
      const filePath = editor.document.uri.fsPath;
      const finding = findFindingAt(filePath, line);
      if (!finding) {
        vscode.window.showInformationMessage("No Lictor finding at this line.");
        return;
      }
      // Show finding in a webview / output channel — see findingsProvider for detail UI
      vscode.window.showInformationMessage(
        `${finding.title}: ${finding.summary}`,
        "Show fix",
      ).then((choice) => {
        if (choice === "Show fix" && finding.fix?.summary) {
          vscode.window.showInformationMessage(finding.fix.summary);
        }
      });
    }),
  );

  // Auto-detect platform + offer audit on first workspace open
  if (vscode.workspace.workspaceFolders) {
    const platform = await detectPlatform(vscode.workspace.workspaceFolders[0].uri.fsPath);
    if (platform !== "unknown") {
      const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
      status.text = `$(shield) Lictor: ${platform}`;
      status.tooltip = `${platform} project detected. Click to audit.`;
      status.command = "lictor.auditWorkspace";
      status.show();
      context.subscriptions.push(status);
    }
  }
}

export function deactivate() {
  diagnosticsCollection?.dispose();
}

// ── Helpers ─────────────────────────────────────────────────────────────

async function checkLictorCli() {
  try {
    await execAsync("lictor version");
  } catch {
    vscode.window
      .showWarningMessage(
        "Lictor CLI not found on PATH. The extension needs it to run audits.",
        "Install instructions",
      )
      .then((choice) => {
        if (choice === "Install instructions") {
          vscode.env.openExternal(
            vscode.Uri.parse("https://lictor-ai.com/cli"),
          );
        }
      });
  }
}

async function detectPlatform(rootPath: string): Promise<string> {
  if (fs.existsSync(path.join(rootPath, ".lovable.json"))) return "Lovable";
  if (fs.existsSync(path.join(rootPath, ".bolt"))) return "Bolt";
  if (fs.existsSync(path.join(rootPath, "vercel.json"))) return "v0";
  if (fs.existsSync(path.join(rootPath, ".replit"))) return "Replit";
  return "unknown";
}

function updateDiagnostics(doc: AuditDocument) {
  diagnosticsCollection.clear();

  // Group findings by file
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of doc.findings) {
    const filePath = finding.evidence?.file_path;
    if (!filePath) continue;

    const line = (finding.evidence?.line ?? 1) - 1; // VS Code is 0-indexed
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

    const severity = mapSeverity(finding.severity);
    const diag = new vscode.Diagnostic(
      range,
      `${finding.title}\n\n${finding.summary}${
        finding.fix?.summary ? `\n\nFix: ${finding.fix.summary}` : ""
      }`,
      severity,
    );
    diag.source = "Lictor";
    diag.code = finding.id;

    const arr = byFile.get(filePath) ?? [];
    arr.push(diag);
    byFile.set(filePath, arr);
  }

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) return;

  const root = workspaceFolders[0].uri.fsPath;
  for (const [relPath, diags] of byFile.entries()) {
    const absPath = path.isAbsolute(relPath) ? relPath : path.join(root, relPath);
    diagnosticsCollection.set(vscode.Uri.file(absPath), diags);
  }
}

function mapSeverity(s: string): vscode.DiagnosticSeverity {
  switch (s) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function findFindingAt(filePath: string, line: number) {
  if (!currentDocument) return null;
  return (
    currentDocument.findings.find(
      (f) =>
        (f.evidence?.file_path === filePath ||
          filePath.endsWith(f.evidence?.file_path ?? "")) &&
        f.evidence?.line === line,
    ) ?? null
  );
}

function showSummary(doc: AuditDocument) {
  const { critical, high, medium, low, info, total } = doc.summary;
  const msg = `Lictor: ${total} findings — 🔴 ${critical} · 🟠 ${high} · 🟡 ${medium} · 🔵 ${low} · ⚪ ${info}`;
  if (critical > 0) {
    vscode.window.showErrorMessage(msg, "Show details").then((c) => {
      if (c) vscode.commands.executeCommand("workbench.action.problems.focus");
    });
  } else if (high > 0) {
    vscode.window.showWarningMessage(msg, "Show details").then((c) => {
      if (c) vscode.commands.executeCommand("workbench.action.problems.focus");
    });
  } else {
    vscode.window.showInformationMessage(msg);
  }
}
