/**
 * Sidebar tree view for the latest audit findings.
 * Groups by severity; clicking a finding opens the file at the line.
 */

import * as vscode from "vscode";
import * as path from "path";
import type { AuditDocument, Finding, Severity } from "./types";

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

type Node = SeverityGroup | FindingNode;

interface SeverityGroup {
  type: "group";
  severity: Severity;
  count: number;
  findings: Finding[];
}

interface FindingNode {
  type: "finding";
  finding: Finding;
}

export class FindingsProvider implements vscode.TreeDataProvider<Node> {
  private _doc: AuditDocument | null = null;
  private _onDidChangeTreeData = new vscode.EventEmitter<Node | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(doc: AuditDocument) {
    this._doc = doc;
    this._onDidChangeTreeData.fire();
  }

  clear() {
    this._doc = null;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.type === "group") {
      const item = new vscode.TreeItem(
        `${SEVERITY_ICONS[node.severity]} ${node.severity.toUpperCase()} · ${node.count}`,
        vscode.TreeItemCollapsibleState.Expanded,
      );
      item.contextValue = "lictor.severityGroup";
      return item;
    }

    const f = node.finding;
    const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
    item.description = f.evidence?.file_path
      ? `${path.basename(f.evidence.file_path)}${f.evidence.line ? `:${f.evidence.line}` : ""}`
      : f.category ?? "";
    item.tooltip = new vscode.MarkdownString(
      `**${f.title}**\n\n${f.summary}${
        f.fix?.summary ? `\n\n**Fix:** ${f.fix.summary}` : ""
      }`,
    );
    item.contextValue = "lictor.finding";

    // Click to open the file at the right line
    if (f.evidence?.file_path) {
      const folders = vscode.workspace.workspaceFolders;
      const absPath = path.isAbsolute(f.evidence.file_path)
        ? f.evidence.file_path
        : folders
          ? path.join(folders[0].uri.fsPath, f.evidence.file_path)
          : f.evidence.file_path;

      item.command = {
        command: "vscode.open",
        title: "Open file",
        arguments: [
          vscode.Uri.file(absPath),
          {
            selection: f.evidence.line
              ? new vscode.Range(
                  f.evidence.line - 1,
                  0,
                  f.evidence.line - 1,
                  Number.MAX_SAFE_INTEGER,
                )
              : undefined,
          },
        ],
      };
    }

    return item;
  }

  getChildren(node?: Node): Node[] {
    if (!this._doc) return [];
    if (!node) {
      // Top level — severity groups
      const groups: SeverityGroup[] = [];
      for (const sev of SEVERITY_ORDER) {
        const findings = this._doc.findings.filter((f) => f.severity === sev);
        if (findings.length > 0) {
          groups.push({ type: "group", severity: sev, count: findings.length, findings });
        }
      }
      return groups;
    }
    if (node.type === "group") {
      return node.findings.map<FindingNode>((f) => ({ type: "finding", finding: f }));
    }
    return [];
  }
}
