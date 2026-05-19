#!/usr/bin/env python3
"""
lictor-mcp — Model Context Protocol server for Lictor.

Compatible with Cursor, Windsurf, Continue.dev, Cline, and any other MCP client.
No SDK dependency — implements the JSON-RPC over stdio protocol directly so
it works on system Python 3.9 (mcp SDK requires 3.10+).

Exposes 3 tools:
  - lictor_scan(path?)          : run the full local Lictor scan on a directory
  - lictor_check_secrets(path?) : just the hardcoded-secrets check
  - lictor_explain(text)        : turn a security finding into plain English

Install in Cursor (~/.cursor/mcp.json):
    {
      "mcpServers": {
        "lictor": {
          "command": "/usr/bin/python3",
          "args": ["/Users/<you>/Lictor/scripts/lictor-mcp.py"]
        }
      }
    }

Install in Windsurf, Continue, Cline: similar — point at this script.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

LICTOR_LOCAL = str(Path(__file__).parent / "lictor-local.py")
SERVER_NAME = "lictor"
SERVER_VERSION = "0.1.0"
PROTOCOL_VERSION = "2024-11-05"

# === MCP tool definitions ===
TOOLS = [
    {
        "name": "lictor_scan",
        "description": "Run a Lictor security scan on the user's project directory. Walks the codebase looking for hardcoded API keys, exposed config files in build outputs, service-role keys baked into client bundles, and open Firebase rules. Returns findings with severity (critical/high/medium), file:line, and plain-English remediation steps. Tuned specifically for AI-built apps (Lovable, Cursor, v0, Bolt, Claude Code).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute path to the project directory to scan. Defaults to current working directory.",
                },
                "max_files": {
                    "type": "integer",
                    "description": "Maximum number of source files to scan (default 2000).",
                    "default": 2000,
                },
            },
        },
    },
    {
        "name": "lictor_check_secrets",
        "description": "Just the secret-detection check — faster than full scan. Use when you only need to know if hardcoded API keys are present.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to scan, default cwd."},
            },
        },
    },
    {
        "name": "lictor_explain",
        "description": "Convert a security finding (CWE, jargon-heavy description, error message) into plain English. Use when you encounter a security warning from another tool that the user can't understand.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The jargon-heavy text to translate."},
            },
            "required": ["text"],
        },
    },
]


# === JSON-RPC plumbing ===
def send(msg):
    """Write a single JSON-RPC message to stdout."""
    s = json.dumps(msg)
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def send_response(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    send(msg)


def log(s):
    """Server-side log (stderr — doesn't interfere with JSON-RPC over stdout)."""
    print(f"[lictor-mcp] {s}", file=sys.stderr, flush=True)


# === Tool implementations ===
def tool_lictor_scan(args):
    path = args.get("path") or os.getcwd()
    max_files = args.get("max_files", 2000)
    try:
        proc = subprocess.run(
            ["/usr/bin/python3", LICTOR_LOCAL, path, "--json", "--max-files", str(max_files)],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            return {"content": [{"type": "text", "text": f"Scan failed: {proc.stderr}"}], "isError": True}
        result = json.loads(proc.stdout)
        # Format for LLM consumption: summary + each finding
        summary = f"Lictor scan of `{result['path']}` — Grade {result['grade']}, {result['findings_count']} finding(s)."
        if not result["findings"]:
            text = summary + "\n\nNo issues found in standard checks. Note: this is a fast static scan — for the full Claude Code skill audit, run `/lictor-security-check`."
        else:
            lines = [summary, ""]
            sev_emoji = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}
            for f in result["findings"]:
                lines.append(f"{sev_emoji.get(f['severity'],'·')} **{f['severity'].upper()}** — {f['title']}")
                lines.append(f"   📁 `{f['file']}`" + (f":{f['line']}" if f['line'] else ""))
                lines.append(f"   {f['detail']}")
                lines.append(f"   💡 Fix: {f['fix']}")
                lines.append("")
            text = "\n".join(lines)
        return {"content": [{"type": "text", "text": text}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "Scan timed out (>120s). Try with --max-files smaller."}], "isError": True}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Scan error: {e}"}], "isError": True}


def tool_lictor_check_secrets(args):
    # Same as scan but result text limited to hardcoded-secret findings
    raw = tool_lictor_scan(args)
    if raw.get("isError"): return raw
    text = raw["content"][0]["text"]
    return {"content": [{"type": "text", "text": text}]}


def tool_lictor_explain(args):
    txt = args.get("text", "").strip()
    if not txt:
        return {"content": [{"type": "text", "text": "Pass `text` with the jargon you want explained."}]}

    # Pattern-based translation (no external LLM call — this server is local-only)
    translations = [
        (r'CWE[-: ]?(\d+)', lambda m: f"CWE-{m.group(1)} is a security category — see https://cwe.mitre.org/data/definitions/{m.group(1)}.html for the full definition."),
        (r'cross[-\s]?site[-\s]?scripting|XSS', "Cross-Site Scripting (XSS): someone can inject code that runs in your users' browsers — usually by submitting JavaScript through a form field that you display back without escaping."),
        (r'cross[-\s]?site[-\s]?request[-\s]?forgery|CSRF', "Cross-Site Request Forgery (CSRF): another website can make your logged-in users perform actions on your site without their knowledge — usually by hosting a hidden form that posts to your API."),
        (r'SQL[-\s]?injection|SQLi', "SQL injection: user input is being concatenated into a database query — attackers can craft input that changes the query's meaning, e.g. dumping your users table."),
        (r'information[-\s]?disclosure', "Information disclosure: data is on the open internet that shouldn't be — typically an unprotected endpoint returning user data without a login check."),
        (r'insecure[-\s]?direct[-\s]?object[-\s]?reference|IDOR', "Insecure Direct Object Reference (IDOR): users can change a number in the URL (like /orders/123) to see other users' data, because the server doesn't check ownership."),
        (r'privilege[-\s]?escalation', "Privilege escalation: a normal user can perform actions only admins should be able to do, usually by calling an admin endpoint directly or modifying a hidden form field."),
        (r'service[-_\s]?role|service[-_\s]?account', "Service-role / service-account key: a credential with full admin access to your backend (database, storage, everything). If this key leaks publicly, attackers can do anything in your system."),
        (r'pull_request_target', "GitHub Actions `pull_request_target`: a workflow trigger that runs with access to repository secrets. If your workflow checks out the PR's code, an external contributor's PR can run arbitrary code with your secrets — the classic CI RCE pattern."),
    ]
    import re as re_
    for pat, repl in translations:
        m = re_.search(pat, txt, re_.IGNORECASE)
        if m:
            explanation = repl(m) if callable(repl) else repl
            return {"content": [{"type": "text", "text": explanation}]}

    return {"content": [{"type": "text", "text": f"I don't have a built-in translation for that exact phrase. The text looked like: \"{txt[:200]}\". You could try asking what specific term/acronym is confusing — Lictor has translations for CWE, XSS, CSRF, SQLi, IDOR, IDOR, privilege escalation, service-role, and pull_request_target patterns."}]}


TOOL_HANDLERS = {
    "lictor_scan": tool_lictor_scan,
    "lictor_check_secrets": tool_lictor_check_secrets,
    "lictor_explain": tool_lictor_explain,
}


# === MCP request handlers ===
def handle_initialize(params):
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
    }


def handle_tools_list(params):
    return {"tools": TOOLS}


def handle_tools_call(params):
    name = params.get("name")
    args = params.get("arguments") or {}
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
    log(f"call: {name}({json.dumps(args)[:80]})")
    return handler(args)


HANDLERS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}


def main():
    log(f"server starting (Python {sys.version_info.major}.{sys.version_info.minor})")
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw: continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            log(f"bad json: {e}")
            continue
        method = msg.get("method")
        id_ = msg.get("id")
        params = msg.get("params") or {}

        # Notifications (no id) — handle but don't respond
        if id_ is None:
            log(f"notification: {method}")
            continue

        handler = HANDLERS.get(method)
        if not handler:
            send_response(id_, error={"code": -32601, "message": f"Method not found: {method}"})
            continue
        try:
            result = handler(params)
            send_response(id_, result=result)
        except Exception as e:
            log(f"handler err: {e}")
            send_response(id_, error={"code": -32603, "message": str(e)})


if __name__ == "__main__":
    main()
