#!/usr/bin/env python3
"""
Cyber-Sentry AI — MCP Server (Model Context Protocol)

A standalone MCP server that exposes Cyber-Sentry AI's pentesting tools
to MCP-compatible AI clients (Claude Desktop, Cursor, VS Code Copilot).

Usage (stdio mode — default for AI client integration):
    python3 cyber_sentry_mcp.py

Usage (with an optional HTTP backend, for advanced setups):
    python3 cyber_sentry_mcp.py --server http://localhost:8888

Configuration for Claude Desktop / Cursor:
  Edit ~/.config/Claude/claude_desktop_config.json (or equivalent):

    {
      "mcpServers": {
        "cyber-sentry": {
          "command": "python3",
          "args": ["/path/to/cyber_sentry_mcp.py"],
          "description": "Cyber-Sentry AI v2.0 – Red Team Pentesting Agent",
          "timeout": 300,
          "disabled": false
        }
      }
    }

Configuration for VS Code Copilot:
  Edit .vscode/settings.json:

    {
      "mcp": {
        "servers": {
          "cyber-sentry": {
            "type": "stdio",
            "command": "python3",
            "args": ["/path/to/cyber_sentry_mcp.py"]
          }
        }
      }
    }
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure the repo root is on sys.path so imports work when this script is run
# directly from the repository checkout (no pip install required).
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR  # cyber_sentry_mcp.py lives at repo root
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cyber_sentry import __version__
from cyber_sentry.guardrails.scope_validator import validate_scope, get_authorized_scopes
from cyber_sentry.notes import NotesManager
from cyber_sentry.browser_agent import BrowserAgent
from cyber_sentry.cve_intel import CVEIntelligence
from cyber_sentry.cache import SmartCache
from cyber_sentry.cli import list_playbooks, load_playbook


# ═══════════════════════════════════════════════════════════════════════════
#  Tool implementations — thin wrappers around existing Cyber-Sentry code
# ═══════════════════════════════════════════════════════════════════════════

def _run_tool(tool_name: str, command: str, target: str) -> dict:
    """Run one of the network tools by name and return a result dict."""
    if not validate_scope(target):
        return {
            "success": False,
            "error": f"Target '{target}' is not in the authorized scope. "
                     f"Authorized scopes: {', '.join(get_authorized_scopes())}",
        }
    try:
        from cyber_sentry.tools.network_tools import tool_registry
        func = tool_registry.get_tool(tool_name)
        if func is None:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
        output = func(command, target)
        return {"success": True, "output": output}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def tool_nmap_scan(target: str, options: str = "") -> str:
    """Run an nmap scan against the target."""
    cmd = f"nmap {options} {target}".strip() if options else ""
    r = _run_tool("nmap_scan", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_nikto_scan(target: str, options: str = "") -> str:
    """Run a Nikto web vulnerability scan against the target."""
    cmd = f"nikto {options} -h http://{target}".strip() if options else ""
    r = _run_tool("nikto_scan", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_nuclei_scan(target: str, options: str = "") -> str:
    """Run Nuclei vulnerability scanner against the target."""
    cmd = f"nuclei {options} -u http://{target}".strip() if options else ""
    r = _run_tool("nuclei_scan", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_gobuster_scan(target: str, options: str = "") -> str:
    """Run Gobuster directory/file enumeration against the target."""
    cmd = f"gobuster {options}".strip() if options else ""
    r = _run_tool("gobuster_scan", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_sqlmap_scan(target: str, options: str = "") -> str:
    """Run SQLMap to test for SQL injection on the target."""
    cmd = f"sqlmap {options}".strip() if options else ""
    r = _run_tool("sqlmap_scan", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_whois_lookup(target: str) -> str:
    """Perform a WHOIS lookup on the target domain."""
    r = _run_tool("whois_lookup", "", target)
    return r.get("output") or r.get("error", "unknown error")


def tool_dig_lookup(target: str, record_type: str = "ANY") -> str:
    """Perform DNS record lookup using dig."""
    cmd = f"dig {target} {record_type}"
    r = _run_tool("dig_lookup", cmd, target)
    return r.get("output") or r.get("error", "unknown error")


def tool_scope_check(target: str) -> str:
    """Check whether a target is within the authorized testing scope."""
    allowed = validate_scope(target)
    scopes = get_authorized_scopes()
    return json.dumps({
        "target": target,
        "authorized": allowed,
        "authorized_scopes": scopes,
    }, indent=2)


def tool_list_tools() -> str:
    """List all 151+ security tools available in Cyber-Sentry."""
    from cyber_sentry.tools.network_tools import tool_registry
    tools = tool_registry.list_tools()
    lines = []
    categories: dict[str, list] = {}
    for t in tools:
        categories.setdefault(t["category"], []).append(t)
    for cat in sorted(categories):
        lines.append(f"\n[{cat.upper()}]")
        for t in categories[cat]:
            lines.append(f"  {t['name']:<24s} {t['description']}")
    return f"Cyber-Sentry AI — {len(tools)} tools across {len(categories)} categories\n" + "\n".join(lines)


def tool_list_playbooks() -> str:
    """List available attack playbooks (pre-built security assessment workflows)."""
    names = list_playbooks()
    if not names:
        return "No playbooks found."
    lines = []
    for n in names:
        pb = load_playbook(n)
        desc = pb.get("description", "").split("\n")[0].strip() if pb else ""
        cat = pb.get("category", "general") if pb else "general"
        lines.append(f"  {n:<20s}  [{cat}]  {desc}")
    return "Available playbooks:\n" + "\n".join(lines)


def tool_analyze_headers(url: str) -> str:
    """Analyze HTTP security headers for a URL."""
    agent = BrowserAgent()
    try:
        result = agent.analyze_security_headers(url)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Error analyzing headers: {exc}"


def tool_detect_technologies(url: str) -> str:
    """Detect web technologies used by a URL."""
    agent = BrowserAgent()
    try:
        result = agent.detect_technologies(url)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Error detecting technologies: {exc}"


def tool_find_forms(url: str) -> str:
    """Discover HTML forms and input fields on a page (useful for injection testing)."""
    agent = BrowserAgent()
    try:
        result = agent.find_forms(url)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Error finding forms: {exc}"


def tool_check_cors(url: str) -> str:
    """Test CORS configuration for a URL."""
    agent = BrowserAgent()
    try:
        result = agent.check_cors(url)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Error checking CORS: {exc}"


def tool_cve_lookup(cve_id: str) -> str:
    """Look up a CVE by its ID (e.g. CVE-2024-1234)."""
    intel = CVEIntelligence()
    result = intel.lookup(cve_id)
    if result is None:
        return f"CVE {cve_id} not found in the local database."
    return json.dumps(result, indent=2)


def tool_cve_search(query: str) -> str:
    """Search the CVE database by keyword."""
    intel = CVEIntelligence()
    results = intel.search(query)
    if not results:
        return f"No CVEs found matching '{query}'."
    return json.dumps(results, indent=2)


def tool_add_note(content: str, category: str = "finding", target: str = "") -> str:
    """Save a finding/note to the loot directory."""
    notes = NotesManager()
    note = notes.add_note(content=content, category=category, target=target, source="mcp")
    return json.dumps(note, indent=2)


def tool_get_notes(category: str = "", target: str = "") -> str:
    """Retrieve saved notes/findings, optionally filtered."""
    notes = NotesManager()
    result = notes.get_notes(
        category=category or None,
        target=target or None,
    )
    if not result:
        return "No notes found."
    return json.dumps(result, indent=2)


def tool_status() -> str:
    """Show Cyber-Sentry AI system status."""
    from cyber_sentry.tools.network_tools import tool_registry
    tools = tool_registry.list_tools()
    notes = NotesManager()
    note_count = len(notes.get_notes())
    playbooks = list_playbooks()

    try:
        cache = SmartCache()
        cache_hits = cache.stats.get("hits", 0)
        cache_misses = cache.stats.get("misses", 0)
    except Exception:
        cache_hits, cache_misses = 0, 0

    return json.dumps({
        "name": "Cyber-Sentry AI",
        "version": __version__,
        "tools_count": len(tools),
        "playbooks": playbooks,
        "notes_count": note_count,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "authorized_scopes": get_authorized_scopes(),
    }, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  MCP Tool Registry — maps names → callables + schemas
# ═══════════════════════════════════════════════════════════════════════════

MCP_TOOLS: list[dict] = [
    {
        "name": "nmap_scan",
        "description": "Run an nmap port/service scan against a target host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host, IP, or domain"},
                "options": {"type": "string", "description": "Extra nmap flags (e.g. '-sV -sC -T4')", "default": ""},
            },
            "required": ["target"],
        },
        "handler": tool_nmap_scan,
    },
    {
        "name": "nikto_scan",
        "description": "Run Nikto web vulnerability scanner against a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or domain"},
                "options": {"type": "string", "description": "Extra nikto flags", "default": ""},
            },
            "required": ["target"],
        },
        "handler": tool_nikto_scan,
    },
    {
        "name": "nuclei_scan",
        "description": "Run Nuclei vulnerability scanner with 4000+ templates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or URL"},
                "options": {"type": "string", "description": "Extra nuclei flags", "default": ""},
            },
            "required": ["target"],
        },
        "handler": tool_nuclei_scan,
    },
    {
        "name": "gobuster_scan",
        "description": "Run Gobuster for directory/file enumeration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or domain"},
                "options": {"type": "string", "description": "Extra gobuster flags", "default": ""},
            },
            "required": ["target"],
        },
        "handler": tool_gobuster_scan,
    },
    {
        "name": "sqlmap_scan",
        "description": "Run SQLMap to test for SQL injection vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with injection point"},
                "options": {"type": "string", "description": "Extra sqlmap flags", "default": ""},
            },
            "required": ["target"],
        },
        "handler": tool_sqlmap_scan,
    },
    {
        "name": "whois_lookup",
        "description": "Perform WHOIS lookup on a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain name to look up"},
            },
            "required": ["target"],
        },
        "handler": tool_whois_lookup,
    },
    {
        "name": "dig_lookup",
        "description": "Perform DNS lookup using dig.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain to query"},
                "record_type": {"type": "string", "description": "DNS record type (A, AAAA, MX, NS, TXT, ANY)", "default": "ANY"},
            },
            "required": ["target"],
        },
        "handler": tool_dig_lookup,
    },
    {
        "name": "scope_check",
        "description": "Check if a target is within the authorized pentesting scope.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to check"},
            },
            "required": ["target"],
        },
        "handler": tool_scope_check,
    },
    {
        "name": "list_tools",
        "description": "List all 151+ security tools available in Cyber-Sentry AI.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_list_tools,
    },
    {
        "name": "list_playbooks",
        "description": "List available attack playbooks (web_pentest, recon, ctf, etc.).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_list_playbooks,
    },
    {
        "name": "analyze_headers",
        "description": "Analyze HTTP security headers for a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to analyze (e.g. http://example.com)"},
            },
            "required": ["url"],
        },
        "handler": tool_analyze_headers,
    },
    {
        "name": "detect_technologies",
        "description": "Detect web technologies (frameworks, CMS, servers) used by a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to analyze"},
            },
            "required": ["url"],
        },
        "handler": tool_detect_technologies,
    },
    {
        "name": "find_forms",
        "description": "Discover HTML forms and input fields on a page (for injection testing).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to analyze"},
            },
            "required": ["url"],
        },
        "handler": tool_find_forms,
    },
    {
        "name": "check_cors",
        "description": "Test CORS configuration of a URL for misconfigurations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Full URL to test"},
            },
            "required": ["url"],
        },
        "handler": tool_check_cors,
    },
    {
        "name": "cve_lookup",
        "description": "Look up a specific CVE by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID (e.g. CVE-2024-1234)"},
            },
            "required": ["cve_id"],
        },
        "handler": tool_cve_lookup,
    },
    {
        "name": "cve_search",
        "description": "Search the CVE intelligence database by keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword (e.g. 'apache', 'rce')"},
            },
            "required": ["query"],
        },
        "handler": tool_cve_search,
    },
    {
        "name": "add_note",
        "description": "Save a finding or note to the Cyber-Sentry loot directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Note content"},
                "category": {"type": "string", "description": "Category: finding, vulnerability, credential, artifact", "default": "finding"},
                "target": {"type": "string", "description": "Related target", "default": ""},
            },
            "required": ["content"],
        },
        "handler": tool_add_note,
    },
    {
        "name": "get_notes",
        "description": "Retrieve saved notes/findings from the loot directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Filter by category", "default": ""},
                "target": {"type": "string", "description": "Filter by target", "default": ""},
            },
        },
        "handler": tool_get_notes,
    },
    {
        "name": "status",
        "description": "Show Cyber-Sentry AI system status (version, tools, notes, scopes).",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": tool_status,
    },
]


# ═══════════════════════════════════════════════════════════════════════════
#  JSON-RPC / MCP stdio protocol handler
# ═══════════════════════════════════════════════════════════════════════════

_SERVER_INFO = {
    "name": "cyber-sentry",
    "version": __version__,
}

_SERVER_CAPABILITIES = {
    "tools": {},
}


def _build_tool_list() -> list[dict]:
    """Build the MCP tools/list response."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "inputSchema": t["inputSchema"],
        }
        for t in MCP_TOOLS
    ]


def _handle_tool_call(name: str, arguments: dict) -> list[dict]:
    """Execute a tool and return MCP-formatted content blocks."""
    handler = None
    for t in MCP_TOOLS:
        if t["name"] == name:
            handler = t["handler"]
            break
    if handler is None:
        return [{"type": "text", "text": f"Error: unknown tool '{name}'"}]

    try:
        result = handler(**arguments)
        return [{"type": "text", "text": str(result)}]
    except TypeError as exc:
        return [{"type": "text", "text": f"Error calling {name}: {exc}"}]
    except Exception as exc:
        return [{"type": "text", "text": f"Error: {exc}"}]


def _handle_request(req: dict) -> dict | None:
    """Process a single JSON-RPC request and return a response dict (or None for notifications)."""
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params", {})

    # --- Initialize handshake ---
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": _SERVER_INFO,
                "capabilities": _SERVER_CAPABILITIES,
            },
        }

    # --- Notifications (no id → no response) ---
    if method == "notifications/initialized":
        return None

    # ping
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    # --- tools/list ---
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": _build_tool_list()},
        }

    # --- tools/call ---
    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        content = _handle_tool_call(tool_name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": content, "isError": False},
        }

    # --- Unknown method ---
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": -32601,
            "message": f"Method not found: {method}",
        },
    }


def run_stdio():
    """Run the MCP server on stdin/stdout (the standard MCP transport)."""
    import io

    # Use binary stdin/stdout to avoid encoding issues
    stdin = sys.stdin.buffer if hasattr(sys.stdin, "buffer") else sys.stdin
    stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout

    reader = io.TextIOWrapper(stdin, encoding="utf-8")
    writer = io.TextIOWrapper(stdout, encoding="utf-8", line_buffering=True)

    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            writer.write(json.dumps(resp) + "\n")
            writer.flush()
            continue

        response = _handle_request(req)
        if response is not None:
            writer.write(json.dumps(response) + "\n")
            writer.flush()


# ═══════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Cyber-Sentry AI — MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--server",
        default=None,
        help="(optional) Upstream HTTP server URL for advanced setups",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print available tools and exit",
    )
    args = parser.parse_args()

    if args.list_tools:
        for t in _build_tool_list():
            print(f"  {t['name']:<24s}  {t['description']}")
        return

    # Store the server URL in env if provided (tools can read it)
    if args.server:
        os.environ["CYBER_SENTRY_SERVER"] = args.server

    run_stdio()


if __name__ == "__main__":
    main()
