#!/usr/bin/env python3
"""
Dexter AI Pentest — MCP Server (Model Context Protocol)

FastMCP-based MCP server that exposes Dexter AI Pentest pentesting tools
to MCP-compatible AI clients such as Claude Desktop, Cursor, and VS Code
Copilot — inspired by the HexStrike AI MCP architecture.

Architecture:
    dexter_ai_mcp.py  ←  MCP stdio client (this file)
           ↕  JSON-RPC / stdio
    AI Client (Claude Desktop / Cursor / VS Code Copilot)

Quick-start (no Docker required):
    pip install -e "."                    # install Dexter AI Pentest
    pip install "mcp[cli]>=1.0.0"        # install FastMCP SDK
    python3 dexter_ai_mcp.py          # start MCP server

Flags:
    --compact      Load only essential gateway tools (scope_check,
                   run_security_tool, system_status) — ideal for
                   lightweight / small-LLM setups.
    --server URL   Optional upstream Dexter AI Pentest API server URL.
    --timeout N    Tool execution timeout in seconds (default: 300).
    --debug        Enable debug logging.

Claude Desktop integration:
    Edit ~/.config/Claude/claude_desktop_config.json:

    {
      "mcpServers": {
        "dexter-ai": {
          "command": "python3",
          "args": ["/path/to/dexter_ai_mcp.py"],
          "description": "Dexter AI Pentest v2.0 – AI Red Team Pentesting Agent",
          "timeout": 300,
          "disabled": false
        }
      }
    }

Cursor integration:
    Same JSON as above in Cursor MCP settings.

VS Code Copilot integration:
    Add to .vscode/settings.json:

    {
      "mcp": {
        "servers": {
          "dexter-ai": {
            "type": "stdio",
            "command": "python3",
            "args": ["/path/to/dexter_ai_mcp.py"]
          }
        }
      }
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Ensure the repo root is on sys.path so imports work when this script is run
# directly from the repository checkout (no pip install required).
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

# ---------------------------------------------------------------------------
# Logging — all logs go to stderr so they don't interfere with MCP stdio
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[🛡️  Dexter AI Pentest MCP] %(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
#  Lazy imports from Dexter AI Pentest (only when a tool is actually called)
# ═══════════════════════════════════════════════════════════════════════════

def _get_version() -> str:
    from dexter_ai import __version__
    return __version__


def _validate_scope(target: str) -> bool:
    from dexter_ai.guardrails.scope_validator import validate_scope
    return validate_scope(target)


def _get_scopes() -> list[str]:
    from dexter_ai.guardrails.scope_validator import get_authorized_scopes
    return get_authorized_scopes()


def _run_tool(tool_name: str, command: str, target: str) -> dict:
    """Run one of the 151+ network tools by name."""
    if not _validate_scope(target):
        return {
            "success": False,
            "error": f"Target '{target}' is NOT in the authorized scope. "
                     f"Authorized: {', '.join(_get_scopes())}",
        }
    try:
        from dexter_ai.tools.network_tools import tool_registry
        func = tool_registry.get_tool(tool_name)
        if func is None:
            return {"success": False, "error": f"Unknown tool: {tool_name}"}
        output = func(command, target)
        return {"success": True, "output": output}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ═══════════════════════════════════════════════════════════════════════════
#  Tool registration helpers
# ═══════════════════════════════════════════════════════════════════════════

def register_gateway_tools(mcp):
    """Register compact/gateway tools — the minimal set."""

    @mcp.tool()
    def scope_check(target: str) -> str:
        """Check if a target is in the authorized pentesting scope.

        Args:
            target: Target host, IP, or domain to validate
        """
        allowed = _validate_scope(target)
        return json.dumps({
            "target": target,
            "authorized": allowed,
            "authorized_scopes": _get_scopes(),
        }, indent=2)

    @mcp.tool()
    def run_security_tool(tool_name: str, target: str, command: str = "") -> str:
        """Execute any of the 151+ Dexter AI Pentest security tools by name.

        Use 'list_tools' first to discover available tools.
        Scope validation is enforced automatically.

        Args:
            tool_name: Name of the tool (e.g. nmap_scan, nikto_scan, nuclei_scan)
            target: Target host/IP/domain
            command: Optional full command string (if empty, uses smart defaults)
        """
        logger.info(f"🔍 Executing {tool_name} against {target}")
        result = _run_tool(tool_name, command, target)
        if result.get("success"):
            logger.info(f"✅ {tool_name} completed for {target}")
        else:
            logger.error(f"❌ {tool_name} failed: {result.get('error')}")
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    def system_status() -> str:
        """Show Dexter AI Pentest system status: version, tool count, scopes, notes."""
        from dexter_ai.tools.network_tools import tool_registry
        from dexter_ai.notes import NotesManager
        from dexter_ai.cli import list_playbooks

        tools = tool_registry.list_tools()
        notes = NotesManager()
        return json.dumps({
            "name": "Dexter AI Pentest",
            "version": _get_version(),
            "tools_count": len(tools),
            "playbooks": list_playbooks(),
            "notes_count": len(notes.get_notes()),
            "authorized_scopes": _get_scopes(),
        }, indent=2)


def register_scanning_tools(mcp):
    """Register network scanning tools (nmap, nikto, nuclei, etc.)."""

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "",
                  additional_args: str = "") -> str:
        """Execute an Nmap port/service scan against a target.

        Args:
            target: IP address or hostname to scan
            scan_type: Scan type flags (e.g. '-sV' for version, '-sC' for scripts)
            ports: Comma-separated ports or ranges (e.g. '22,80,443' or '1-1000')
            additional_args: Extra nmap arguments
        """
        parts = ["nmap", scan_type]
        if ports:
            parts += ["-p", ports]
        if additional_args:
            parts.append(additional_args)
        parts.append(target)
        cmd = " ".join(parts)
        logger.info(f"🔍 Nmap scan: {target}")
        r = _run_tool("nmap_scan", cmd, target)
        if r.get("success"):
            logger.info(f"✅ Nmap completed for {target}")
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def nikto_scan(target: str, options: str = "") -> str:
        """Run Nikto web vulnerability scanner against a target.

        Args:
            target: Target host or domain
            options: Additional nikto flags
        """
        cmd = f"nikto {options} -h http://{target}".strip() if options else ""
        logger.info(f"🔍 Nikto scan: {target}")
        r = _run_tool("nikto_scan", cmd, target)
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def nuclei_scan(target: str, severity: str = "critical,high,medium",
                    options: str = "") -> str:
        """Run Nuclei vulnerability scanner with 4000+ templates.

        Args:
            target: Target host or URL
            severity: Comma-separated severity levels (critical,high,medium,low)
            options: Additional nuclei flags
        """
        cmd = f"nuclei -u http://{target} -severity {severity} {options}".strip()
        logger.info(f"🔍 Nuclei scan: {target}")
        r = _run_tool("nuclei_scan", cmd, target)
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def sqlmap_scan(target: str, options: str = "") -> str:
        """Run SQLMap for SQL injection testing. Only for authorized targets!

        Args:
            target: Target URL with potential injection point
            options: Extra sqlmap flags (e.g. '--batch --level=3')
        """
        cmd = f"sqlmap {options}".strip() if options else ""
        logger.info(f"🔍 SQLMap scan: {target}")
        r = _run_tool("sqlmap_scan", cmd, target)
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def gobuster_scan(target: str, mode: str = "dir", options: str = "") -> str:
        """Run Gobuster for directory/file/DNS enumeration.

        Args:
            target: Target host or domain
            mode: Gobuster mode (dir, dns, vhost, fuzz)
            options: Extra gobuster flags
        """
        cmd = f"gobuster {mode} {options}".strip() if options else ""
        logger.info(f"🔍 Gobuster scan: {target}")
        r = _run_tool("gobuster_scan", cmd, target)
        return json.dumps(r, indent=2, default=str)


def register_recon_tools(mcp):
    """Register reconnaissance and OSINT tools."""

    @mcp.tool()
    def whois_lookup(target: str) -> str:
        """Perform WHOIS lookup on a domain to get registration info.

        Args:
            target: Domain name to look up
        """
        logger.info(f"🔍 WHOIS: {target}")
        r = _run_tool("whois_lookup", "", target)
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def dig_lookup(target: str, record_type: str = "ANY") -> str:
        """Perform DNS record lookup using dig.

        Args:
            target: Domain to query
            record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, ANY)
        """
        cmd = f"dig {target} {record_type}"
        logger.info(f"🔍 DNS lookup: {target} ({record_type})")
        r = _run_tool("dig_lookup", cmd, target)
        return json.dumps(r, indent=2, default=str)

    @mcp.tool()
    def curl_scan(target: str, options: str = "-I") -> str:
        """Fetch HTTP headers or page content with curl.

        Args:
            target: Target URL or host
            options: Curl flags (default: -I for headers only)
        """
        cmd = f"curl {options} http://{target}"
        logger.info(f"🔍 Curl: {target}")
        r = _run_tool("curl_scan", cmd, target)
        return json.dumps(r, indent=2, default=str)


def register_web_analysis_tools(mcp):
    """Register browser-based web analysis tools (no Selenium required)."""

    @mcp.tool()
    def analyze_security_headers(url: str) -> str:
        """Analyze HTTP security headers and provide a security grade.

        Args:
            url: Full URL to analyze (e.g. http://example.com)
        """
        from dexter_ai.browser_agent import BrowserAgent
        agent = BrowserAgent()
        try:
            result = agent.analyze_security_headers(url)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @mcp.tool()
    def detect_technologies(url: str) -> str:
        """Detect web technologies, frameworks, and server software.

        Args:
            url: Full URL to fingerprint
        """
        from dexter_ai.browser_agent import BrowserAgent
        agent = BrowserAgent()
        try:
            result = agent.detect_technologies(url)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @mcp.tool()
    def find_forms(url: str) -> str:
        """Discover HTML forms and input fields — useful for injection point discovery.

        Args:
            url: Full URL to crawl for forms
        """
        from dexter_ai.browser_agent import BrowserAgent
        agent = BrowserAgent()
        try:
            result = agent.find_forms(url)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @mcp.tool()
    def check_cors(url: str) -> str:
        """Test CORS configuration of a URL for misconfigurations.

        Args:
            url: Full URL to test
        """
        from dexter_ai.browser_agent import BrowserAgent
        agent = BrowserAgent()
        try:
            result = agent.check_cors(url)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})


def register_intel_tools(mcp):
    """Register CVE intelligence and knowledge tools."""

    @mcp.tool()
    def cve_lookup(cve_id: str) -> str:
        """Look up a CVE by its ID for vulnerability intelligence.

        Args:
            cve_id: CVE identifier (e.g. CVE-2024-1234)
        """
        from dexter_ai.cve_intel import CVEIntelligence
        intel = CVEIntelligence()
        result = intel.lookup(cve_id)
        if result is None:
            return json.dumps({"error": f"CVE {cve_id} not found in local database"})
        return json.dumps(result, indent=2)

    @mcp.tool()
    def cve_search(query: str) -> str:
        """Search the CVE intelligence database by keyword.

        Args:
            query: Search keyword (e.g. 'apache', 'rce', 'log4j')
        """
        from dexter_ai.cve_intel import CVEIntelligence
        intel = CVEIntelligence()
        results = intel.search(query)
        if not results:
            return json.dumps({"results": [], "message": f"No CVEs matching '{query}'"})
        return json.dumps(results, indent=2)


def register_notes_tools(mcp):
    """Register notes/loot management tools."""

    @mcp.tool()
    def add_note(content: str, category: str = "finding", target: str = "") -> str:
        """Save a finding, vulnerability, or note to the loot directory.

        Args:
            content: Note content to save
            category: One of: finding, vulnerability, credential, artifact
            target: Related target host (optional)
        """
        from dexter_ai.notes import NotesManager
        notes = NotesManager()
        note = notes.add_note(content=content, category=category,
                              target=target, source="mcp")
        return json.dumps(note, indent=2)

    @mcp.tool()
    def get_notes(category: str = "", target: str = "") -> str:
        """Retrieve saved notes/findings from the loot directory.

        Args:
            category: Filter by category (finding, vulnerability, credential, artifact)
            target: Filter by target host
        """
        from dexter_ai.notes import NotesManager
        notes = NotesManager()
        result = notes.get_notes(
            category=category or None,
            target=target or None,
        )
        if not result:
            return json.dumps({"notes": [], "message": "No notes found"})
        return json.dumps(result, indent=2)


def register_discovery_tools(mcp):
    """Register tool/playbook discovery tools."""

    @mcp.tool()
    def list_tools() -> str:
        """List all 151+ security tools available in Dexter AI Pentest, grouped by category."""
        from dexter_ai.tools.network_tools import tool_registry
        tools = tool_registry.list_tools()
        categories: dict[str, list] = {}
        for t in tools:
            categories.setdefault(t["category"], []).append(t)
        lines = [f"Dexter AI Pentest — {len(tools)} tools across {len(categories)} categories\n"]
        for cat in sorted(categories):
            lines.append(f"\n[{cat.upper()}]")
            for t in categories[cat]:
                lines.append(f"  {t['name']:<24s} {t['description']}")
        return "\n".join(lines)

    @mcp.tool()
    def list_playbooks() -> str:
        """List available attack playbooks (pre-built security workflows)."""
        from dexter_ai.cli import list_playbooks as _list_pb, load_playbook
        names = _list_pb()
        if not names:
            return "No playbooks found."
        lines = ["Available playbooks:\n"]
        for n in names:
            pb = load_playbook(n)
            desc = pb.get("description", "").split("\n")[0].strip() if pb else ""
            cat = pb.get("category", "general") if pb else "general"
            lines.append(f"  {n:<20s}  [{cat}]  {desc}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  MCP Server Setup (FastMCP — same pattern as HexStrike AI)
# ═══════════════════════════════════════════════════════════════════════════

def setup_mcp_server(compact: bool = False):
    """Create and configure the FastMCP server instance.

    Args:
        compact: If True, register only the 3 gateway tools
                 (scope_check, run_security_tool, system_status).
                 Ideal for small LLMs or lightweight setups.
    """
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("dexter-ai-pentest")

    # Always register gateway tools
    register_gateway_tools(mcp)

    if compact:
        logger.info("⚡ Compact mode: only gateway tools registered "
                     "(scope_check, run_security_tool, system_status)")
        return mcp

    # Full mode — register all tool categories
    register_scanning_tools(mcp)
    register_recon_tools(mcp)
    register_web_analysis_tools(mcp)
    register_intel_tools(mcp)
    register_notes_tools(mcp)
    register_discovery_tools(mcp)

    logger.info("🔧 Full mode: all tool categories registered")
    return mcp


# ═══════════════════════════════════════════════════════════════════════════
#  CLI argument parsing (mirrors HexStrike pattern)
# ═══════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Dexter AI Pentest — MCP Server for AI Client Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--server", type=str, default=None,
        help="Optional upstream Dexter AI Pentest API server URL "
             "(e.g. http://localhost:8000)",
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Tool execution timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--compact", action="store_true",
        help="Compact mode: register only gateway tools "
             "(scope_check, run_security_tool, system_status)",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help="Print available MCP tools and exit",
    )
    return parser.parse_args()


# ═══════════════════════════════════════════════════════════════════════════
#  Main entry point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    args = parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    # Store server URL for tools that need it
    if args.server:
        os.environ["DEXTER_AI_SERVER"] = args.server
        logger.info(f"🔗 Upstream server: {args.server}")

    if args.timeout != 300:
        os.environ["DEXTER_AI_TIMEOUT"] = str(args.timeout)

    logger.info(f"🚀 Starting Dexter AI Pentest MCP Server v{_get_version()}")

    if args.list_tools:
        mcp = setup_mcp_server(compact=args.compact)
        # FastMCP doesn't have a direct list method; just print the registered info
        mode = "compact" if args.compact else "full"
        print(f"Dexter AI Pentest MCP Server — {mode} mode")
        print(f"Version: {_get_version()}\n")
        print("Registered MCP tools:")
        # Print the tool names from the categories we registered
        if args.compact:
            for name in ["scope_check", "run_security_tool", "system_status"]:
                print(f"  {name}")
        else:
            for name in [
                "scope_check", "run_security_tool", "system_status",
                "nmap_scan", "nikto_scan", "nuclei_scan", "sqlmap_scan",
                "gobuster_scan", "whois_lookup", "dig_lookup", "curl_scan",
                "analyze_security_headers", "detect_technologies",
                "find_forms", "check_cors",
                "cve_lookup", "cve_search",
                "add_note", "get_notes",
                "list_tools", "list_playbooks",
            ]:
                print(f"  {name}")
        return

    # Set up and run MCP server (FastMCP handles stdio transport)
    mcp = setup_mcp_server(compact=args.compact)

    logger.info("🤖 Ready to serve AI agents with cybersecurity capabilities")
    logger.info("📡 Listening on stdio (JSON-RPC)")

    mcp.run()


if __name__ == "__main__":
    main()
