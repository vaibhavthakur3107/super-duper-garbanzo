"""
Dexter AI Pentest – CLI Entry Point
Mirrors the 'pentestagent' command-line interface from PentestAgent.

Usage:
    python -m dexter_ai.cli                        # interactive mode
    python -m dexter_ai.cli -t example.com         # set target upfront
    python -m dexter_ai.cli -t example.com --playbook web_pentest
    python -m dexter_ai.cli run -t example.com --playbook recon
    python -m dexter_ai.cli notes                  # show saved notes
    python -m dexter_ai.cli report                 # generate report
    python -m dexter_ai.cli playbooks              # list playbooks
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Allow running as  python -m dexter_ai.cli  from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from dexter_ai import __version__
from dexter_ai.providers import PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER
from dexter_ai.notes import NotesManager
from dexter_ai.autonomous import autonomous_engine, specialist_team
from dexter_ai.reporting import report_generator


# ── ANSI Color Utilities ─────────────────────────────────────────────────────

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"


def colored(text, color):
    return f"{color}{text}{Colors.RESET}"


def success(text):
    return colored(f"[✓] {text}", Colors.GREEN)


def error(text):
    return colored(f"[✗] {text}", Colors.RED)


def warning(text):
    return colored(f"[!] {text}", Colors.YELLOW)


def info(text):
    return colored(f"[*] {text}", Colors.CYAN)


def header(text):
    return colored(f"═══ {text} ═══", Colors.MAGENTA + Colors.BOLD)


# ── Banner & Help ────────────────────────────────────────────────────────────

BANNER = (
    f"\n"
    f"{Colors.CYAN}{Colors.BOLD}"
    f"  ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗ \n"
    f"  ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗\n"
    f"  ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝\n"
    f"  ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗\n"
    f"  ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║\n"
    f"  ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{Colors.RESET}\n"
    f"{Colors.RED}{Colors.BOLD}"
    f"     █████╗ ██╗    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗\n"
    f"    ██╔══██╗██║    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝\n"
    f"    ███████║██║    ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   \n"
    f"    ██╔══██║██║    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   \n"
    f"    ██║  ██║██║    ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   \n"
    f"    ╚═╝  ╚═╝╚═╝    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   {Colors.RESET}\n"
    f"\n"
    f"  {Colors.DIM}{'─' * 56}{Colors.RESET}\n"
    f"  {Colors.GREEN}▸ AI-Powered Red Team Pentesting Agent{Colors.RESET}\n"
    f"  {Colors.YELLOW}▸ v{__version__}{Colors.RESET}  "
    f"{Colors.CYAN}Tools: 151+{Colors.RESET}  "
    f"{Colors.MAGENTA}Agents: 12+{Colors.RESET}  "
    f"{Colors.GREEN}Status: READY{Colors.RESET}\n"
    f"  {Colors.DIM}{'─' * 56}{Colors.RESET}\n"
)

# Agent definitions for /agents command
_AGENTS = [
    ("IntelligentDecisionEngine", "Selects optimal tools & parameters for any task"),
    ("BugBountyWorkflowManager", "Manages end-to-end bug bounty hunting workflows"),
    ("CTFWorkflowManager", "Solves CTF challenges with adaptive strategies"),
    ("CVEIntelligenceManager", "CVE lookup, analysis, and exploit correlation"),
    ("AIExploitGenerator", "Generates and validates exploit payloads"),
    ("VulnerabilityCorrelator", "Correlates findings across tools and scans"),
    ("TechnologyDetector", "Fingerprints tech stacks and frameworks"),
    ("RateLimitDetector", "Detects and adapts to rate limiting defenses"),
    ("FailureRecoverySystem", "Auto-recovers from tool and agent failures"),
    ("PerformanceMonitor", "Tracks agent performance and resource usage"),
    ("ParameterOptimizer", "Tunes tool parameters based on results"),
    ("GracefulDegradation", "Maintains operations when components fail"),
]

HELP_TEXT = (
    f"\n"
    f"  {header('COMMANDS')}\n"
    f"\n"
    f"  {colored('Agent & Execution', Colors.CYAN + Colors.BOLD)}\n"
    f"    {colored('/agent <task>', Colors.GREEN)}        Run autonomous agent on task\n"
    f"    {colored('/auto', Colors.GREEN)}                Run fully autonomous pentest (all phases)\n"
    f"    {colored('/playbook <name>', Colors.GREEN)}     Load and run a playbook\n"
    f"    {colored('/target <host>', Colors.GREEN)}       Set target\n"
    f"\n"
    f"  {colored('Reporting & Intel', Colors.CYAN + Colors.BOLD)}\n"
    f"    {colored('/notes', Colors.GREEN)}               Show saved notes / loot\n"
    f"    {colored('/report', Colors.GREEN)}              Generate detailed Markdown report with exploitation guides\n"
    f"\n"
    f"  {colored('Discovery', Colors.CYAN + Colors.BOLD)}\n"
    f"    {colored('/playbooks', Colors.GREEN)}           List available playbooks\n"
    f"    {colored('/tools', Colors.GREEN)}               List available tools (151+)\n"
    f"    {colored('/agents', Colors.GREEN)}              List AI agents (12+)\n"
    f"    {colored('/specialists', Colors.GREEN)}         Show specialist team status\n"
    f"\n"
    f"  {colored('System', Colors.CYAN + Colors.BOLD)}\n"
    f"    {colored('/status', Colors.GREEN)}              Show system status dashboard\n"
    f"    {colored('/dashboard', Colors.GREEN)}           Detailed status dashboard\n"
    f"    {colored('/mcp list', Colors.GREEN)}            List configured MCP servers\n"
    f"    {colored('/mcp add <n> <cmd>', Colors.GREEN)}   Add MCP server\n"
    f"    {colored('/mcp test <name>', Colors.GREEN)}     Test MCP server availability\n"
    f"    {colored('/clear', Colors.GREEN)}               Clear current session\n"
    f"\n"
    f"  {colored('Navigation', Colors.CYAN + Colors.BOLD)}\n"
    f"    {colored('/help', Colors.GREEN)}                Show this help  (/h, /?)\n"
    f"    {colored('/quit', Colors.GREEN)}                Exit  (/exit, /q)\n"
)


def _status_dashboard(target: str, notes: NotesManager, provider: str, session_count: int = 0) -> str:
    """Render a status dashboard box."""
    note_count = len(notes.get_notes())
    t_display = target if target else "not set"
    status = colored("ACTIVE", Colors.GREEN + Colors.BOLD) if target else colored("READY", Colors.YELLOW)

    # Try to get cache stats
    try:
        from dexter_ai.cache import SmartCache
        cache = SmartCache()
        hits = cache.stats.get("hits", 0)
        misses = cache.stats.get("misses", 0)
    except Exception:
        hits, misses = 0, 0

    w = 56
    border = Colors.CYAN
    lines = [
        f"  {border}╔{'═' * w}╗{Colors.RESET}",
        f"  {border}║{Colors.RESET}  {Colors.BOLD}{Colors.CYAN}DEXTER AI PENTEST v{__version__} — STATUS DASHBOARD{Colors.RESET}{' ' * max(0, w - 39 - len(__version__))}{border}║{Colors.RESET}",
        f"  {border}╠{'═' * w}╣{Colors.RESET}",
        f"  {border}║{Colors.RESET}  🎯 Target: {t_display:<20s}  Status: {status}{' ' * max(0, w - 43 - len(t_display))}{border}║{Colors.RESET}",
        f"  {border}║{Colors.RESET}  🔧 Tools:  151+{' ' * 17}Agents: 12+{' ' * (w - 48)}{border}║{Colors.RESET}",
        f"  {border}║{Colors.RESET}  📋 Notes:  {note_count:<20d} Sessions: {session_count:<9d}{border}║{Colors.RESET}",
        f"  {border}║{Colors.RESET}  💾 Cache:  {hits} hits / {misses} misses{' ' * max(0, w - 37 - len(str(hits)) - len(str(misses)))}Provider: {provider:<8s}{border}║{Colors.RESET}",
        f"  {border}╚{'═' * w}╝{Colors.RESET}",
    ]
    return "\n".join(lines)


def _format_tools_table() -> str:
    """Render tools grouped by category in a table."""
    from dexter_ai.tools.network_tools import tool_registry
    tools = tool_registry.list_tools()
    categories: dict[str, list] = {}
    for t in tools:
        categories.setdefault(t["category"], []).append(t)

    lines = []
    for cat in sorted(categories):
        cat_tools = categories[cat]
        lines.append(f"\n  {colored(f'┌── {cat.upper()} ({len(cat_tools)} tools)', Colors.MAGENTA + Colors.BOLD)}")
        lines.append(f"  {Colors.DIM}│{'─' * 54}{Colors.RESET}")
        for t in cat_tools:
            name_col = colored(f"{t['name']:<22s}", Colors.GREEN)
            lines.append(f"  {Colors.DIM}│{Colors.RESET} {name_col} {Colors.DIM}{t['description'][:45]}{Colors.RESET}")
        lines.append(f"  {Colors.DIM}└{'─' * 54}{Colors.RESET}")

    total = len(tools)
    lines.insert(0, f"\n  {colored(f'TOOL ARSENAL — {total} tools across {len(categories)} categories', Colors.CYAN + Colors.BOLD)}")
    return "\n".join(lines)


def _format_playbooks() -> str:
    """Render playbooks in a formatted display."""
    names = list_playbooks()
    if not names:
        return info("No playbooks found.")
    lines = [f"\n  {colored('PLAYBOOKS', Colors.CYAN + Colors.BOLD)}", ""]
    for n in names:
        pb = load_playbook(n)
        desc = pb.get("description", "").split("\n")[0].strip() if pb else ""
        cat = pb.get("category", "general") if pb else "general"
        lines.append(
            f"  {colored('▸', Colors.GREEN)} {colored(f'{n:<20s}', Colors.YELLOW)}"
            f" {Colors.DIM}[{cat}]{Colors.RESET}  {desc}"
        )
    return "\n".join(lines)


def _format_agents() -> str:
    """Render the agent list."""
    lines = [f"\n  {colored(f'AI AGENTS — {len(_AGENTS)} specialized agents', Colors.CYAN + Colors.BOLD)}", ""]
    for i, (name, desc) in enumerate(_AGENTS, 1):
        lines.append(
            f"  {colored(f'{i:>2}.', Colors.MAGENTA)} {colored(name, Colors.GREEN + Colors.BOLD)}\n"
            f"      {Colors.DIM}{desc}{Colors.RESET}"
        )
    return "\n".join(lines)


def _format_specialists() -> str:
    """Render the specialist team status table."""
    status = specialist_team.get_team_status()
    specialists = status["specialists"]
    lines = [
        f"\n  {colored(f'SPECIALIST TEAM — {status[\"team_size\"]} specialists', Colors.CYAN + Colors.BOLD)}",
        "",
    ]
    status_colors = {
        "idle": Colors.DIM,
        "assigned": Colors.YELLOW,
        "active": Colors.GREEN,
    }
    for s in specialists:
        sc = status_colors.get(s["status"], Colors.WHITE)
        caps = ", ".join(s["capabilities"])
        lines.append(
            f"  {colored(s['name'], Colors.GREEN + Colors.BOLD)}"
            f"  {colored(f'[{s[\"status\"].upper()}]', sc)}\n"
            f"      {Colors.DIM}Role: {s['role']}  |  Capabilities: {caps}{Colors.RESET}"
        )
    return "\n".join(lines)


def _format_notes(notes_list: list[dict]) -> str:
    """Render notes with category-based coloring."""
    if not notes_list:
        return info("No notes saved yet.")
    cat_colors = {
        "vulnerability": Colors.RED,
        "credential": Colors.YELLOW,
        "finding": Colors.GREEN,
        "artifact": Colors.BLUE,
    }
    lines = []
    for n in notes_list:
        cat = n.get("category", "finding")
        c = cat_colors.get(cat, Colors.WHITE)
        lines.append(f"  {colored(f'[{cat.upper()}]', c + Colors.BOLD)} {n['content'][:120]}")
    return "\n".join(lines)


def list_playbooks() -> list[str]:
    """Return names of available playbooks."""
    playbook_dir = Path(__file__).parent / "playbooks"
    return sorted(p.stem for p in playbook_dir.glob("*.yaml"))


def load_playbook(name: str) -> dict | None:
    """Load a playbook by name. Returns parsed YAML dict or None."""
    try:
        import yaml  # optional dep
    except ImportError:
        # Fallback: read and parse minimal YAML manually
        return _parse_playbook_minimal(name)

    playbook_dir = Path(__file__).parent / "playbooks"
    path = playbook_dir / f"{name}.yaml"
    if not path.exists():
        return None
    with open(path) as f:
        return yaml.safe_load(f)


def _parse_playbook_minimal(name: str) -> dict | None:
    """Minimal YAML parser for playbook name/description without PyYAML."""
    playbook_dir = Path(__file__).parent / "playbooks"
    path = playbook_dir / f"{name}.yaml"
    if not path.exists():
        return None
    result: dict = {}
    with open(path) as f:
        for line in f:
            if line.startswith("name:"):
                result["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("description:"):
                result["description"] = line.split(":", 1)[1].strip()
            elif line.startswith("category:"):
                result["category"] = line.split(":", 1)[1].strip()
    return result


def _handle_mcp_command(prompt: str):
    """Handle /mcp <subcommand> in the interactive REPL."""
    from dexter_ai.mcp import MCPClient  # noqa: C0415
    client = MCPClient()
    parts = prompt.split()
    sub = parts[1] if len(parts) > 1 else "list"

    if sub == "list":
        servers = client.list_servers()
        if not servers:
            print("[*] No MCP servers configured. Copy mcp_servers.json.example → mcp_servers.json")
            return
        for s in servers:
            status = "✓" if s["available"] else "✗"
            print(f"  {status} {s['name']:<16s}  {s['command']}  {s.get('description','')}")

    elif sub == "add" and len(parts) >= 4:
        name, command = parts[2], parts[3]
        args = parts[4:] if len(parts) > 4 else []
        cfg = client.add_server(name, command, args=args)
        print(f"[+] MCP server '{cfg.name}' added → mcp_servers.json")

    elif sub == "test" and len(parts) >= 3:
        name = parts[2]
        ok, msg = client.test_server(name)
        print(f"[{'+' if ok else '!'}] {msg}")

    elif sub == "remove" and len(parts) >= 3:
        name = parts[2]
        removed = client.remove_server(name)
        print(f"[{'+' if removed else '!'}] {'Removed' if removed else 'Not found'}: {name}")

    else:
        print("Usage: /mcp list | /mcp add <name> <command> [args...] | /mcp test <name> | /mcp remove <name>")


async def run_agent(target: str, task: str, model: str, provider: str, notes: NotesManager) -> dict:
    """Run the LangGraph pentesting agent and save findings."""
    # Lazy import – avoids pulling in langgraph at CLI startup
    from dexter_ai.main import run_pentest  # noqa: C0415
    t0 = time.time()
    print(f"\n{info(f'Starting agent on target: {target}')}")
    print(f"{info(f'Task: {task}')}")
    print(f"{info(f'Provider: {provider} / Model: {model}')}\n")

    result = await run_pentest(target, task, model, provider)

    # Save findings to notes
    for thought in result.get("thought_trace", []):
        if thought.get("node") == "tool" and thought.get("observation"):
            notes.add_note(
                category="finding",
                content=thought["observation"],
                target=target,
                source=thought.get("action", "unknown"),
            )

    # Print thought trace summary
    thoughts = result.get("thought_trace", [])
    elapsed = time.time() - t0
    print(f"\n{success(f'Assessment complete. {len(thoughts)} reasoning steps recorded in {elapsed:.1f}s.')}")
    if result.get("error"):
        print(error(f"Error: {result['error']}"))

    return result


def interactive_mode(args: argparse.Namespace):
    """REPL-style interactive session (like PentestAgent TUI)."""
    print(BANNER)
    print(f"  {Colors.DIM}Type /help for commands, /quit to exit.{Colors.RESET}\n")

    target = args.target or ""
    model = args.model
    provider = args.provider or os.environ.get("LLM_PROVIDER", PROVIDER_OLLAMA)
    notes = NotesManager()
    session_results: list[dict] = []

    if target:
        print(success(f"Target set: {target}"))

    while True:
        try:
            if target:
                prompt_str = f"{Colors.RED}⚡{Colors.RESET}{Colors.CYAN}{Colors.BOLD}dexter-ai{Colors.RESET}{Colors.DIM}[{Colors.RESET}{Colors.YELLOW}{target}{Colors.RESET}{Colors.DIM}]{Colors.RESET}{Colors.CYAN}>{Colors.RESET} "
            else:
                prompt_str = f"{Colors.RED}⚡{Colors.RESET}{Colors.CYAN}{Colors.BOLD}dexter-ai{Colors.RESET}{Colors.CYAN}>{Colors.RESET} "
            prompt = input(prompt_str).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{info('Exiting. Goodbye!')}")
            break

        if not prompt:
            continue

        # ── Built-in commands ────────────────────────────────────────────────
        if prompt in ("/quit", "/exit", "/q"):
            print(success("Goodbye!"))
            break

        if prompt in ("/help", "/h", "/?"):
            print(HELP_TEXT)
            continue

        if prompt.startswith("/target "):
            target = prompt[8:].strip()
            print(success(f"Target set: {target}"))
            continue

        if prompt == "/notes":
            all_notes = notes.get_notes()
            print(_format_notes(all_notes))
            continue

        if prompt == "/report":
            if not session_results and not notes.get_notes():
                print(warning("No session results to report yet."))
                continue
            report_content = report_generator.generate_full_report(session_results, target, notes)
            report_path = report_generator.loot_dir / f"full_report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            print(success(f"Detailed report saved to: {report_path}"))
            continue

        if prompt == "/playbooks":
            print(_format_playbooks())
            continue

        if prompt == "/tools":
            print(_format_tools_table())
            continue

        if prompt == "/agents":
            print(_format_agents())
            continue

        if prompt in ("/status", "/dashboard"):
            print(f"\n{_status_dashboard(target, notes, provider, session_count=len(session_results))}")
            continue

        if prompt == "/clear":
            session_results.clear()
            notes.clear_session()
            print(info("Session cleared."))
            continue

        # ── MCP commands ─────────────────────────────────────────────────────
        if prompt.startswith("/mcp"):
            _handle_mcp_command(prompt)
            continue

        if prompt.startswith("/playbook "):
            pb_name = prompt[10:].strip()
            pb = load_playbook(pb_name)
            if not pb:
                print(error(f"Playbook '{pb_name}' not found. Use /playbooks to list available."))
                continue
            task = pb.get("description", f"Run {pb_name} playbook").strip()
            if not target:
                target = input("Enter target: ").strip()
            result = asyncio.run(run_agent(target, task, model, provider, notes))
            session_results.append(result)
            continue

        if prompt.startswith("/agent "):
            task = prompt[7:].strip()
            if not target:
                target = input("Enter target: ").strip()
            result = asyncio.run(run_agent(target, task, model, provider, notes))
            session_results.append(result)
            continue

        # Default: treat as a task for the agent
        if target:
            result = asyncio.run(run_agent(target, prompt, model, provider, notes))
            session_results.append(result)
        else:
            print(warning("No target set. Use /target <host> first, or /agent <task>."))


def run_mode(args: argparse.Namespace):
    """Non-interactive one-shot run mode."""
    target = args.target
    if not target:
        print("[!] --target is required for run mode.")
        sys.exit(1)

    provider = args.provider or os.environ.get("LLM_PROVIDER", PROVIDER_OLLAMA)
    notes = NotesManager()

    if args.playbook:
        pb = load_playbook(args.playbook)
        if not pb:
            print(f"[!] Playbook '{args.playbook}' not found.")
            sys.exit(1)
        task = pb.get("description", f"Run {args.playbook}").strip()
        print(BANNER)
    else:
        task = args.task or "Perform comprehensive penetration testing"

    result = asyncio.run(run_agent(target, task, args.model, provider, notes))

    if args.report:
        path = notes.generate_report([result], target)
        print(f"[+] Report saved to: {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="dexter-ai",
        description="Dexter AI Pentest – Red Team Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target", help="Target host / IP / domain")
    parser.add_argument("--model", default="llama3", help="LLM model name (default: llama3)")
    parser.add_argument(
        "--provider",
        choices=[PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER],
        default=None,
        help="LLM provider (default: auto-detect from env)",
    )

    sub = parser.add_subparsers(dest="command")

    # ── run subcommand ────────────────────────────────────────────────────────
    run_parser = sub.add_parser("run", help="Non-interactive one-shot assessment")
    run_parser.add_argument("-t", "--target", required=True, help="Target host")
    run_parser.add_argument("--task", help="Custom task description")
    run_parser.add_argument("--playbook", choices=list_playbooks(), help="Playbook to run")
    run_parser.add_argument("--model", default="llama3", help="LLM model")
    run_parser.add_argument(
        "--provider",
        choices=[PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER],
        default=None,
    )
    run_parser.add_argument("--report", action="store_true", help="Save Markdown report after run")

    # ── notes subcommand ─────────────────────────────────────────────────────
    sub.add_parser("notes", help="Show all saved notes / loot")

    # ── playbooks subcommand ─────────────────────────────────────────────────
    sub.add_parser("playbooks", help="List available playbooks")

    # ── mcp subcommand ───────────────────────────────────────────────────────
    mcp_parser = sub.add_parser("mcp", help="Manage MCP servers")
    mcp_parser.add_argument("mcp_action", choices=["list", "add", "test", "remove"],
                            help="MCP action")
    mcp_parser.add_argument("mcp_args", nargs="*", help="Action arguments")

    args = parser.parse_args()

    if args.command == "run":
        run_mode(args)
    elif args.command == "notes":
        notes = NotesManager()
        for n in notes.get_notes():
            print(f"[{n['category']}] {n.get('target','')} – {n['content'][:200]}")
    elif args.command == "playbooks":
        for name in list_playbooks():
            pb = load_playbook(name)
            desc = pb.get("description", "").split("\n")[0].strip() if pb else ""
            print(f"  {name:<20s}  {desc}")
    elif args.command == "mcp":
        _handle_mcp_command(f"/mcp {args.mcp_action} {' '.join(args.mcp_args)}")
    else:
        interactive_mode(args)


if __name__ == "__main__":
    main()
