"""
Cyber-Sentry AI – CLI Entry Point
Mirrors the 'pentestagent' command-line interface from PentestAgent.

Usage:
    python -m cyber_sentry.cli                        # interactive mode
    python -m cyber_sentry.cli -t example.com         # set target upfront
    python -m cyber_sentry.cli -t example.com --playbook web_pentest
    python -m cyber_sentry.cli run -t example.com --playbook recon
    python -m cyber_sentry.cli notes                  # show saved notes
    python -m cyber_sentry.cli report                 # generate report
    python -m cyber_sentry.cli playbooks              # list playbooks
"""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Allow running as  python -m cyber_sentry.cli  from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from cyber_sentry.providers import PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER
from cyber_sentry.notes import NotesManager

BANNER = r"""
   _____      _               ____             _              
  / ____|    | |             / ___|  ___  _ __ | |_ _ __ _   _ 
 | |    _   _| |__   ___ _ _\___ \ / _ \| '_ \| __| '__| | | |
 | |___| |_| | '_ \ / _ \ '__|__) |  __/| | | | |_| |  | |_| |
  \_____\__, |_.__/ \___/_| |____/ \___||_| |_|\__|_|   \__, |
         __/ |                                            __/ |
        |___/   AI-Powered Red Team Pentesting Agent     |___/ 
"""

HELP_TEXT = """
Commands:
  /agent <task>        Run autonomous agent on task
  /target <host>       Set target
  /playbook <name>     Load and run a playbook
  /notes               Show saved notes / loot
  /report              Generate Markdown report for current session
  /playbooks           List available playbooks
  /tools               List available tools
  /mcp list            List configured MCP servers
  /mcp add <n> <cmd>   Add MCP server (name + command)
  /mcp test <name>     Test MCP server availability
  /clear               Clear current session
  /quit                Exit  (also /exit, /q)
  /help                Show this help  (also /h, /?)
"""


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
    from cyber_sentry.mcp import MCPClient  # noqa: C0415
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
    from cyber_sentry.main import run_pentest  # noqa: C0415
    print(f"\n[*] Starting agent on target: {target}")
    print(f"[*] Task: {task}")
    print(f"[*] Provider: {provider} / Model: {model}\n")

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
    print(f"\n[+] Assessment complete. {len(thoughts)} reasoning steps recorded.")
    if result.get("error"):
        print(f"[!] Error: {result['error']}")

    return result


def interactive_mode(args: argparse.Namespace):
    """REPL-style interactive session (like PentestAgent TUI)."""
    print(BANNER)
    print("Type /help for commands, /quit to exit.\n")

    target = args.target or ""
    model = args.model
    provider = args.provider or os.environ.get("LLM_PROVIDER", PROVIDER_OLLAMA)
    notes = NotesManager()
    session_results: list[dict] = []

    if target:
        print(f"[*] Target set: {target}")

    while True:
        try:
            prompt = input("cyber-sentry> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting. Goodbye!")
            break

        if not prompt:
            continue

        # ── Built-in commands ────────────────────────────────────────────────
        if prompt in ("/quit", "/exit", "/q"):
            print("Goodbye!")
            break

        if prompt in ("/help", "/h", "/?"):
            print(HELP_TEXT)
            continue

        if prompt.startswith("/target "):
            target = prompt[8:].strip()
            print(f"[*] Target set: {target}")
            continue

        if prompt == "/notes":
            all_notes = notes.get_notes()
            if not all_notes:
                print("[*] No notes saved yet.")
            else:
                for n in all_notes:
                    print(f"  [{n['category']}] {n['content'][:120]}")
            continue

        if prompt == "/report":
            if not session_results:
                print("[!] No session results to report yet.")
                continue
            path = notes.generate_report(session_results, target)
            print(f"[+] Report saved to: {path}")
            continue

        if prompt == "/playbooks":
            names = list_playbooks()
            if not names:
                print("[*] No playbooks found.")
            else:
                print("Available playbooks:")
                for n in names:
                    pb = load_playbook(n)
                    desc = pb.get("description", "").split("\n")[0].strip() if pb else ""
                    print(f"  {n:<20s}  {desc}")
            continue

        if prompt == "/tools":
            from cyber_sentry.tools.network_tools import tool_registry
            for t in tool_registry.list_tools():
                print(f"  {t['name']:<20s}  [{t['category']}]  {t['description']}")
            continue

        if prompt == "/clear":
            session_results.clear()
            notes.clear_session()
            print("[*] Session cleared.")
            continue

        # ── MCP commands ─────────────────────────────────────────────────────
        if prompt.startswith("/mcp"):
            _handle_mcp_command(prompt)
            continue

        if prompt.startswith("/playbook "):
            pb_name = prompt[10:].strip()
            pb = load_playbook(pb_name)
            if not pb:
                print(f"[!] Playbook '{pb_name}' not found. Use /playbooks to list available.")
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
            print("[!] No target set. Use /target <host> first, or /agent <task>.")


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
        prog="cyber-sentry",
        description="Cyber-Sentry AI – Red Team Pentesting Agent",
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
