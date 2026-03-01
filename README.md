# 🛡️ Dexter AI Pentest

> AI-powered autonomous Red Team Pentesting Agent — similar to [PentestGPT](https://github.com/GreyDGL/PentestGPT), [Pentagi](https://github.com/vxcontrol/pentagi), [PentestAgent](https://github.com/GH05TCREW/pentestagent), and [Shannon](https://github.com/KeygraphHQ/shannon).

[![Python](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)](Dockerfile)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agent_Graph-blue)](dexter_ai/main.py)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)](tests/)

📖 **[→ Complete Beginner's Setup & Usage Guide (GUIDE.md)](GUIDE.md)**
🔍 **[→ Feature Comparison vs HexStrike AI / PentAGI (COMPARISON.md)](COMPARISON.md)**
📋 **[→ Complete Capabilities Reference (CAPABILITIES.md)](CAPABILITIES.md)**

---

## 📖 Overview

Dexter AI Pentest is a production-ready **multi-agent pentesting system** built with:

- **LangGraph** for agent orchestration (Supervisor → Guardrail → Planner → Tool → Reflection loop)
- **Ollama / OpenAI / Anthropic / OpenRouter** for LLM inference
- **Streamlit** web UI with live Thought-Trace visualisation
- **FastAPI** REST + WebSocket backend
- **Interactive CLI** (REPL with `/agent`, `/playbook`, `/notes`, `/report` commands)
- **Attack Playbooks** (web pentest, network audit, recon, CTF)
- **Notes / Loot** persistence across sessions
- **MCP (Model Context Protocol)** integration for external tool servers
- **Docker** for isolated, reproducible execution

For detailed documentation see [`dexter_ai/README.md`](dexter_ai/README.md).

---

## 🚀 Quickstart

```bash
# 1. Clone
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo

# 2. Configure
cp .env.example .env
# edit .env with your API key(s)

# 3a. Docker (recommended – includes nmap, nikto, dig, etc.)
docker compose up          # Streamlit UI → http://localhost:8501

# 3b. Local Python
make setup                 # installs deps + creates .env
make run                   # Streamlit UI → http://localhost:8501
make run-cli               # interactive CLI
```

---

## 🖥️ CLI

```bash
python -m dexter_ai.cli                          # interactive REPL
python -m dexter_ai.cli -t 192.168.1.1           # pre-set target
python -m dexter_ai.cli run -t example.com \
    --playbook web_pentest --report                  # one-shot + report

# MCP server management
python -m dexter_ai.cli mcp list
python -m dexter_ai.cli mcp add nmap npx gc-nmap-mcp
```

---

## 📋 Playbooks

| Name | Category | Description |
|---|---|---|
| `web_pentest` | Web | Full black-box web app penetration test |
| `network_audit` | Network | Infrastructure audit with SSL/TLS review |
| `recon` | Recon | Passive OSINT + active enum, no exploitation |
| `ctf` | CTF | Capture The Flag challenge solver |

---

## 🔌 LLM Providers

| Provider | Env Var | Default Model |
|---|---|---|
| **Ollama** (default, local) | `OLLAMA_BASE_URL` | `llama3` |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o-mini` |
| **Anthropic** | `ANTHROPIC_API_KEY` | `claude-3-haiku-20240307` |
| **OpenRouter** | `OPENROUTER_API_KEY` | `openai/gpt-4o-mini` |

---

## 🧩 MCP Support — AI Client Integration

Dexter AI Pentest includes a **FastMCP-based MCP server** (inspired by [HexStrike AI](https://github.com/0x4m4/hexstrike-ai)) that lets you use all 151+ security tools directly from **Claude Desktop**, **Cursor**, or **VS Code Copilot** — no Docker required.

### Quick Setup (No Docker)

```bash
# 1. Clone the repository
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo

# 2. Create virtual environment
python3 -m venv dexter-ai-env
source dexter-ai-env/bin/activate   # Linux/Mac
# dexter-ai-env\Scripts\activate    # Windows

# 3. Install dependencies
pip3 install -e "."
pip3 install "mcp[cli]>=1.0.0"

# 4. Start the MCP server (to test it works)
python3 dexter_ai_mcp.py --list-tools

# 5. Or start it in compact mode (3 gateway tools only — ideal for small LLMs)
python3 dexter_ai_mcp.py --compact --list-tools
```

### Claude Desktop Integration

Edit `~/.config/Claude/claude_desktop_config.json` (Linux/Mac) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "dexter-ai": {
      "command": "python3",
      "args": [
        "/path/to/super-duper-garbanzo/dexter_ai_mcp.py"
      ],
      "description": "Dexter AI Pentest v2.0 – AI Red Team Pentesting Agent",
      "timeout": 300,
      "disabled": false
    }
  }
}
```

> **Tip:** Use the full path to your venv Python if you installed in a venv:
> `"command": "/path/to/super-duper-garbanzo/dexter-ai-env/bin/python3"`

### Cursor Integration

Same JSON config as Claude Desktop — add it to Cursor's MCP settings.

### VS Code Copilot Integration

Add to `.vscode/settings.json`:

```json
{
  "mcp": {
    "servers": {
      "dexter-ai": {
        "type": "stdio",
        "command": "python3",
        "args": [
          "/path/to/super-duper-garbanzo/dexter_ai_mcp.py"
        ]
      }
    }
  }
}
```

### OpenCode Integration

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "dexter-ai": {
      "type": "local",
      "timeout": 300,
      "command": [
        "/path/to/super-duper-garbanzo/dexter-ai-env/bin/python3",
        "/path/to/super-duper-garbanzo/dexter_ai_mcp.py"
      ],
      "enabled": true
    }
  }
}
```

### MCP Server Flags

| Flag | Description |
|---|---|
| `--compact` | Load only 3 gateway tools (scope_check, run_security_tool, system_status) — for small LLMs |
| `--server URL` | Optional upstream Dexter AI Pentest API server URL |
| `--timeout N` | Tool execution timeout in seconds (default: 300) |
| `--debug` | Enable debug logging |
| `--list-tools` | Print registered tools and exit |

### Available MCP Tools (21 tools in full mode)

| Tool | Description |
|---|---|
| `scope_check` | Check if a target is in the authorized pentesting scope |
| `run_security_tool` | Execute any of the 151+ tools by name |
| `system_status` | Show system status (version, tools, scopes) |
| `nmap_scan` | Port/service scanning |
| `nikto_scan` | Web vulnerability scanning |
| `nuclei_scan` | Template-based vulnerability scanning (4000+ templates) |
| `sqlmap_scan` | SQL injection testing |
| `gobuster_scan` | Directory/file enumeration |
| `whois_lookup` | Domain WHOIS lookup |
| `dig_lookup` | DNS record lookup |
| `curl_scan` | HTTP header/response analysis |
| `analyze_security_headers` | Security header grading |
| `detect_technologies` | Web technology fingerprinting |
| `find_forms` | HTML form/input discovery |
| `check_cors` | CORS misconfiguration testing |
| `cve_lookup` | CVE intelligence lookup |
| `cve_search` | CVE database search |
| `add_note` | Save findings to loot directory |
| `get_notes` | Retrieve saved findings |
| `list_tools` | List all 151+ available tools |
| `list_playbooks` | List attack playbooks |

### Using with MCP Servers (External Tools)

Dexter AI Pentest also supports [Model Context Protocol](https://modelcontextprotocol.io/) servers for external tools:

```bash
# Configure MCP servers
cp mcp_servers.json.example mcp_servers.json
# edit mcp_servers.json with your MCP server configs

# Use in CLI
/mcp list
/mcp add nmap npx gc-nmap-mcp
```

---

## 🧠 Knowledge Base

Place domain knowledge, CVE notes, or methodologies in `dexter_ai/knowledge/sources/` — they are injected into the agent context automatically at runtime.

---

## ⚠️ Disclaimer

For educational and authorised security testing only. Always obtain written permission before scanning any target.

