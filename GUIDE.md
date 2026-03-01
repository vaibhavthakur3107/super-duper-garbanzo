# 🛡️ Cyber-Sentry AI — Complete Beginner's Setup & Usage Guide

> **Read this first if you are new to the project.**
> This guide walks you through everything — from zero to running your first AI-powered pentest — in plain language.

---

## Table of Contents

1. [What is Cyber-Sentry AI?](#1-what-is-cyber-sentry-ai)
2. [How does it compare to similar projects?](#2-how-does-it-compare-to-similar-projects)
3. [System Requirements](#3-system-requirements)
4. [Installation — Option A: Local Python (Recommended for beginners)](#4-option-a-local-python)
5. [Installation — Option B: Docker (Easiest, most reliable)](#5-option-b-docker)
6. [Configure your LLM provider](#6-configure-your-llm-provider)
7. [First run — Streamlit Web UI](#7-first-run--streamlit-web-ui)
8. [First run — Interactive CLI](#8-first-run--interactive-cli)
9. [Understanding the output (not hallucinations!)](#9-understanding-the-output)
10. [Attack Playbooks](#10-attack-playbooks)
11. [Notes & Loot system](#11-notes--loot-system)
12. [MCP server integration](#12-mcp-server-integration)
13. [Knowledge Base](#13-knowledge-base)
14. [Web Search tool](#14-web-search-tool)
15. [Generating reports](#15-generating-reports)
16. [Troubleshooting](#16-troubleshooting)
17. [FAQ](#17-faq)

---

## 1. What is Cyber-Sentry AI?

Cyber-Sentry is an **AI-powered autonomous Red Team pentesting agent**.
You give it a target (a domain, IP address, or IP range you are authorized to test) and a task, and it:

1. **Plans** a step-by-step attack strategy using an LLM
2. **Validates** the target is in your authorized scope (safety guardrail)
3. **Executes** real security tools (`nmap`, `nikto`, `gobuster`, `nuclei`, `whois`, `dig`, etc.)
4. **Reflects** on the tool output to decide what to do next
5. **Saves** all findings to a persistent notes/loot system
6. **Reports** a structured Markdown report when done

The agent loop is built with **LangGraph** (a state-machine framework for LLM agents), so every decision step is transparent and auditable in the Thought Trace panel.

> ⚠️ **Legal notice**: Only test systems you own or have **written permission** to assess.
> Unauthorized scanning is a crime in most jurisdictions.

---

## 2. How does it compare to similar projects?

| Feature | Cyber-Sentry | PentestGPT | Pentagi | PentestAgent | Shannon |
|---|:---:|:---:|:---:|:---:|:---:|
| LangGraph state machine | ✅ | ❌ | ❌ | ❌ | ❌ |
| Ollama (free, local LLM) | ✅ | ❌ | ✅ | ✅ | ❌ |
| OpenAI / Anthropic / OpenRouter | ✅ | ✅ | ✅ | ✅ | ✅ |
| Interactive CLI | ✅ | ✅ | ✅ | ✅ | ❌ |
| Attack playbooks | ✅ | ❌ | ❌ | ✅ | ❌ |
| Notes / loot persistence | ✅ | ❌ | ✅ | ✅ | ❌ |
| Markdown report export | ✅ | ❌ | ✅ | ✅ | ❌ |
| Streamlit web UI | ✅ | ❌ | ✅ | ❌ | ❌ |
| FastAPI REST + WebSocket | ✅ | ❌ | ✅ | ❌ | ❌ |
| MCP tool server support | ✅ | ❌ | ❌ | ✅ | ❌ |
| Knowledge base / RAG | ✅ | ❌ | ❌ | ✅ | ❌ |
| Web search (Tavily / DDG) | ✅ | ❌ | ❌ | ✅ | ❌ |
| Scope validation guardrail | ✅ | ✅ | ✅ | ✅ | ✅ |
| Prompt injection protection | ✅ | ✅ | ✅ | ✅ | ✅ |
| Docker-ready | ✅ | ✅ | ✅ | ✅ | ❌ |
| Test suite (56 tests) | ✅ | ✅ | ✅ | ✅ | ❌ |

**Cyber-Sentry uniquely combines** a LangGraph state machine, Streamlit thought-trace UI, FastAPI backend, MCP integration, knowledge base RAG, and support for all major LLM providers — making it the most feature-complete of the referenced projects.

---

## 3. System Requirements

### Minimum
| Component | Requirement |
|---|---|
| OS | Linux (Ubuntu 22.04+ recommended), macOS 13+, Windows 10/11 (WSL2) |
| Python | 3.10 or newer |
| RAM | 4 GB (8 GB recommended for local Ollama models) |
| Disk | 2 GB free (+ ~4 GB per Ollama model if using local LLM) |
| Internet | Needed for cloud LLM providers; Ollama works offline after model download |

### Optional (for running real pentest tools)
| Tool | Install |
|---|---|
| `nmap` | `sudo apt install nmap` (Debian/Ubuntu) |
| `nikto` | `sudo apt install nikto` |
| `gobuster` | `sudo apt install gobuster` |
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `sqlmap` | `pip install sqlmap` |
| `whois` | `sudo apt install whois` |
| `dig` | `sudo apt install dnsutils` |

> **Note**: Without these tools installed, the agent will report "command not found" errors in tool output but will not crash — the LLM reasoning and planning still works.

---

## 4. Option A: Local Python

### Step 1 — Clone the repository

```bash
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo
```

### Step 2 — Create a Python virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# OR
.venv\Scripts\activate         # Windows
```

### Step 3 — Install the project

```bash
pip install -e "."
```

This installs Cyber-Sentry and its core dependencies (LangGraph, LangChain, Streamlit, FastAPI, etc.).

**For cloud LLM providers, also run:**

```bash
pip install langchain-openai      # for OpenAI or OpenRouter
pip install langchain-anthropic   # for Anthropic (Claude)
```

### Step 4 — Install security tools (Linux/macOS)

```bash
sudo apt update && sudo apt install -y nmap nikto whois dnsutils curl
```

### Step 5 — Set up your configuration

```bash
cp .env.example .env
```

Now open `.env` in a text editor and fill in your API key (see [Section 6](#6-configure-your-llm-provider) for details).

---

## 5. Option B: Docker

Docker is the easiest approach because security tools (`nmap`, `nikto`, etc.) are pre-installed in the container.

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose on Linux)

### Step 1 — Clone the repository

```bash
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo
```

### Step 2 — Set up your configuration

```bash
cp .env.example .env
# Edit .env with your API keys
```

### Step 3 — Start the services

```bash
docker compose up
```

This starts:
- **Streamlit UI** at http://localhost:8501
- **FastAPI backend** at http://localhost:8000
- **Ollama** (local LLM server) at http://localhost:11434

> **First run**: Docker will build the image and pull the Ollama container. This takes 2–5 minutes. Subsequent starts are faster.

### Step 4 — Download a local model (if using Ollama)

In a separate terminal:

```bash
docker compose exec ollama ollama pull llama3
```

This downloads the `llama3` model (~4 GB). You only need to do this once.

---

## 6. Configure your LLM Provider

Open `.env` and set **one** of the following:

### Option A: Ollama (Free, runs locally, no internet needed for inference)

```dotenv
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
```

Then pull the model once:

```bash
ollama pull llama3          # ~4 GB, best for most tasks
# OR
ollama pull mistral         # ~4 GB, also excellent
# OR
ollama pull phi3            # ~2 GB, faster but less capable
```

> Install Ollama from https://ollama.com/download

### Option B: OpenRouter (Recommended — 200+ models, many free!)

Get a **free** API key at https://openrouter.ai/keys — no credit card required for free models.

```dotenv
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
```

Free models to try:
- `meta-llama/llama-3.1-8b-instruct:free`
- `mistralai/mistral-7b-instruct:free`
- `google/gemini-flash-1.5` (very fast)

### Option C: OpenAI

```dotenv
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

### Option D: Anthropic (Claude)

```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

### Authorized scopes (important!)

The agent **refuses to scan targets not on this list**. Add your lab targets:

```dotenv
AUTHORIZED_SCOPES=example.com,192.168.1.0,10.0.0.0,localhost,127.0.0.1
```

---

## 7. First Run — Streamlit Web UI

### Start the UI

```bash
# Local Python
make run
# OR directly:
streamlit run cyber_sentry/app.py

# Docker
docker compose up
```

Open your browser at **http://localhost:8501**.

### What you see

```
┌─────────────────────────────────────────────────────┐
│ 🛡️ Cyber-Sentry AI                                  │
│ ── Sidebar ──────────────────────────────────────── │
│  LLM Provider: [ollama ▾]                           │
│  Model: [llama3 ▾]                                  │
│  Authorized Scopes: example.com, localhost, ...     │
├─────────────────────────────────────────────────────┤
│ Target: [_________________]  Task: [Full Pentest ▾] │
│                                                     │
│              [🚀 Execute Assessment]                │
├─────────────────────────────────────────────────────┤
│ 🧠 Thought Trace                                    │
│  SUPERVISOR → GUARDRAIL → PLANNER → TOOL → REFLECT │
└─────────────────────────────────────────────────────┘
```

### Running your first scan

1. Select your **LLM Provider** in the sidebar
2. Select a **Model** for that provider
3. Enter a **Target** (must be in your Authorized Scopes) — e.g. `example.com`
4. Select **Task Type** — try `Reconnaissance Only` for a safe first run
5. Click **🚀 Execute Assessment**

You will see the **Thought Trace** panel populate in real time, showing each step the agent takes.

---

## 8. First Run — Interactive CLI

The CLI is great for scripting, automation, and running headless on a remote server.

### Start the interactive REPL

```bash
python -m cyber_sentry.cli
```

You will see the banner:

```
   _____      _               ____             _
  / ____|    | |             / ___|  ___  _ __ | |_ _ __ _   _
 | |    _   _| |__   ___ _ _\___ \ / _ \| '_ \| __| '__| | | |
 ...

Type /help for commands, /quit to exit.

cyber-sentry>
```

### Basic CLI walkthrough

```
# 1. Set your target
cyber-sentry> /target 192.168.1.10

# 2. Run a task
cyber-sentry> perform reconnaissance and port scan

# 3. Or use a built-in playbook
cyber-sentry> /playbook recon

# 4. View saved findings
cyber-sentry> /notes

# 5. Generate a report
cyber-sentry> /report

# 6. List all available commands
cyber-sentry> /help
```

### One-shot non-interactive mode (great for scripts)

```bash
# Run a playbook and save a report
python -m cyber_sentry.cli run \
    --target 192.168.1.10 \
    --playbook web_pentest \
    --report

# Custom task
python -m cyber_sentry.cli run \
    --target example.com \
    --task "Find open ports and check for web vulnerabilities" \
    --model llama3 \
    --provider ollama
```

### All CLI commands

```bash
python -m cyber_sentry.cli --help
python -m cyber_sentry.cli run --help
python -m cyber_sentry.cli playbooks        # list playbooks
python -m cyber_sentry.cli notes            # show saved findings
python -m cyber_sentry.cli mcp list         # list MCP servers
python -m cyber_sentry.cli mcp add nmap npx -y gc-nmap-mcp
```

### Available slash commands in the REPL

| Command | Description |
|---|---|
| `/target <host>` | Set the current target |
| `/agent <task>` | Run the autonomous agent on a task |
| `/playbook <name>` | Load and run an attack playbook |
| `/playbooks` | List all available playbooks |
| `/tools` | List all available tools |
| `/notes` | View saved findings and loot |
| `/report` | Generate a Markdown report for this session |
| `/mcp list` | List configured MCP servers |
| `/mcp add <name> <cmd>` | Add a new MCP server |
| `/mcp test <name>` | Test an MCP server connection |
| `/clear` | Clear the current session |
| `/help` | Show all commands |
| `/quit` | Exit |

---

## 9. Understanding the Output

### Is the output real or hallucinated?

The agent operates in two distinct modes:

**Real tool output (not hallucinated)**:
When the `[TOOL]` step appears in the thought trace, the agent has run an **actual system command** (e.g. `nmap -sV -sC example.com`). The output you see is the **raw stdout** from that command — identical to what you would see running it yourself.

**LLM reasoning**:
The `[SUPERVISOR]`, `[PLANNER]`, and `[REFLECTION]` steps are LLM reasoning steps. The *analysis* of results is LLM-generated. The LLM reads the real tool output and produces interpretations.

### What to trust

| Step | Source | Trust level |
|---|---|---|
| SUPERVISOR — Attack plan | LLM | Medium (reasonable, may not be optimal) |
| GUARDRAIL — Scope check | Code (deterministic) | High |
| PLANNER — Command selection | LLM | High (commands are real) |
| TOOL — Command output | Real system tool | **Highest** |
| REFLECTION — Analysis | LLM reads real output | Medium-High |

### Example: real nmap output vs LLM analysis

```
[TOOL] nmap_scan
Command: nmap -sV -sC -T4 example.com
Output:
  Starting Nmap 7.94 ( https://nmap.org )
  Nmap scan report for example.com (93.184.216.34)
  PORT    STATE SERVICE VERSION
  80/tcp  open  http    Apache httpd 2.4.41
  443/tcp open  https   Apache httpd 2.4.41
                                ↑ REAL output from nmap

[REFLECTION]
Reasoning: Discovered Apache 2.4.41 on ports 80/443. Should check for
           CVE-2021-41773 (path traversal) and CVE-2021-42013...
                                ↑ LLM analysis of the real output
```

---

## 10. Attack Playbooks

Playbooks are pre-built attack workflows. Each playbook defines the task description that gets sent to the agent.

### Available playbooks

| Name | Best for |
|---|---|
| `recon` | Passive OSINT + active enum, **no exploitation** — safest to run |
| `web_pentest` | Full black-box web app pentest (recon → enum → vuln scan → basic injection) |
| `network_audit` | Network infrastructure audit (host discovery → ports → services → SSL) |
| `ctf` | Capture The Flag challenges (web, forensics, recon, crypto) |

### Running a playbook

**CLI (interactive)**:
```
cyber-sentry> /playbook recon
Enter target: 192.168.1.10
```

**CLI (one-shot)**:
```bash
python -m cyber_sentry.cli run -t 192.168.1.10 --playbook network_audit --report
```

**Streamlit UI**:
- Select `Reconnaissance Only` in the Task Type dropdown
- The agent automatically uses the `recon` strategy

### Creating your own playbook

Add a `.yaml` file to `cyber_sentry/playbooks/`:

```yaml
# cyber_sentry/playbooks/my_custom.yaml
name: my_custom
category: custom
description: |
  My custom assessment: check SSH, FTP, and Telnet for weak configs.
  Look for default credentials and outdated software.

steps:
  - name: port_scan
    tool: nmap
    description: Scan for SSH/FTP/Telnet
  - name: service_enum
    tool: nmap
    description: Enumerate service versions
```

---

## 11. Notes & Loot System

The agent automatically saves all findings to `loot/notes.json`. This persists across sessions so you can pick up where you left off.

### Note categories

| Category | What it stores |
|---|---|
| `finding` | General discoveries (open ports, services, etc.) |
| `vulnerability` | Confirmed vulnerabilities (CVEs, misconfigs) |
| `credential` | Discovered usernames, passwords |
| `artifact` | Files, hashes, screenshots |

### Viewing your notes

```bash
# CLI subcommand
python -m cyber_sentry.cli notes

# Interactive REPL
cyber-sentry> /notes
```

### Storage location

Notes are saved to `./loot/notes.json` by default. You can change this:

```dotenv
# in .env
LOOT_DIR=/path/to/my/loot
```

### Generating a Markdown report

```bash
# Interactive REPL
cyber-sentry> /report

# One-shot mode
python -m cyber_sentry.cli run -t example.com --playbook recon --report
```

The report is saved as `loot/report_YYYYMMDD_HHMMSS.md` and includes:
- Target info
- All saved notes grouped by category
- Full thought trace with tool outputs

---

## 12. MCP Server Integration

[MCP (Model Context Protocol)](https://modelcontextprotocol.io/) lets you plug any external tool into Cyber-Sentry as a first-class agent tool — nmap MCP, Metasploit MCP, Burp Suite extensions, or your own custom tool server.

### Step 1 — Create your MCP config file

```bash
cp mcp_servers.json.example mcp_servers.json
```

### Step 2 — Edit `mcp_servers.json`

```json
{
  "mcpServers": {
    "nmap": {
      "command": "npx",
      "args": ["-y", "gc-nmap-mcp"],
      "env": {
        "NMAP_PATH": "/usr/bin/nmap"
      },
      "description": "nmap MCP server for network scanning"
    }
  }
}
```

### Step 3 — Add servers via CLI

```bash
# Add nmap MCP server
python -m cyber_sentry.cli mcp add nmap npx -y gc-nmap-mcp

# Add a custom server
python -m cyber_sentry.cli mcp add my_tool python3 /path/to/my_mcp_server.py
```

### Step 4 — Test the connection

```bash
python -m cyber_sentry.cli mcp test nmap
# [+] Server 'nmap' (npx) is available
```

### In the interactive REPL

```
cyber-sentry> /mcp list
  ✓ nmap            npx    nmap MCP server for network scanning

cyber-sentry> /mcp test nmap
[+] Server 'nmap' (npx) is available
```

---

## 13. Knowledge Base

The knowledge base injects domain knowledge into agent prompts — like giving the AI a cheat sheet.

### Built-in knowledge

Two files come pre-loaded:
- `cyber_sentry/knowledge/sources/web_methodology.md` — OWASP web pentest methodology
- `cyber_sentry/knowledge/sources/network_methodology.md` — Network audit methodology

### Adding your own knowledge

Just drop `.md` or `.txt` files into `cyber_sentry/knowledge/sources/`:

```bash
# Add a CVE cheat sheet
cat > cyber_sentry/knowledge/sources/cve_cheatsheet.md << 'EOF'
# Common CVEs to Check

## Apache
- CVE-2021-41773: Path traversal & RCE (Apache 2.4.49)
- CVE-2021-42013: Same, bypasses 41773 fix

## WordPress
- CVE-2023-28121: Unauthenticated RCE in WooCommerce Payments

## SSH
- Check for outdated OpenSSH < 9.3p2
EOF
```

The agent will automatically inject relevant sections when planning its next move.

### Checking what's loaded

```python
from cyber_sentry.knowledge import knowledge_base
print(knowledge_base.list_sources())
# ['web_methodology', 'network_methodology', 'cve_cheatsheet']
```

---

## 14. Web Search Tool

The agent can search the web for vulnerability information, CVE details, and attack techniques.

### Setup (optional)

**With Tavily (AI-powered, better results)**:
1. Get a free key at https://tavily.com
2. Add to `.env`:
   ```dotenv
   TAVILY_API_KEY=tvly-...
   ```

**Without Tavily**: The tool automatically falls back to DuckDuckGo instant-answer API — no key needed.

### How the agent uses it

The agent calls `web_search` during reconnaissance to look up:
- Vulnerability details for discovered software versions
- CVE information
- Exploit availability
- Wordlists and methodology references

---

## 15. Generating Reports

### Via interactive REPL

```
cyber-sentry> /report
[+] Report saved to: loot/report_20240301_143022.md
```

### Via one-shot mode

```bash
python -m cyber_sentry.cli run \
    -t 192.168.1.10 \
    --playbook web_pentest \
    --report
```

### Via Streamlit UI

After an assessment completes, scroll down to **Export Report** and click **📥 Generate Markdown Report**, then **⬇️ Download report.md**.

### Report format

```markdown
# Cyber-Sentry AI – Penetration Test Report

**Target:** 192.168.1.10
**Generated:** 2024-03-01 14:30:22

---

## 📌 Saved Notes

### [VULNERABILITY] nmap_scan
*2024-03-01T14:28:15*

80/tcp open  http   Apache httpd 2.4.41 ...

## Session 1 – Thought Trace

### [SUPERVISOR] plan_generation
**Thought:** Analyzing target...
**Reasoning:** Generated 5-step plan...

### [TOOL] nmap_scan
**Observation:**
\`\`\`
Starting Nmap 7.94...
\`\`\`
```

---

## 16. Troubleshooting

### "No module named 'langgraph'"

```bash
pip install langgraph langchain langchain-core langchain-community
```

### "No module named 'langchain_openai'"

```bash
pip install langchain-openai     # for OpenAI or OpenRouter
pip install langchain-anthropic  # for Anthropic
```

### "Target X is not in authorized scope"

Add your target to `.env`:
```dotenv
AUTHORIZED_SCOPES=example.com,192.168.1.0,10.0.0.5,my-lab.local
```
Or set it for a single session:
```bash
export AUTHORIZED_SCOPES="my-target.com,192.168.1.0"
```

### "ollama: command not found" / Connection refused on port 11434

1. Install Ollama: https://ollama.com/download
2. Start it: `ollama serve`
3. Pull a model: `ollama pull llama3`
4. Check it works: `ollama list`

### "nmap: command not found"

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y nmap

# macOS
brew install nmap

# Or use Docker (all tools pre-installed)
docker compose up
```

### Streamlit "ModuleNotFoundError" on start

Ensure you ran `pip install -e "."` from the **repo root** (not inside `cyber_sentry/`):

```bash
cd super-duper-garbanzo    # repo root
pip install -e "."
streamlit run cyber_sentry/app.py
```

### Docker: port already in use

```bash
# Find and kill the process using port 8501
lsof -i :8501
kill <PID>

# Or change the port
STREAMLIT_PORT=8502 docker compose up
```

### LLM gives poor results / seems to hallucinate plans

1. Try a larger model: `ollama pull llama3:70b` or switch to OpenRouter with `meta-llama/llama-3.1-70b-instruct`
2. Add context to the knowledge base (`cyber_sentry/knowledge/sources/`)
3. Use a specific playbook instead of a free-form task

### Tests fail

```bash
pip install pytest pyyaml
python -m pytest tests/test_core.py -v
```

Expected: `56 passed in X.XXs` — no LLM, no network access needed for tests.

---

## 17. FAQ

**Q: Does Cyber-Sentry require an internet connection?**
A: No — if you use Ollama with a downloaded model and your targets are on a local network, everything works fully offline. The web search tool is optional and falls back gracefully.

**Q: Can I use a free LLM?**
A: Yes! Options:
- **Ollama** (completely free, runs locally): `ollama pull llama3`
- **OpenRouter free tier**: many models available at zero cost — sign up at https://openrouter.ai/keys

**Q: Will the agent actually exploit vulnerabilities?**
A: By default the agent performs **scanning and enumeration only**. It runs `nmap`, `nikto`, `gobuster`, `nuclei` — these are passive discovery tools. `sqlmap` is in the tool list but only runs if the LLM explicitly selects it for SQL injection testing on a web target.

**Q: Is the output safe to save/share?**
A: The `OutputFilteringGuardrail` automatically redacts SSNs, credit card numbers, passwords, and API keys from tool output. Still review reports before sharing.

**Q: Can I add my own tools?**
A: Yes — three ways:
1. **MCP server**: Expose any tool as an MCP server and add it to `mcp_servers.json`
2. **Direct function**: Add a function to `cyber_sentry/tools/network_tools.py` and register it in `ToolRegistry`
3. **Playbook**: Reference the new tool name in a playbook step

**Q: How do I change the default model?**
A: Via CLI flag: `python -m cyber_sentry.cli --model mistral` or set in `.env`:
```dotenv
LLM_PROVIDER=ollama
```
Then when running: `--model mistral`

**Q: How do I add more authorized targets?**
A: Edit `.env`:
```dotenv
AUTHORIZED_SCOPES=target1.com,target2.local,192.168.1.0,10.0.0.0
```
Or via Streamlit sidebar: edit the "Allowed Targets" text area.

**Q: Can I run multiple scans in parallel?**
A: The CLI runs one agent session at a time. For parallel runs, use multiple terminal sessions or the FastAPI backend:
```bash
make run-api           # Start the API
# Then POST to /tasks multiple times
```

**Q: Where are results saved?**
A: By default in `./loot/notes.json` and `./loot/report_*.md`. Change with `LOOT_DIR=` in `.env`.

---

## Quick Reference Card

```bash
# Setup (one time)
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo
pip install -e "."
cp .env.example .env    # Edit with your API key
ollama pull llama3      # If using Ollama

# Run (pick one)
make run                         # Streamlit UI → http://localhost:8501
python -m cyber_sentry.cli       # Interactive CLI
docker compose up                # Docker (all tools pre-installed)

# One-shot assessment
python -m cyber_sentry.cli run -t 192.168.1.1 --playbook recon --report

# Tests
python -m pytest tests/ -v       # 56 tests, no LLM needed
```

---

*Cyber-Sentry AI is for educational and authorized security testing only. Always get written permission before scanning any target.*
