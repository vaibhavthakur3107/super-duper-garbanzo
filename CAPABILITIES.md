# 🛡️ Dexter AI Pentest — Complete Capabilities Reference

> **Everything your project can do — explained from first principles.**
> Every single feature, layer, and module, in plain English.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [The LangGraph Agent Brain](#2-the-langgraph-agent-brain)
3. [The Multi-Agent System](#3-the-multi-agent-system)
4. [All Security Tools](#4-all-security-tools)
5. [The Safety Guardrails](#5-the-safety-guardrails)
6. [Attack Playbooks](#6-attack-playbooks)
7. [The Knowledge Base (RAG)](#7-the-knowledge-base-rag)
8. [Web Search](#8-web-search)
9. [MCP — Model Context Protocol](#9-mcp--model-context-protocol)
10. [Notes / Loot System](#10-notes--loot-system)
11. [Report Generation](#11-report-generation)
12. [SQLite Memory / Session Storage](#12-sqlite-memory--session-storage)
13. [LLM Providers](#13-llm-providers)
14. [Interactive CLI](#14-interactive-cli)
15. [Streamlit Web UI](#15-streamlit-web-ui)
16. [FastAPI REST Backend](#16-fastapi-rest-backend)
17. [Docker / Docker Compose](#17-docker--docker-compose)
18. [Test Suite](#18-test-suite)
19. [The .env Configuration System](#19-the-env-configuration-system)
20. [Full Component Map](#20-full-component-map)

---

## 1. The Big Picture

Dexter AI Pentest is an **autonomous AI agent for penetration testing and red team security assessments**.

You give it:
- A **target** (domain, IP, or IP range you own or have permission to test)
- A **task** (what to do — pentest, recon, web scan, etc.)
- An **LLM** (local free Ollama, or cloud OpenAI/Anthropic/OpenRouter)

It then:
1. 🧠 **Plans** a step-by-step attack strategy
2. 🔒 **Validates** the target is authorized (safety guardrail)
3. 🔧 **Executes** real security tools (`nmap`, `nikto`, `gobuster`, `nuclei`, etc.)
4. 👁️ **Observes** and analyzes the results
5. 🔁 **Reflects** and decides what to do next (loops autonomously)
6. 📄 **Saves** all findings to a persistent notes/loot file
7. 📊 **Reports** a structured Markdown report when done

It does all of this **without you having to type a single command** — the AI drives the tools.

---

## 2. The LangGraph Agent Brain

**File:** `dexter_ai/main.py`

The core agent is built as a **state machine** using [LangGraph](https://langchain-ai.github.io/langgraph/). This means instead of a simple chatbot loop, the agent has a defined graph of nodes (steps), each with a specific job, connected by edges (transitions).

### The 5 Nodes

```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  SUPERVISOR  │─────▶│  GUARDRAIL   │─────▶│   PLANNER    │
└──────────────┘      └──────────────┘      └──────────────┘
                                                    │
                             ┌──────────────────────┘
                             ▼
                      ┌──────────────┐      ┌──────────────┐
                      │     TOOL     │─────▶│  REFLECTION  │
                      └──────────────┘      └──────────────┘
                                                    │
                             ┌──────────────────────┘
                             ▼
                      ┌─────────────────────────────────────┐
                      │  Continue? → back to PLANNER        │
                      │  Done/Error? → END                  │
                      └─────────────────────────────────────┘
```

#### 🟡 SUPERVISOR Node
- Receives the target and task
- Uses the LLM to generate a **multi-step attack plan** (e.g. `reconnaissance → port_scan → web_enumeration → vulnerability_scan → exploitation → reporting`)
- Adds the plan to the agent state
- Records its reasoning in the Thought Trace

#### 🟢 GUARDRAIL Node
- **Deterministic** (no LLM) — pure Python code, always reliable
- Validates the target is in the authorized scope
- Checks messages for **prompt injection** attempts (e.g. "ignore previous instructions")
- Blocks the run immediately if anything is suspicious, before any tool runs

#### 🔵 PLANNER Node
- Looks at the current step (e.g. `port_scan`)
- Asks the LLM to generate the **exact command** to run for that step
- Auto-selects the right tool (`nmap_scan` for port scans, `nikto_scan` for web, `dig_lookup` for DNS, etc.)
- Records the planned command in the Thought Trace

#### 🔧 TOOL Node
- **Actually executes the command** using the real system tool via `subprocess`
- Captures stdout and stderr
- Has a timeout (300 seconds for most tools, up to 1800 for sqlmap)
- Returns the raw tool output (this is the real, non-hallucinated data)

#### 🔴 REFLECTION Node
- Feeds the real tool output back to the LLM
- The LLM **analyzes** what was found (open ports, vulnerabilities, services)
- Decides whether to continue to the next step or stop
- Moves to the next step in the plan, or generates an additional step dynamically

### Why This Matters

This architecture means the agent is **transparent and auditable** — you can see every decision it made and why. Every step is logged in the **Thought Trace**, which is displayed in the UI and saved in reports.

---

## 3. The Multi-Agent System

**Files:** `dexter_ai/agents/__init__.py`, `dexter_ai/agents/specialized.py`

Besides the LangGraph brain, Dexter AI Pentest has a separate **multi-agent orchestration system** used by the FastAPI backend. It follows the **ReAct (Reason + Act)** framework.

### Base Agent Class (`Agent`)

Every agent:
- `think(prompt)` — ReAct cycle: reason → decide action → check guardrails → act → observe
- `get_thought_trace()` — Full history of every reasoning step
- `clear_history()` — Reset for a new session
- Has its own **state** (`IDLE` / `THINKING` / `ACTING` / `OBSERVING` / `COMPLETED` / `ERROR` / `BLOCKED`)

### Four Specialized Agents

#### 🕵️ Reconnaissance Agent (`ReconnaissanceAgent`)
- Extracts target domains from the task prompt
- Decides to run `recon_target`, `analyze_environment`, or `list_capabilities`
- Updates context with findings for other agents

#### 🔍 Vulnerability Agent (`VulnerabilityAgent`)
- Runs after Recon
- Selects `scan_vulnerabilities` for the discovered target
- Marks context so Exploitation Agent knows it's ready

#### 💥 Exploitation Agent (`ExploitationAgent`)
- Only activates after Vulnerability scan is complete
- Runs `validate_exploits` to safely test vulnerabilities
- Constrained to stay within scope and legal boundaries

#### 📄 Reporting Agent (`ReportingAgent`)
- Compiles all findings into a structured report
- Generates executive summary + technical details
- Assigns risk levels

### Agent Orchestrator (`AgentOrchestrator`)
- Coordinates all four agents for a given task
- Maintains session state across agents
- Returns a full session object with results and thought traces
- Used by the FastAPI `/tasks` endpoint

### Agent Factory (`AgentFactory`)
- Creates all four agents with correct configs and guardrails
- Used on API startup to register agents

---

## 4. All Security Tools

### Real Tool Wrappers — `dexter_ai/tools/network_tools.py`

These functions run **real system commands** and return their actual output.

#### `nmap_scan(command, target)`
- Runs `nmap` for port scanning and service detection
- Default: `nmap -sV -sC -T4 -oA nmap_scan <target>`
- Timeout: 10 minutes
- Returns raw nmap output (real scan data)

#### `nikto_scan(command, target)`
- Runs `nikto` for web server vulnerability checks
- Default: `nikto -h http://<target> -o nikto_scan.txt`
- Checks for: outdated software, dangerous files, server misconfigs, XSS, SQLi hints
- Timeout: 15 minutes

#### `gobuster_scan(command, target)`
- Runs `gobuster dir` for directory/file enumeration
- Uses `/usr/share/wordlists/dirb/common.txt` by default
- Discovers: hidden admin panels, backup files, config files, upload directories
- Timeout: 20 minutes

#### `nuclei_scan(command, target)`
- Runs `nuclei` vulnerability scanner with community templates
- Default: critical, high, medium severity templates
- Discovers: CVEs, misconfigurations, exposed APIs, default credentials
- Timeout: 20 minutes

#### `sqlmap_scan(command, target)`
- Runs `sqlmap` for SQL injection testing
- Default: `--batch --risk=1 --level=1` (safe, non-destructive)
- Timeout: 30 minutes

#### `whois_lookup(command, target)`
- Runs `whois` to get domain registration info
- Returns: registrar, registration date, expiry date, name servers, contact info
- Timeout: 30 seconds

#### `dig_lookup(command, target)`
- Runs `dig` for DNS record enumeration
- Default: `dig <target> ANY +short` (all record types)
- Returns: A, AAAA, MX, TXT, NS, CNAME, SOA records
- Timeout: 30 seconds

#### `curl_scan(command, target)`
- Runs `curl -I -L` to fetch HTTP headers
- Returns: server type, technology headers, response codes, redirects
- Timeout: 60 seconds

#### `web_search(query, target)`
- AI-powered web search (see [Section 8](#8-web-search))

### Helper Functions

#### `extract_ports(nmap_output)`
- Parses nmap output with regex
- Returns list of `{port, protocol, service}` dicts
- Example: `[{"port": 80, "protocol": "tcp", "service": "http"}]`

#### `extract_urls(gobuster_output)`
- Parses gobuster output
- Returns discovered URLs with status codes (200, 301, 302, 403)

#### `extract_cves(nuclei_output)`
- Extracts CVE numbers from nuclei output (regex `[CVE-XXXX-XXXXX]`)
- Returns deduplicated list

#### `sanitize_command(command)`
- Safety filter: blocks `rm -rf`, fork bombs, pipe-to-shell, disk writes, `sudo`, `chmod 777`
- Allows only: `nmap`, `nikto`, `gobuster`, `nuclei`, `sqlmap`, `whois`, `dig`, `host`, `curl`, `wget`
- Returns `(is_valid, error_message)`

#### `run_command(command, timeout)`
- The underlying shell executor
- Sets PATH to include `/usr/local/bin:/usr/bin:/bin`
- Truncates output at 100,000 characters
- Returns combined stdout+stderr

### API-Layer Tool Classes — `dexter_ai/tools/registry.py`

These are the object-oriented tool classes used by the FastAPI-facing `ToolRegistry`:

| Class | Tool Name | What It Does |
|---|---|---|
| `NetworkScannerTool` | `recon_target` | Port scan + service identification |
| `VulnerabilityScannerTool` | `scan_vulnerabilities` | Known CVE checking |
| `WhoisLookupTool` | `whois_lookup` | WHOIS domain info |
| `SSLAnalysisTool` | `ssl_analysis` | SSL/TLS cipher suite analysis |
| `AnalyzeEnvironmentTool` | `analyze_environment` | Context and environment analysis |
| `ListCapabilitiesTool` | `list_capabilities` | Returns all available capabilities |

---

## 5. The Safety Guardrails

Dexter AI Pentest has **two separate guardrail layers** — one in the LangGraph brain, one in the API agent system.

### LangGraph Guardrails — `dexter_ai/guardrails/scope_validator.py`

#### `validate_scope(target)`
The most important safety check. Called before **any** tool runs. Checks if a target is allowed.

**What it authorizes:**
- Exact matches in `AUTHORIZED_SCOPES` list
- Domain suffix matches (e.g. `sub.example.com` passes if `example.com` is in scope)
- Private IP ranges: `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`, `127.x.x.x`
- `localhost`, `0.0.0.0`
- Reads from `AUTHORIZED_SCOPES` environment variable (comma-separated)

**What it does to the input:**
- Strips `http://` and `https://` prefixes
- Strips URL paths (`/path/to/page`)
- Strips port numbers (`:8080`)
- Lowercases everything

**If a target is NOT authorized:** The entire run stops immediately with `DENIED` status.

#### Prompt Injection Detection (in `main.py` GUARDRAIL node)
Blocks messages containing:
- `"ignore previous"`, `"ignore all"`
- `"you are now"`, `"disregard instructions"`
- `"new instructions:"`, `"system:"`, `"assistant:"`

### API Guardrails — `dexter_ai/guardrails/security.py`

Seven guardrails used by the FastAPI multi-agent system:

| Guardrail | What It Does |
|---|---|
| `ScopeValidationGuardrail` | Same domain/IP scope check as above |
| `DangerousActionGuardrail` | Blocks: `execute_arbitrary_code`, `delete_data`, `modify_data`, `install_malware`, `denial_of_service`, `exploit_remote`, `privilege_escalation`; also blocks `destructive=True` and `force=True` params |
| `RateLimitGuardrail` | Max 60 requests/minute per agent (configurable). Prevents abuse. |
| `InputValidationGuardrail` | Regex blocks: shell metacharacters (`;|` `` ` ``$`()`), XSS (`<script`, `javascript:`), event handlers (`onclick=`), SQL injection (`union select`), path traversal (`../`) |
| `LegalComplianceGuardrail` | Blocks scanning `.gov`, `.mil`, `whitehouse.gov`, `cia.gov`, `fbi.gov` etc. |
| `OutputFilteringGuardrail` | Auto-redacts SSNs, credit card numbers, passwords, API keys from tool output |
| `AuditLoggingGuardrail` | Logs every action with agent name, params, target, and timestamp for audit trail |

---

## 6. Attack Playbooks

**Directory:** `dexter_ai/playbooks/`

Playbooks are YAML files that define pre-built attack workflows. Each one sets the task description that gets sent to the LangGraph agent.

### Built-in Playbooks

#### 📋 `recon` — Reconnaissance Only
**Category:** Passive + Active Information Gathering (no exploitation)

**Phases:**
1. **Passive OSINT** — WHOIS, DNS records, certificate transparency logs, subdomain discovery
2. **DNS Enumeration** — Zone transfer attempts, brute-force subdomains, reverse DNS
3. **Active Recon** — Ping sweep, top-1000 port scan, OS detection
4. **Web Fingerprinting** — HTTP banner grabbing, CMS/framework identification, robots.txt/sitemap

**Best for:** Safe first look at any target, no risk of triggering IDS

---

#### 🌐 `web_pentest` — Full Web Application Pentest
**Category:** Web Security Assessment

**Phases:**
1. **Reconnaissance** — WHOIS, DNS, HTTP header fingerprinting
2. **Port Scan** — Web ports (80, 443, 8080, 8443, 8000, 3000) with service detection
3. **Web Enumeration** — gobuster directory scan + nikto quick vulnerability check
4. **Vulnerability Scan** — nuclei templates for CVEs, misconfigs, exposed endpoints
5. **Injection Testing** — sqlmap for SQL injection, XSS assessment

**Report sections:** Executive summary, scope/methodology, findings, risk ratings, remediation

---

#### 🔌 `network_audit` — Network Infrastructure Audit
**Category:** Network Security Assessment

**Phases:**
1. **Host Discovery** — Ping sweep of network range
2. **Port Scan** — Full TCP + UDP scan of all 65,535 ports with version detection
3. **Service Enumeration** — Banner grabbing, FTP/SMB/LDAP/SNMP/NFS anonymous access checks
4. **Vulnerability Assessment** — nmap NSE vuln scripts + nuclei network templates
5. **SSL/TLS Audit** — Cipher suite enumeration, expired certs, weak protocols (POODLE, BEAST, CRIME)

---

#### 🚩 `ctf` — Capture The Flag Solver
**Category:** CTF Challenge (Web, Forensics, Recon, Crypto)

**Phases:**
1. **Initial Recon** — Challenge type identification, port scan, page source analysis
2. **Web Analysis** — Directory enumeration, parameter fuzzing (IDOR/LFI/RFI/SQLi/XSS), cookie analysis
3. **OSINT & Metadata** — File metadata extraction, certificate transparency, GitHub/Pastebin leaks
4. **Vulnerability Exploitation** — Inject identified points, escalate privileges, capture flag

---

### Creating Your Own Playbook

Drop any `.yaml` file in `dexter_ai/playbooks/` with this structure:

```yaml
name: my_playbook
description: >
  What this playbook does — this text becomes the agent's task.
category: custom

phases:
  - name: phase_one
    description: Description of this phase
    tools:
      - nmap_scan
      - dig_lookup
    steps:
      - "Step 1 description"
      - "Step 2 description"
```

---

## 7. The Knowledge Base (RAG)

**File:** `dexter_ai/knowledge/__init__.py`
**Sources:** `dexter_ai/knowledge/sources/`

The Knowledge Base is a lightweight **Retrieval-Augmented Generation (RAG)** system that injects domain expertise into agent prompts.

### How It Works

1. On startup, it loads every `.md` and `.txt` file from `sources/`
2. When the agent needs context, it calls `get_context(query)` with a keyword
3. Documents whose filenames or content contain the keyword are returned
4. The context is injected into the LLM prompt (up to 4,000 characters)

### Built-in Knowledge Sources

#### `web_methodology.md` — OWASP Web Pentest Methodology
Contains:
- Phase 1: Passive Recon (WHOIS, DNS, crt.sh, Shodan, Google dorking)
- Phase 2: Scanning (nmap commands, service fingerprinting)
- Phase 3: Enumeration (gobuster, ffuf, subdomain brute-force, robots.txt)
- Phase 4: Vulnerability Assessment (nuclei, default creds, OWASP Top 10)
- Phase 5: Exploitation (minimal impact PoCs, CVSS scoring)
- Phase 6: Reporting (executive summary, technical findings, remediation)

#### `network_methodology.md` — Network Audit Methodology
Contains:
- Phase 1: Host Discovery (nmap ping sweep, arp-scan)
- Phase 2: Port Scanning (fast TCP, full TCP+UDP, stealth)
- Phase 3: Service Enumeration (SMB, LDAP, SNMP, NFS, banner grabbing)
- Phase 4: SSL/TLS Audit (weak ciphers, expired certs, HSTS)
- Phase 5: Vulnerability Scanning (nmap NSE vuln, nuclei, EternalBlue, BlueKeep)
- Common Findings reference list

### Adding Your Own Knowledge

```bash
# Add CVE cheat sheet
echo "# Apache CVEs..." > dexter_ai/knowledge/sources/apache_cves.md

# Add your custom methodology
echo "# My Red Team Notes..." > dexter_ai/knowledge/sources/custom_methodology.md
```

The agent automatically picks it up on next run — no code changes needed.

---

## 8. Web Search

**Function:** `web_search()` in `dexter_ai/tools/network_tools.py`

The agent can search the web to look up CVE details, vulnerability info, exploit availability, and attack techniques.

### Mode 1: Tavily AI Search (set `TAVILY_API_KEY`)
- AI-powered search with structured answers
- Returns: direct answer + up to 5 result URLs with summaries
- Free tier available at https://tavily.com

### Mode 2: DuckDuckGo Instant Answer (no key needed, automatic fallback)
- Uses `curl` to query the DuckDuckGo instant-answer JSON API
- Returns: abstract text + related topics
- Works completely offline-friendly (no API key, no signup)
- Falls back gracefully if network is unavailable

### How the Agent Uses It

The agent calls `web_search` to:
- Look up CVE details for discovered software versions
- Find known exploits for identified vulnerabilities
- Search for default credentials for discovered services
- Find attack technique documentation

---

## 9. MCP — Model Context Protocol

**File:** `dexter_ai/mcp/__init__.py`
**Config:** `mcp_servers.json` (copy from `mcp_servers.json.example`)

MCP (Model Context Protocol) is an open standard for connecting AI agents to external tool servers. Dexter AI Pentest implements a full MCP client that lets you plug **any external tool** into the agent.

### What You Can Connect

- **nmap MCP** — nmap as an MCP server
- **Metasploit MCP** — Metasploit Framework modules as agent tools
- **Burp Suite extension** — Burp Scanner results as tools
- **Custom tools** — Any script or program you want the agent to use
- **Third-party MCP servers** — Any server from the MCP ecosystem

### `MCPClient` — What It Can Do

| Method | What It Does |
|---|---|
| `list_servers()` | Lists all configured MCP servers with availability status |
| `add_server(name, command, args, env, description)` | Adds/updates a server config and persists to `mcp_servers.json` |
| `remove_server(name)` | Removes a server from the config |
| `get_server(name)` | Gets a server's full configuration |
| `test_server(name)` | Checks whether the server command exists on PATH |
| `call_tool(server_name, tool_name, arguments)` | Calls a tool on the MCP server |

### How `call_tool` Works

1. **Tries the official `mcp` Python SDK** (if installed via `pip install mcp`)
2. **Falls back to subprocess JSON-RPC** if the SDK is not available — sends a JSON-RPC 2.0 `tools/call` request to the server's stdin and reads the response from stdout

### Config Format (`mcp_servers.json`)

```json
{
  "mcpServers": {
    "nmap": {
      "command": "npx",
      "args": ["-y", "gc-nmap-mcp"],
      "env": {"NMAP_PATH": "/usr/bin/nmap"},
      "description": "nmap MCP server"
    },
    "metasploit": {
      "command": "python3",
      "args": ["/path/to/msf_mcp_server.py"],
      "description": "Metasploit MCP server"
    }
  }
}
```

---

## 10. Notes / Loot System

**File:** `dexter_ai/notes.py`
**Storage:** `./loot/notes.json` (persists across sessions)

Every finding from every assessment is automatically saved.

### Four Note Categories

| Category | What Gets Saved Here |
|---|---|
| `finding` | General discoveries — open ports, running services, interesting paths |
| `vulnerability` | Confirmed vulnerabilities — CVE IDs, misconfigurations, weak configs |
| `credential` | Discovered usernames, passwords, API keys, tokens |
| `artifact` | Files, hashes, screenshots, captured flags |

### `NotesManager` — What It Can Do

| Method | What It Does |
|---|---|
| `add_note(content, category, target, source)` | Saves a note with timestamp and auto-incrementing ID |
| `get_notes(category=None, target=None)` | Returns all notes, optionally filtered by category or target |
| `generate_report(session_results, target)` | Compiles Markdown report from notes + thought traces |
| `clear_session()` | Clears in-memory state (does NOT delete persisted notes file) |

### Note Structure

Each note in `loot/notes.json` looks like:

```json
{
  "id": 1,
  "timestamp": "2024-03-01T14:30:22.123456",
  "category": "finding",
  "target": "testphp.vulnweb.com",
  "source": "nmap_scan",
  "content": "80/tcp open  http   Apache httpd 2.4.7..."
}
```

---

## 11. Report Generation

Reports are **Markdown files** generated automatically from notes and thought traces.

### What's in a Report

```markdown
# Dexter AI Pentest – Penetration Test Report

**Target:** testphp.vulnweb.com
**Generated:** 2024-03-01 14:30:22

---

## 📌 Saved Notes

### [FINDING] nmap_scan
*2024-03-01T14:28:15*
80/tcp open  http   Apache httpd 2.4.7 ...

### [VULNERABILITY] nuclei_scan
*2024-03-01T14:29:33*
[CVE-2021-41773] Apache path traversal...

---

## Session 1 – Thought Trace

### [SUPERVISOR] plan_generation
**Thought:** Analyzing target testphp.vulnweb.com
**Reasoning:** Generated 6-step plan: recon, port_scan, web_enum, vuln_scan, injection, report

### [TOOL] nmap_scan
**Observation:**
\`\`\`
Starting Nmap 7.94...
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.7
\`\`\`
```

### How to Generate

```bash
# CLI interactive
dexter-ai> /report

# CLI one-shot (automatic after run)
python -m dexter_ai.cli run -t target.com --report

# Streamlit UI
# Scroll to bottom → "📥 Generate Markdown Report" → "⬇️ Download report.md"
```

Reports are saved to `loot/report_YYYYMMDD_HHMMSS.md`.

---

## 12. SQLite Memory / Session Storage

**File:** `dexter_ai/db/memory.py`
**Database:** `dexter_ai.db` (SQLite, auto-created)

Full conversation and session history is persisted in a local SQLite database.

### Four Database Tables

| Table | What It Stores |
|---|---|
| `sessions` | Session ID, target, task, status, timestamps |
| `thoughts` | All thought trace steps per session (node, thought, reasoning, action, observation) |
| `messages` | Conversation messages (role, content) per session |
| `tool_results` | Raw tool execution results per session |

### `ConversationMemory` — What It Can Do

| Method | What It Does |
|---|---|
| `create_session(id, target, task)` | Opens a new assessment session |
| `update_session_status(id, status)` | Updates `running` / `completed` / `failed` |
| `add_thought(session_id, thought)` | Saves a thought trace entry |
| `add_message(session_id, role, content)` | Saves a conversation message |
| `add_tool_result(session_id, tool_name, command, result)` | Saves tool output |
| `get_thoughts(session_id)` | Retrieves full thought trace for a session |
| `get_session(session_id)` | Retrieves session metadata |
| `list_sessions(limit=10)` | Lists recent sessions sorted by last activity |

---

## 13. LLM Providers

**File:** `dexter_ai/providers.py`

Dexter AI Pentest works with **four LLM providers**. You can switch between them by setting one environment variable.

### Provider Selection Order

When you don't specify a provider explicitly:
1. `LLM_PROVIDER` environment variable
2. Auto-detected from available API keys: `OPENROUTER_API_KEY` → `OPENAI_API_KEY` → `ANTHROPIC_API_KEY` → Ollama (default)

### Ollama (Local, Free)
- **Cost:** Free — runs entirely on your machine
- **Privacy:** 100% local, nothing sent to internet
- **Models:** llama3, mistral, codellama, neural-chat, phi3, and any other pulled model
- **Requirements:** Ollama installed + model pulled (`ollama pull llama3`)
- **Config:** `LLM_PROVIDER=ollama`, `OLLAMA_BASE_URL=http://localhost:11434`
- **Streaming:** ✅

### OpenAI
- **Cost:** Pay-per-token
- **Models:** gpt-4o-mini (default), gpt-4o, gpt-4-turbo, gpt-3.5-turbo
- **Config:** `LLM_PROVIDER=openai`, `OPENAI_API_KEY=sk-...`
- **Streaming:** ✅

### Anthropic (Claude)
- **Cost:** Pay-per-token
- **Models:** claude-3-haiku (default), claude-3-5-sonnet, claude-3-opus
- **Config:** `LLM_PROVIDER=anthropic`, `ANTHROPIC_API_KEY=sk-ant-...`
- **Streaming:** ✅

### OpenRouter (200+ Models, Many Free)
- **Cost:** Free tier available with many models
- **Models:** 200+ including free Llama, Mistral, Gemini, DeepSeek models
- **Config:** `LLM_PROVIDER=openrouter`, `OPENROUTER_API_KEY=sk-or-...`
- **Free models:** `meta-llama/llama-3.1-8b-instruct:free`, `mistralai/mistral-7b-instruct:free`
- **Streaming:** ✅

### `get_llm(model, temperature, provider)` Factory

Returns the right `ChatLLM` object for the selected provider. Called by all entry points (CLI, Streamlit, API). Setting `temperature=0.7` by default balances creativity with consistency.

---

## 14. Interactive CLI

**File:** `dexter_ai/cli.py`
**Entry point:** `python -m dexter_ai.cli`

The CLI has two modes: interactive REPL and one-shot non-interactive.

### Interactive REPL Mode

Launch with: `python -m dexter_ai.cli`

You get the Dexter AI Pentest banner and a `dexter-ai>` prompt.

#### All Slash Commands

| Command | What It Does |
|---|---|
| `/target <host>` | Set the current assessment target |
| `/agent <task>` | Run the full autonomous agent on a custom task |
| `/playbook <name>` | Load a playbook and run the agent with that task |
| `/playbooks` | List all available playbooks with descriptions |
| `/notes` | Print all saved notes/findings from `loot/notes.json` |
| `/report` | Generate Markdown report for the current session → `loot/report_*.md` |
| `/tools` | List all registered tools with category and description |
| `/clear` | Clear the current session (notes remain persisted) |
| `/mcp list` | List configured MCP servers with availability status |
| `/mcp add <name> <command> [args...]` | Add a new MCP server |
| `/mcp test <name>` | Test whether an MCP server's command is available |
| `/mcp remove <name>` | Remove an MCP server |
| `/help` (or `/h`, `/?`) | Show all commands |
| `/quit` (or `/exit`, `/q`) | Exit the CLI |

#### Default Behaviour (no slash command)
If you type a plain sentence and a target is set, it runs the agent with that as the task. Example:
```
dexter-ai> find all open ports and look for web vulnerabilities
```

### One-Shot Mode (Subcommands)

#### `python -m dexter_ai.cli run`
```
-t / --target     (required) Target host
--task            Custom task description
--playbook        Name of playbook to run (ctf, network_audit, recon, web_pentest)
--model           LLM model name
--provider        LLM provider
--report          Save Markdown report when done
```

#### `python -m dexter_ai.cli notes`
Prints all notes from `loot/notes.json`.

#### `python -m dexter_ai.cli playbooks`
Lists all playbooks with descriptions.

#### `python -m dexter_ai.cli mcp <list|add|test|remove> [args]`
Manages MCP server configuration.

### CLI Flags (all modes)
```
-t / --target     Pre-set target before entering interactive mode
--model           LLM model (default: llama3)
--provider        LLM provider (default: auto-detect from env)
```

---

## 15. Streamlit Web UI

**File:** `dexter_ai/app.py`
**Launch:** `make run` or `streamlit run dexter_ai/app.py`
**URL:** http://localhost:8501

A dark-themed, professional-looking web interface.

### Sidebar
- **LLM Provider** dropdown (ollama / openai / anthropic / openrouter)
- **Model** dropdown (changes options based on selected provider, e.g. gpt-4o-mini, claude-3-haiku, llama3, etc.)
- **Authorized Scopes** text area — comma-separated allowed targets
- **Session Info** — current session ID and thought count
- Version and description

### Main Panel

#### Input Area
- **Target** text field
- **Task Type** dropdown:
  - Full Pentest
  - Reconnaissance Only
  - Vulnerability Scan
  - Web Enumeration
  - Port Scan
- **🚀 Execute Assessment** button

#### Thought Trace Panel

After running, shows:
- **Summary metrics**: Total Thoughts, Supervisor count, Tools Executed, Reflections
- **Filter by Node** dropdown (All / supervisor / guardrail / planner / tool / reflection)
- **Show only latest** checkbox (shows last 5 thoughts)
- **Individual thought cards** for each step, color-coded:
  - 🟡 Yellow border = Supervisor (planning)
  - 🟢 Green border = Tool (acting)
  - 🔴 Red border = Guardrail blocked
  - 🔵 Blue border = Default
- Each card shows: Node name, Timestamp, Thought text, Reasoning, Action, Action Input (collapsible), Observation (collapsible)

#### Example Thought Trace
When no scan has run yet, shows example cards so you can see how the UI works.

#### Tool Results Section
Shows tool execution results with success/failure status and output text.

#### Export Report Section
- **📥 Generate Markdown Report** button — builds the report in memory
- **⬇️ Download report.md** button — downloads the file
- **Preview Report** expander — shows the report inline

---

## 16. FastAPI REST Backend

**File:** `dexter_ai/api/main.py`
**Launch:** `make run-api` or `uvicorn dexter_ai.api.main:app --reload`
**URL:** http://localhost:8000

Full REST API with WebSocket and Server-Sent Events support.

### Endpoints

| Method | Path | What It Does |
|---|---|---|
| `GET` | `/` | API info (name, version, status) |
| `GET` | `/health` | Health check with component status |
| `GET` | `/status` | Full system status (agents, tools, guardrails, active sessions) |
| `POST` | `/tasks` | Create and execute a new assessment task |
| `GET` | `/tasks` | List all sessions with metadata |
| `GET` | `/tasks/{session_id}` | Get full results for a specific session |
| `GET` | `/agents` | List all registered agents |
| `GET` | `/agents/{name}/thoughts` | Get thought trace for a specific agent |
| `GET` | `/tools` | List all available tools |
| `GET` | `/guardrails` | List all active guardrails |
| `WS` | `/ws/thoughts` | WebSocket for real-time thought streaming |
| `GET` | `/events/thoughts/{session_id}` | Server-Sent Events for thought streaming |

### Task Request Format

```json
POST /tasks
{
  "task": "Perform reconnaissance and port scan",
  "target": "192.168.1.10",
  "agents": ["Reconnaissance Agent"],  // optional, uses all if omitted
  "options": {}
}
```

### Task Response Format

```json
{
  "session_id": "uuid-...",
  "status": "completed",
  "task": "Perform reconnaissance...",
  "start_time": "2024-03-01T14:30:00",
  "results": [...]
}
```

### Real-time Streaming

The `/ws/thoughts` WebSocket endpoint streams thought events as they happen:
```json
{
  "type": "thought_trace",
  "agent": "Reconnaissance Agent",
  "thought": { "id": "...", "action": "recon_target", ... },
  "timestamp": "2024-03-01T14:30:22"
}
```

---

## 17. Docker / Docker Compose

**Files:** `Dockerfile`, `docker-compose.yml`

### Services

| Service | Port | What It Runs |
|---|---|---|
| `ui` | 8501 | Streamlit web UI |
| `api` | 8000 | FastAPI REST backend |
| `cli` | — | Interactive CLI (profile: cli) |
| `ollama` | 11434 | Local Ollama LLM server |

### Starting Services

```bash
docker compose up               # UI + API + Ollama
docker compose up ui            # Only Streamlit
docker compose up api           # Only FastAPI
docker compose run --rm cli     # Interactive CLI session
```

### Environment Variables via Docker

All `.env` variables are passed through to every container:
- `LLM_PROVIDER` — which LLM to use
- `OLLAMA_BASE_URL` — points to the `ollama` service automatically (`http://ollama:11434`)
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`
- `AUTHORIZED_SCOPES`

### Volume Mounts

```yaml
volumes:
  - ./loot:/app/loot        # Findings and reports persist on host
  - ./sessions:/app/sessions # Session data persists on host
  - ollama_data:/root/.ollama # Downloaded LLM models persist
```

---

## 18. Test Suite

**File:** `tests/test_core.py`
**Run:** `python -m pytest tests/ -v`
**Result:** 56 tests, all pass, no LLM or network access required

### What's Tested

| Test Class | Number of Tests | What It Covers |
|---|---|---|
| `TestScopeValidator` | 11 | All scope validation rules (authorized domains, IPs, private ranges, stripping protocols/ports) |
| `TestNotesManager` | 8 | All note categories, filtering, disk persistence, report generation |
| `TestProviderConstants` | 5 | All provider name constants and OpenRouter base URL |
| `TestPlaybooks` | 7 | Playbook discovery, YAML loading, descriptions, missing playbook handling |
| `TestNetworkToolHelpers` | 7 | Port extraction, CVE extraction, URL extraction, command sanitization, web_search in registry |
| `TestMCPClient` | 11 | Server add/list/get/remove/test, disk persistence, example config format, unavailable command |
| `TestKnowledgeBase` | 7 | Source loading, document retrieval, context filtering, built-in sources |

### Why Tests Don't Need an LLM

All tests operate on the **infrastructure layer** — guardrails, tools, notes, playbooks, MCP, knowledge base. They test that:
- Safety checks work correctly
- Data is persisted and loaded properly
- Tool helpers parse output correctly
- MCP configs round-trip correctly
- Knowledge base loads and queries correctly

---

## 19. The .env Configuration System

**File:** `.env.example` → copy to `.env`

Every behaviour can be configured without touching code.

| Variable | Default | What It Controls |
|---|---|---|
| `LLM_PROVIDER` | `ollama` | Which LLM to use: `ollama`, `openai`, `anthropic`, `openrouter` |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Where Ollama is running |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `ANTHROPIC_API_KEY` | — | Anthropic (Claude) API key |
| `OPENROUTER_API_KEY` | — | OpenRouter API key |
| `OPENROUTER_SITE_URL` | repo URL | Shown in OpenRouter dashboard |
| `OPENROUTER_APP_TITLE` | `Dexter AI Pentest` | Shown in OpenRouter dashboard |
| `AUTHORIZED_SCOPES` | `example.com,test.local,127.0.0.1,localhost` | Comma-separated list of targets the agent is allowed to scan |
| `LOOT_DIR` | `./loot` | Where notes and reports are saved |
| `SESSIONS_DIR` | `./sessions` | Where session data is saved |
| `TAVILY_API_KEY` | — | Tavily web search API key (optional; DDG fallback if not set) |
| `MCP_CONFIG` | `./mcp_servers.json` | Path to MCP server configuration file |

---

## 20. Full Component Map

Here is every file in the project and what it does:

```
super-duper-garbanzo/
│
├── 📄 README.md                    # Project overview and quickstart
├── 📄 GUIDE.md                     # Complete beginner's setup guide (17 sections)
├── 📄 CAPABILITIES.md              # This file — everything the project can do
├── 📄 SOLUTION.md                  # Original design notes
├── 📄 .env.example                 # All environment variables, documented
├── 📄 mcp_servers.json.example     # Example MCP server configuration
├── 📄 pyproject.toml               # pip install -e ".", console_scripts, extras
├── 📄 Makefile                     # install/run/test/docker-up targets
├── 📄 Dockerfile                   # Multi-stage Docker image with security tools
├── 📄 docker-compose.yml           # ui + api + cli + ollama services
├── 📄 decoder.py                   # (original repo utility)
├── 📁 loot/                        # ← All your findings and reports go here
│   └── .gitkeep
│
├── 📁 dexter_ai/
│   ├── __init__.py
│   ├── main.py                     # ★ LangGraph agent (Supervisor→Guardrail→Planner→Tool→Reflect)
│   ├── app.py                      # ★ Streamlit web UI
│   ├── cli.py                      # ★ Interactive CLI + one-shot run mode
│   ├── providers.py                # LLM factory (Ollama/OpenAI/Anthropic/OpenRouter)
│   ├── notes.py                    # Notes/loot persistence (JSON)
│   ├── requirements.txt            # Python dependencies
│   │
│   ├── 📁 agents/
│   │   ├── __init__.py             # Base Agent, AgentOrchestrator, ReAct framework, Thought, Guardrail
│   │   └── specialized.py          # Recon, Vulnerability, Exploitation, Reporting agents + Factory
│   │
│   ├── 📁 api/
│   │   ├── __init__.py
│   │   └── main.py                 # FastAPI REST backend (12 endpoints + WebSocket + SSE)
│   │
│   ├── 📁 db/
│   │   ├── __init__.py
│   │   └── memory.py               # SQLite conversation + session + thought + tool_result storage
│   │
│   ├── 📁 guardrails/
│   │   ├── __init__.py
│   │   ├── scope_validator.py      # ★ Target scope check (used by LangGraph brain)
│   │   └── security.py             # 7 guardrails for API agent system
│   │
│   ├── 📁 knowledge/
│   │   ├── __init__.py             # KnowledgeBase class (RAG context injection)
│   │   └── 📁 sources/
│   │       ├── web_methodology.md  # OWASP web pentest methodology
│   │       └── network_methodology.md # Network audit methodology
│   │
│   ├── 📁 mcp/
│   │   └── __init__.py             # MCPClient (add/remove/list/test/call MCP servers)
│   │
│   ├── 📁 playbooks/
│   │   ├── __init__.py
│   │   ├── recon.yaml              # Passive OSINT + active recon (no exploitation)
│   │   ├── web_pentest.yaml        # Full web app pentest (5 phases)
│   │   ├── network_audit.yaml      # Network infrastructure audit (5 phases)
│   │   └── ctf.yaml                # CTF challenge solver (4 phases)
│   │
│   ├── 📁 prompts/
│   │   ├── __init__.py
│   │   └── system_prompt.py        # SYSTEM_PROMPT, SUPERVISOR_PROMPT, REFLECTION_PROMPT, PLANNER_PROMPT, GUARDRAIL_PROMPT
│   │
│   ├── 📁 tools/
│   │   ├── __init__.py
│   │   ├── network_tools.py        # ★ Real tool wrappers (nmap/nikto/gobuster/nuclei/sqlmap/whois/dig/curl/web_search)
│   │   └── registry.py             # API-layer OO tool classes (NetworkScanner, VulnScanner, WHOIS, SSL, etc.)
│   │
│   └── 📁 ui/                      # React/TypeScript UI (Vite + Tailwind)
│       ├── index.html
│       ├── package.json
│       ├── tsconfig.json
│       └── 📁 src/
│           ├── App.tsx
│           ├── components/
│           │   ├── AgentList.tsx   # Agent status panel
│           │   ├── SystemInfo.tsx  # System status panel
│           │   ├── TaskInput.tsx   # Task submission form
│           │   └── ThoughtTrace.tsx # Real-time thought trace visualizer
│           ├── index.css
│           └── main.tsx
│
└── 📁 tests/
    ├── __init__.py
    └── test_core.py                # 56 unit tests (no LLM/network needed)
```

---

## Quick Summary

In one paragraph: **Dexter AI Pentest is an autonomous, multi-modal, AI-driven penetration testing platform.** It combines a LangGraph state-machine agent brain with real security tool execution (nmap, nikto, gobuster, nuclei, sqlmap, whois, dig), four specialized sub-agents (Recon/Vuln/Exploit/Report), seven safety guardrails, four LLM providers (including free local Ollama), four attack playbooks, a knowledge base for RAG context, web search, MCP server support, a full-featured CLI with an interactive REPL, a dark-themed Streamlit web UI, a FastAPI REST backend with WebSocket streaming, persistent JSON notes and SQLite session storage, Markdown report export, Docker Compose deployment, and a 56-test suite — all controlled by a single `.env` file.
