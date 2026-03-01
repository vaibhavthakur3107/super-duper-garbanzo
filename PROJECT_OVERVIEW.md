# 🛡️ Cyber-Sentry AI — Complete Project Overview

> **AI-Powered Red Team Pentesting Agent** built with LangGraph multi-agent orchestration.

---

## 📋 Table of Contents

1. [What Is Cyber-Sentry AI?](#what-is-cyber-sentry-ai)
2. [What Can It Do?](#what-can-it-do)
3. [How Does It Work?](#how-does-it-work)
4. [Architecture & Tech Stack](#architecture--tech-stack)
5. [Features at a Glance](#features-at-a-glance)
6. [Getting Started](#getting-started)
7. [CLI Usage & Commands](#cli-usage--commands)
8. [Web UI (Streamlit)](#web-ui-streamlit)
9. [REST API (FastAPI)](#rest-api-fastapi)
10. [Testing It on testphp.vulnweb.com](#testing-it-on-testphpvulnwebcom)
11. [Project Structure](#project-structure)
12. [Sample CLI Output](#sample-cli-output)
13. [Hackathon Q&A — Expected Questions & Answers](#hackathon-qa--expected-questions--answers)
14. [Why This Project Stands Out](#why-this-project-stands-out)

---

## What Is Cyber-Sentry AI?

**Cyber-Sentry AI** is an autonomous red team penetration testing agent that uses **AI (Large Language Models)** to plan, execute, and analyze security assessments — just like a human penetration tester would, but automated.

Think of it like this:
- A human pentester thinks → picks a tool → runs it → analyzes results → decides next step.
- Cyber-Sentry AI does the **exact same loop**, but powered by an LLM (like GPT-4, Claude, Llama 3, or 200+ models via OpenRouter).

It uses **LangGraph** (a state-machine framework for AI agents) to orchestrate a multi-agent pipeline:

```
Supervisor → Guardrail → Planner → Tool Executor → Reflection → (loop or finish)
```

---

## What Can It Do?

### 🔍 Reconnaissance & OSINT
- Subdomain enumeration (amass, subfinder, fierce)
- DNS analysis (dig, dnsenum, dnsrecon)
- WHOIS lookups
- Email harvesting (theHarvester)
- Web technology fingerprinting (whatweb, httpx)
- Historical URL fetching (waybackurls, gau)

### 🌐 Web Application Testing
- Directory brute-forcing (gobuster, feroxbuster, ffuf, dirsearch)
- Vulnerability scanning (nuclei, nikto)
- SQL injection testing (sqlmap, nosqlmap)
- XSS detection (dalfox, xsstrike)
- WordPress scanning (wpscan)
- SSL/TLS analysis (testssl, sslscan)
- WAF detection (wafw00f)
- CORS misconfiguration checks
- Security header analysis

### 🔐 Authentication & Credential Testing
- Password brute-forcing (hydra, medusa)
- Hash cracking (john, hashcat)
- Credential discovery

### ☁️ Cloud & Container Security
- AWS/Azure/GCP auditing (prowler, scout, pacu)
- Container scanning (trivy, falco)
- Kubernetes hunting (kube-hunter)
- Infrastructure-as-code checks (checkov, terraform-compliance)

### 🧬 Binary Analysis & Forensics
- Memory forensics (volatility3)
- Binary analysis (radare2, binwalk, checksec)
- Steganography detection (steghide, zsteg)
- Metadata extraction (exiftool)

### 📱 Mobile Security
- Android app analysis (apktool, jadx, frida, drozer)
- iOS testing (objection, ios-deploy)

### 📡 Wireless Security
- WiFi auditing (aircrack-ng, wifite, kismet)
- Network MITM (bettercap, responder)

### 📊 Reporting
- Auto-generated Markdown reports with findings, risk scores, and remediation
- Exploitation guides and attack chain analysis
- Persistent notes/loot across sessions

---

## How Does It Work?

### The AI Agent Loop (ReAct Pattern)

```
┌──────────────────────────────────────────────────────┐
│                    USER INPUT                        │
│  "Scan testphp.vulnweb.com for web vulnerabilities"  │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
         ┌─────────────────────────┐
         │      SUPERVISOR         │  ← LLM analyzes task
         │  (Plans attack steps)   │     and creates a plan
         └────────────┬────────────┘
                      │
                      ▼
         ┌─────────────────────────┐
         │      GUARDRAIL          │  ← Checks if target is
         │  (Scope validation)     │     authorized + safe
         └────────────┬────────────┘
                      │
                      ▼
         ┌─────────────────────────┐
         │       PLANNER           │  ← LLM picks the right
         │  (Selects tool + cmd)   │     tool and parameters
         └────────────┬────────────┘
                      │
                      ▼
         ┌─────────────────────────┐
         │    TOOL EXECUTOR        │  ← Runs nmap, nikto,
         │  (Runs security tool)   │     sqlmap, etc.
         └────────────┬────────────┘
                      │
                      ▼
         ┌─────────────────────────┐
         │      REFLECTION         │  ← LLM analyzes output
         │  (Analyzes results)     │     and decides next step
         └────────────┬────────────┘
                      │
               ┌──────┴──────┐
               │ More steps?  │
               └──────┬──────┘
                 Yes ↙     ↘ No
           (back to       ┌──────────┐
            Planner)      │  REPORT  │
                          │  Output  │
                          └──────────┘
```

### Key Concept: The agent **thinks before it acts**

1. **Think**: "The target is a PHP web application. I should start with reconnaissance."
2. **Act**: Runs `nmap -sV -sC testphp.vulnweb.com` to discover open ports/services.
3. **Observe**: "Port 80 is open running Apache/PHP. Let me scan for web vulnerabilities."
4. **Think**: "I should run nikto and nuclei for vulnerability scanning."
5. **Act**: Runs `nikto -h http://testphp.vulnweb.com`
6. **Observe**: "Found SQL injection, XSS vulnerabilities. Let me document these."
7. **Report**: Generates a detailed Markdown report with findings and remediation.

---

## Architecture & Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Agent Orchestration** | LangGraph | Multi-agent state machine (Supervisor→Guardrail→Planner→Tool→Reflection) |
| **LLM Integration** | LangChain | Unified interface to all LLM providers |
| **Local AI** | Ollama (Llama 3) | Free, private, runs on your machine |
| **Cloud AI** | OpenAI, Anthropic, OpenRouter | GPT-4, Claude, 200+ models |
| **Web UI** | Streamlit | Interactive dashboard with thought-trace visualization |
| **REST API** | FastAPI + WebSockets | Programmatic access, real-time streaming |
| **CLI** | Custom REPL | Interactive terminal with colored output |
| **Security Tools** | nmap, nikto, nuclei, sqlmap, etc. | 151+ tool wrappers |
| **Database** | SQLite | Conversation memory persistence |
| **Containerization** | Docker + Docker Compose | One-command deployment |
| **Safety** | Custom Guardrails | Scope validation, prompt injection detection, rate limiting |

### LLM Provider Support

| Provider | Models | Cost | Setup |
|----------|--------|------|-------|
| **Ollama** (default) | Llama 3, Mistral, CodeLlama | Free (local) | `ollama pull llama3` |
| **OpenAI** | GPT-4o, GPT-4o-mini | Pay-per-use | API key |
| **Anthropic** | Claude 3.5, Claude 3 Haiku | Pay-per-use | API key |
| **OpenRouter** | 200+ models | Pay-per-use | Free API key |

---

## Features at a Glance

| Feature | Details |
|---------|---------|
| 🔧 **151+ Security Tools** | Wrappers for nmap, nikto, nuclei, sqlmap, gobuster, and 146 more |
| 🤖 **12+ AI Agents** | Specialized agents for recon, vuln scanning, exploitation, reporting, etc. |
| 📋 **7 Attack Playbooks** | Pre-built workflows: web_pentest, network_audit, recon, ctf, bugbounty, cloud_security, binary_forensics |
| 🧠 **5 Knowledge Sources** | Built-in methodology guides for web, network, OSINT, cloud, binary analysis |
| 🛡️ **7 Security Guardrails** | Scope validation, dangerous action blocking, rate limiting, input validation, legal compliance, output filtering, audit logging |
| 💾 **Smart Caching** | Thread-safe LRU cache with per-entry TTL for tool results |
| 📝 **Notes/Loot System** | Persistent findings storage with categories (credential, vulnerability, finding, artifact) |
| 🔌 **MCP Integration** | Model Context Protocol for connecting external tool servers |
| 📊 **Auto Reporting** | Markdown reports with risk scoring, exploitation guides, remediation templates |
| 🐳 **Docker Ready** | Multi-service Docker Compose (UI + API + CLI + Ollama) |

---

## Getting Started

### Option 1: Local Python (Quick Start)

```bash
# Clone the repository
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo

# Install dependencies
pip install -e ".[dev]"

# (Optional) Set up environment
cp .env.example .env
# Edit .env with your API keys, or use Ollama (free, local)

# Run the CLI
python -m cyber_sentry.cli

# Or use the Makefile shortcuts
make run-cli    # Interactive CLI
make run        # Streamlit Web UI (http://localhost:8501)
make run-api    # FastAPI backend (http://localhost:8000)
make test       # Run all tests
```

### Option 2: Docker (Recommended for Full Stack)

```bash
cp .env.example .env
# Edit .env with your settings

docker compose up          # Starts UI + API + Ollama
# Streamlit UI: http://localhost:8501
# FastAPI:      http://localhost:8000

docker compose run --rm cli  # Interactive CLI
```

### Option 3: Ollama Only (Completely Free)

```bash
# Install Ollama: https://ollama.ai
ollama pull llama3

# Run Cyber-Sentry
python -m cyber_sentry.cli
```

---

## CLI Usage & Commands

### Interactive Mode (REPL)

```
⚡cyber-sentry> /help

═══ COMMANDS ═══

Agent & Execution
  /agent <task>        Run autonomous agent on task
  /playbook <name>     Load and run a playbook
  /target <host>       Set target

Reporting & Intel
  /notes               Show saved notes / loot
  /report              Generate Markdown report

Discovery
  /playbooks           List available playbooks
  /tools               List available tools (151+)
  /agents              List AI agents (12+)

System
  /status              Show system status dashboard
  /dashboard           Detailed status dashboard
  /mcp list            List configured MCP servers
  /clear               Clear current session

Navigation
  /help                Show this help
  /quit                Exit
```

### Example Session

```
⚡cyber-sentry> /target testphp.vulnweb.com
[✓] Target set: testphp.vulnweb.com

⚡cyber-sentry[testphp.vulnweb.com]> /playbook web_pentest
[*] Starting agent on target: testphp.vulnweb.com
[*] Task: Comprehensive web application penetration test
[*] Provider: ollama / Model: llama3

  ... (agent thinks, plans, runs tools, analyzes results) ...

[✓] Assessment complete. 8 reasoning steps recorded in 45.2s.

⚡cyber-sentry[testphp.vulnweb.com]> /notes
  [VULNERABILITY] SQL injection found in login form
  [VULNERABILITY] XSS reflected in search parameter
  [FINDING] Apache/2.4.7 detected, outdated version
  [FINDING] Missing security headers: CSP, HSTS

⚡cyber-sentry[testphp.vulnweb.com]> /report
[✓] Report saved to: loot/report_20260301_060816.md
```

### One-Shot Mode

```bash
# Run a specific playbook and generate report
python -m cyber_sentry.cli run -t testphp.vulnweb.com --playbook web_pentest --report

# Custom task
python -m cyber_sentry.cli run -t testphp.vulnweb.com --task "Check for SQL injection"
```

---

## Web UI (Streamlit)

The Streamlit dashboard provides:
- **Target input** with task selection
- **Real-time thought trace** visualization (see the AI think step by step)
- **Security headers analysis** panel
- **Metrics dashboard** (tools used, findings count, risk score)

Start it with:
```bash
make run
# or
streamlit run cyber_sentry/app.py
```

Access at **http://localhost:8501**

---

## REST API (FastAPI)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | System info |
| `GET /status` | GET | System status with agents and tools |
| `POST /tasks` | POST | Execute a new pentesting task |
| `GET /tasks/{id}` | GET | Get task results |
| `GET /agents` | GET | List registered agents |
| `GET /tools` | GET | List available tools |
| `GET /guardrails` | GET | List security guardrails |
| `GET /health` | GET | Health check |
| `WS /ws/thoughts` | WebSocket | Real-time thought streaming |

Start it with:
```bash
make run-api
# or
uvicorn cyber_sentry.api.main:app --reload
```

Access at **http://localhost:8000** (API docs at `/docs`)

---

## Testing It on testphp.vulnweb.com

`testphp.vulnweb.com` is a **legal, authorized** test website by Acunetix designed for security testing practice. It has intentional vulnerabilities like SQL injection, XSS, file inclusion, etc.

### What Cyber-Sentry AI Finds

When you run `web_pentest` playbook against `testphp.vulnweb.com`, the agent typically discovers:

| Finding | Type | Severity |
|---------|------|----------|
| SQL injection in login/search forms | Vulnerability | Critical |
| Reflected XSS in search parameter | Vulnerability | High |
| Missing Content-Security-Policy header | Finding | Medium |
| Missing Strict-Transport-Security | Finding | Medium |
| Missing X-Content-Type-Options | Finding | Low |
| Outdated Apache/PHP version | Finding | Medium |
| Directory listing enabled | Vulnerability | Medium |
| CORS misconfiguration | Vulnerability | Medium |
| Multiple form inputs without CSRF tokens | Finding | Medium |

### Browser Agent Analysis

The built-in browser agent (no Selenium required) can:

```python
from cyber_sentry.browser_agent import BrowserAgent
agent = BrowserAgent()

# Analyze security headers
headers = agent.analyze_security_headers("http://testphp.vulnweb.com/")
# Result: grade "F", missing CSP, HSTS, X-Frame-Options, etc.

# Detect technologies
tech = agent.detect_technologies("http://testphp.vulnweb.com/")
# Result: PHP, Apache detected

# Find forms (potential injection points)
forms = agent.find_forms("http://testphp.vulnweb.com/")
# Result: login form, search form, etc.

# Check CORS configuration
cors = agent.check_cors("http://testphp.vulnweb.com/")
# Result: CORS configuration details
```

---

## Project Structure

```
super-duper-garbanzo/
├── cyber_sentry/                  # Main package
│   ├── __init__.py                # Package init (version = 2.0.0)
│   ├── main.py                    # LangGraph core — state machine orchestration
│   ├── cli.py                     # Interactive REPL command-line interface
│   ├── app.py                     # Streamlit web UI frontend
│   ├── autonomous.py              # Autonomous engine with specialist delegation
│   ├── browser_agent.py           # Web page analysis (stdlib, no Selenium needed)
│   ├── cache.py                   # Smart LRU cache with TTL
│   ├── cve_intel.py               # CVE intelligence database (10+ built-in CVEs)
│   ├── notes.py                   # Notes/loot persistence manager
│   ├── process_manager.py         # Subprocess lifecycle management
│   ├── providers.py               # LLM provider factory (Ollama/OpenAI/Anthropic/OpenRouter)
│   ├── reporting.py               # Detailed report generator
│   ├── requirements.txt           # Python dependencies
│   ├── README.md                  # Module documentation
│   │
│   ├── agents/                    # AI agent implementations
│   │   ├── __init__.py            # Agent base classes, orchestrator, Tool, Guardrail ABCs
│   │   ├── ai_agents.py           # LLM-based decision engine, 12+ specialized agents
│   │   └── specialized.py         # ReconAgent, VulnAgent, ExploitAgent, ReportAgent
│   │
│   ├── tools/                     # Security tool wrappers
│   │   ├── network_tools.py       # 151+ tool functions + ToolRegistry
│   │   └── registry.py            # OOP tool registry with async execution
│   │
│   ├── guardrails/                # Safety & validation
│   │   ├── scope_validator.py     # Target whitelist (CIDR, domains, private IPs)
│   │   └── security.py            # 7 guardrails (scope, dangerous action, rate limit, etc.)
│   │
│   ├── prompts/                   # LLM system prompts
│   │   └── system_prompt.py       # Supervisor, planner, reflection prompts
│   │
│   ├── db/                        # Data persistence
│   │   └── memory.py              # SQLite conversation memory
│   │
│   ├── mcp/                       # Model Context Protocol
│   │   └── __init__.py            # MCP client for external tool servers
│   │
│   ├── knowledge/                 # RAG knowledge base
│   │   ├── __init__.py            # KnowledgeBase class
│   │   └── sources/               # 5 methodology documents
│   │
│   ├── playbooks/                 # Attack workflow definitions
│   │   ├── web_pentest.yaml
│   │   ├── network_audit.yaml
│   │   ├── recon.yaml
│   │   ├── ctf.yaml
│   │   ├── bugbounty.yaml
│   │   ├── cloud_security.yaml
│   │   └── binary_forensics.yaml
│   │
│   ├── api/                       # REST API backend
│   │   └── main.py                # FastAPI app with WebSocket support
│   │
│   └── ui/                        # UI components
│
├── tests/
│   └── test_core.py               # 165 tests (all offline, no LLM needed)
│
├── loot/                          # Findings output directory
├── decoder.py                     # Cipher decoder utility (CTF helper)
├── pyproject.toml                 # Package configuration
├── Dockerfile                     # Multi-stage Docker build
├── docker-compose.yml             # 4 services: UI, API, CLI, Ollama
├── Makefile                       # Quick commands (make run, make test, etc.)
├── .env.example                   # Environment variable template
├── mcp_servers.json.example       # MCP server configuration template
│
├── README.md                      # Project overview
├── CAPABILITIES.md                # Feature capabilities
├── COMPARISON.md                  # Comparison with similar tools
├── GUIDE.md                       # Usage guide
├── SOLUTION.md                    # Solution architecture
└── PROJECT_OVERVIEW.md            # ← THIS FILE (comprehensive reference)
```

---

## Sample CLI Output

### Banner & Startup

```
   ██████╗██╗   ██╗██████╗ ███████╗██████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
  ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
  ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝

  ────────────────────────────────────────────────────────
  ▸ AI-Powered Red Team Pentesting Agent
  ▸ v2.0.0  Tools: 151+  Agents: 12+  Status: READY
  ────────────────────────────────────────────────────────

  Type /help for commands, /quit to exit.
```

### Status Dashboard

```
  ╔════════════════════════════════════════════════════════╗
  ║  CYBER-SENTRY AI v2.0.0 — STATUS DASHBOARD           ║
  ╠════════════════════════════════════════════════════════╣
  ║  🎯 Target: testphp.vulnweb.com   Status: ACTIVE     ║
  ║  🔧 Tools:  151+                  Agents: 12+        ║
  ║  📋 Notes:  5                     Sessions: 1        ║
  ║  💾 Cache:  3 hits / 2 misses     Provider: ollama   ║
  ╚════════════════════════════════════════════════════════╝
```

### Playbooks List

```
  PLAYBOOKS

  ▸ binary_forensics      [forensics]   Binary analysis and memory forensics
  ▸ bugbounty             [offensive]   Bug bounty hunting workflow
  ▸ cloud_security        [cloud]       Cloud infrastructure security audit
  ▸ ctf                   [ctf]         CTF challenge solving
  ▸ network_audit         [network]     Network security audit
  ▸ recon                 [reconnaissance] Passive and active reconnaissance
  ▸ web_pentest           [web]         Comprehensive web application pentest
```

### Agent Task Execution

```
⚡cyber-sentry[testphp.vulnweb.com]> /agent Scan for web vulnerabilities

[*] Starting agent on target: testphp.vulnweb.com
[*] Task: Scan for web vulnerabilities
[*] Provider: ollama / Model: llama3

  [SUPERVISOR] Analyzing target and creating attack plan...
  [GUARDRAIL]  ✓ Target authorized — testphp.vulnweb.com in scope
  [PLANNER]    Selected nmap_scan for reconnaissance
  [TOOL]       Executing nmap -sV -sC -T4 testphp.vulnweb.com
  [REFLECTION] Port 80 open (Apache/PHP). Proceeding to web vuln scan...
  [PLANNER]    Selected nikto_scan for vulnerability detection
  [TOOL]       Executing nikto -h http://testphp.vulnweb.com
  [REFLECTION] Multiple vulnerabilities found. Documenting findings...

[✓] Assessment complete. 8 reasoning steps recorded in 45.2s.
```

### Tools Arsenal (partial)

```
  TOOL ARSENAL — 151 tools across 14 categories

  ┌── RECONNAISSANCE (24 tools)
  │──────────────────────────────────────────────────────
  │ nmap_scan              Network port and service scanning
  │ rustscan               Ultra-fast port scanner
  │ masscan                High-speed Internet-scale scanner
  │ amass_enum             Subdomain enumeration (OWASP)
  │ subfinder              Fast passive subdomain discovery
  │ ...
  └──────────────────────────────────────────────────────

  ┌── VULNERABILITY (20 tools)
  │──────────────────────────────────────────────────────
  │ nikto_scan             Web server vulnerability scanner
  │ nuclei_scan            Template-based vulnerability scanner
  │ sqlmap_scan            SQL injection testing
  │ dalfox                 Advanced XSS scanner
  │ ...
  └──────────────────────────────────────────────────────
```

### Test Results

```
$ make test
========================= test session starts =========================
platform linux -- Python 3.12.3, pytest-9.0.2
collected 165 items

tests/test_core.py::TestScopeValidator (11 tests)          PASSED
tests/test_core.py::TestNotesManager (9 tests)              PASSED
tests/test_core.py::TestProviderConstants (5 tests)         PASSED
tests/test_core.py::TestPlaybooks (6 tests)                 PASSED
tests/test_core.py::TestNetworkToolHelpers (7 tests)        PASSED
tests/test_core.py::TestMCPClient (11 tests)                PASSED
tests/test_core.py::TestKnowledgeBase (7 tests)             PASSED
tests/test_core.py::TestExpandedToolArsenal (30+ tests)     PASSED
tests/test_core.py::TestSmartCache (7 tests)                PASSED
tests/test_core.py::TestCVEIntelligence (6 tests)           PASSED
tests/test_core.py::TestProcessManager (3 tests)            PASSED
tests/test_core.py::TestBrowserAgent (2 tests)              PASSED
tests/test_core.py::TestAIAgents (4 tests)                  PASSED
tests/test_core.py::TestReportingEngine (6 tests)           PASSED
tests/test_core.py::TestAutonomousEngine (6 tests)          PASSED
tests/test_core.py::TestCLIEnhancements (11 tests)          PASSED

========================= 165 passed in 0.48s =========================
```

---

## Hackathon Q&A — Expected Questions & Answers

### 🔹 Q1: "What problem does your project solve?"

**A:** Manual penetration testing is time-consuming, expensive, and requires deep expertise. Cyber-Sentry AI automates the entire pentest workflow using AI agents that think, plan, and execute security assessments autonomously — making security testing accessible and faster.

---

### 🔹 Q2: "How is this different from just running nmap or Burp Suite manually?"

**A:** Great question! The key difference is **intelligence and autonomy**:
- Manual tools: You run one tool, read the output, decide what to do next.
- Cyber-Sentry AI: The AI agent **analyzes the output**, **decides the next step**, and **chains tools together** intelligently. It's like having an AI security expert making decisions for you.

For example, if nmap finds port 80 open with PHP, the AI automatically decides to run nikto for web vulnerabilities, then sqlmap if it detects potential SQL injection points.

---

### 🔹 Q3: "What LLM/AI model does it use?"

**A:** It supports **4 providers** with any model:
- **Ollama** (default): Free, local, private — runs Llama 3, Mistral, etc. on your machine
- **OpenAI**: GPT-4o, GPT-4o-mini
- **Anthropic**: Claude 3.5 Sonnet, Claude 3 Haiku
- **OpenRouter**: 200+ models via one API key (free tier available)

You can switch providers with a single environment variable or CLI flag.

---

### 🔹 Q4: "Is this legal? How do you handle authorization?"

**A:** Security is our top priority. The system has **7 built-in guardrails**:

1. **Scope Validation**: Only scans targets you explicitly authorize (whitelist-based)
2. **Dangerous Action Blocking**: Blocks destructive operations
3. **Rate Limiting**: Prevents abuse
4. **Input Validation**: Blocks injection attempts
5. **Legal Compliance**: Blocks government/critical infrastructure scanning
6. **Output Filtering**: Redacts sensitive data (passwords, SSNs, API keys)
7. **Audit Logging**: Logs all operations

The agent **refuses to scan** any target not in the authorized scope. By default, only `localhost`, `example.com`, `test.local`, private IPs, and `testphp.vulnweb.com` (legal test site) are allowed.

---

### 🔹 Q5: "What is LangGraph and why did you choose it?"

**A:** LangGraph is a framework by LangChain for building **stateful, multi-agent AI workflows** as directed graphs. I chose it because:
- It allows defining a **state machine** where each node is an agent step
- It supports **conditional routing** (the AI decides what to do next)
- It handles **iteration loops** (the agent keeps going until it's done)
- It's production-ready with built-in checkpointing and error handling

Our graph: `Supervisor → Guardrail → Planner → Tool → Reflection → (loop or end)`

---

### 🔹 Q6: "How many tools does it support?"

**A:** **151+ security tools** across 14 categories:
- Reconnaissance (24): nmap, rustscan, masscan, amass, subfinder, etc.
- Web Application (20): nikto, nuclei, gobuster, sqlmap, dalfox, etc.
- OSINT (16): sherlock, recon-ng, trufflehog, shodan, etc.
- Exploitation (12): msfconsole, searchsploit, impacket, etc.
- Cloud (11): prowler, trivy, kube-hunter, checkov, etc.
- And 9 more categories...

All tools have **safe wrappers** with command sanitization to prevent injection.

---

### 🔹 Q7: "Did you test it on a real target?"

**A:** Yes! We tested against `testphp.vulnweb.com`, which is a **legal, authorized** test website by Acunetix designed specifically for security testing practice. It has intentional vulnerabilities (SQL injection, XSS, etc.) that our agent successfully detects and reports.

---

### 🔹 Q8: "How does the multi-agent architecture work?"

**A:** We have **12+ specialized AI agents**, each with a specific role:
- **IntelligentDecisionEngine**: Picks the optimal tool for each task
- **BugBountyWorkflowManager**: Manages end-to-end bug bounty workflows
- **CTFWorkflowManager**: Solves CTF challenges adaptively
- **CVEIntelligenceManager**: CVE lookup and exploit correlation
- **AIExploitGenerator**: Generates and validates exploits
- **VulnerabilityCorrelator**: Correlates findings across scans
- **TechnologyDetector**: Fingerprints tech stacks
- And more...

These agents are orchestrated by the **LangGraph state machine** and can be combined for complex multi-step assessments.

---

### 🔹 Q9: "What's the tech stack?"

**A:**
- **Python 3.10+** — Core language
- **LangGraph + LangChain** — AI agent orchestration
- **Ollama / OpenAI / Anthropic / OpenRouter** — LLM providers
- **Streamlit** — Web dashboard
- **FastAPI + WebSockets** — REST API with real-time streaming
- **SQLite** — Conversation memory
- **Docker + Docker Compose** — Containerized deployment
- **pytest** — 165 automated tests

---

### 🔹 Q10: "What makes this hackathon-worthy?"

**A:**
1. **Novel approach**: Uses AI agents (not just scripts) for pentesting — the AI thinks and decides
2. **Full stack**: CLI + Web UI + REST API + Docker — complete product
3. **151+ tools**: Most comprehensive tool integration in an AI pentest agent
4. **Multi-provider**: Works with free local models (Ollama) or cloud (GPT-4, Claude)
5. **Safety first**: 7 guardrails, scope validation, prompt injection detection
6. **Production ready**: 165 tests, Docker deployment, auto-reporting
7. **MCP support**: Model Context Protocol for extensibility
8. **Knowledge base**: Built-in methodology guides for AI context

---

### 🔹 Q11: "How do you prevent the AI from going rogue?"

**A:** Multiple layers of protection:
- **Scope validation**: Only targets you authorize
- **Command sanitization**: Blocks `rm -rf`, `sudo`, pipe-to-shell, etc.
- **Iteration limits**: Max 20 iterations per assessment
- **Guardrails**: 7 safety checks before every action
- **Prompt injection detection**: Blocks "ignore previous instructions" attacks
- **Allowed tool whitelist**: Only approved security tools can be executed

---

### 🔹 Q12: "Can you demo it live?"

**A:** Yes! Three ways:
1. **CLI**: `python -m cyber_sentry.cli -t testphp.vulnweb.com` → `/playbook web_pentest`
2. **Web UI**: `make run` → Open http://localhost:8501 → Enter target → Start scan
3. **API**: `curl -X POST http://localhost:8000/tasks -d '{"task":"scan","target":"testphp.vulnweb.com"}'`

---

### 🔹 Q13: "What was the hardest part?"

**A:** Designing the **reflection loop** — making the AI agent decide when to continue scanning vs. when it has enough findings. The agent needs to balance thoroughness with efficiency. We solved this with a conditional routing system in LangGraph where the reflection node analyzes results and the router decides whether to loop back to the planner or finish.

---

### 🔹 Q14: "What are the future plans?"

**A:**
- **Real-time collaboration**: Multiple users working on the same assessment
- **Metasploit integration**: Deeper exploitation capabilities
- **Custom playbook builder**: Visual editor for creating attack workflows
- **AI-powered remediation**: Automatically suggest and validate fixes
- **Compliance mapping**: Map findings to OWASP, NIST, PCI-DSS standards
- **Plugin system**: Community-contributed tool wrappers and agents

---

### 🔹 Q15: "How do you handle rate limiting and not getting blocked?"

**A:** The built-in `RateLimitGuardrail` enforces a maximum of 60 requests per minute per agent. The AI is also instructed via system prompts to be respectful of target resources. Additionally, tools like nmap use the `-T4` timing template (aggressive but not flooding), and the agent can detect and adapt to rate limiting.

---

## Why This Project Stands Out

| Aspect | Cyber-Sentry AI | Traditional Tools |
|--------|-----------------|-------------------|
| **Intelligence** | AI decides next steps | You decide manually |
| **Autonomy** | Runs end-to-end | One tool at a time |
| **Tool Count** | 151+ integrated | One per tool |
| **Reporting** | Auto-generated | Manual |
| **Learning** | Knowledge base + LLM | None |
| **Safety** | 7 guardrails | Up to you |
| **Interface** | CLI + Web + API | Usually CLI only |
| **Multi-model** | 200+ LLMs supported | N/A |

---

*This document is part of the [Cyber-Sentry AI](https://github.com/vaibhavthakur3107/super-duper-garbanzo) project.*
*Version 2.0.0 — 151+ tools, 12+ agents, 7 playbooks, 165 tests.*
