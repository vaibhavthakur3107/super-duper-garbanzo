# 🛡️ Cyber-Sentry AI

A production-ready autonomous Red Team Pentesting Agent built with LangGraph, Streamlit, and your choice of LLM provider.

![Python](https://img.shields.io/badge/Python-3.10+-green)
![LangGraph](https://img.shields.io/badge/LangGraph-0.0.20+-blue)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)
![Ollama](https://img.shields.io/badge/Ollama-Local-orange)
![OpenAI](https://img.shields.io/badge/OpenAI-API-412991)
![Anthropic](https://img.shields.io/badge/Anthropic-Claude-blueviolet)
![OpenRouter](https://img.shields.io/badge/OpenRouter-200%2B_Models-ff6b35)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-red)
![Tests](https://img.shields.io/badge/Tests-37_passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🎯 Overview

Cyber-Sentry is a multi-agent pentesting system that uses:
- **LangGraph** for agent orchestration with state machine architecture
- **Ollama** (Llama3/Mistral) for local LLM inference, **or** cloud providers:
  - **OpenAI** (GPT-4o, GPT-4-turbo, …)
  - **Anthropic** (Claude 3 Haiku/Sonnet/Opus)
  - **OpenRouter** (200+ models — GPT-4o, Claude, Llama 3, Mistral, Gemini, DeepSeek, …)
- **Streamlit** for interactive Thought Trace visualization
- **SQLite** for conversation memory storage
- **Docker** for isolated, reproducible execution with security tools pre-installed
- **Playbooks** for structured, repeatable attack scenarios
- **Notes/Loot** system to persist findings across sessions

## 📂 Project Structure

```
cyber_sentry/
├── main.py                    # LangGraph state machine
├── providers.py               # LLM provider constants & factory (no heavy deps)
├── cli.py                     # Interactive CLI entry point
├── notes.py                   # Notes / loot saving system
├── app.py                     # Streamlit frontend
├── requirements.txt           # Python dependencies
├── playbooks/
│   ├── web_pentest.yaml       # Full web application pentest
│   ├── network_audit.yaml     # Network infrastructure audit
│   ├── recon.yaml             # Reconnaissance only
│   └── ctf.yaml               # CTF challenge solver
├── agents/                    # Agent implementations
├── tools/
│   ├── network_tools.py       # Nmap, Nikto, Gobuster wrappers
│   └── registry.py            # Tool registry
├── guardrails/
│   ├── security.py            # Security guardrails
│   └── scope_validator.py     # Target scope validation
├── prompts/
│   └── system_prompt.py       # LLM prompts
├── db/
│   └── memory.py              # SQLite conversation memory
└── api/                       # REST API (FastAPI)

# Root-level infrastructure
Dockerfile                     # Multi-stage Docker build
docker-compose.yml             # Docker Compose (UI + API + Ollama + CLI)
Makefile                       # Quick commands: make run, make docker-up, make test
.env.example                   # All environment variables documented
tests/
└── test_core.py               # 37-test suite (no LLM required)
```

## 🚀 Quick Start

### Option A – Docker (Recommended, like PentestGPT)

```bash
# 1. Clone
git clone https://github.com/vaibhavthakur3107/super-duper-garbanzo.git
cd super-duper-garbanzo

# 2. Configure
cp .env.example .env
# Edit .env with your API key(s)

# 3. Start (includes Ollama + Streamlit UI + security tools)
docker compose up

# Open http://localhost:8501
```

### Option B – Local Python

```bash
# 1. Setup
make setup          # installs deps + creates .env from example

# 2. (Optional) pull Ollama model
make pull-ollama

# 3. Start Streamlit UI
make run            # → http://localhost:8501

# Or start interactive CLI
make run-cli
```

### Option C – Manual

```bash
cd super-duper-garbanzo

python3 -m venv venv
source venv/bin/activate

pip install -r cyber_sentry/requirements.txt
# Optional cloud providers:
pip install langchain-openai      # for OpenAI or OpenRouter
pip install langchain-anthropic   # for Anthropic

cp .env.example .env   # then edit with your keys
streamlit run cyber_sentry/app.py
```

## 🖥️ CLI Usage

Cyber-Sentry ships a `cyber-sentry` interactive CLI similar to PentestAgent:

```bash
# Interactive REPL (default)
python -m cyber_sentry.cli

# With target preset
python -m cyber_sentry.cli -t 192.168.1.1

# One-shot non-interactive run
python -m cyber_sentry.cli run -t example.com --playbook web_pentest --report

# List available playbooks
python -m cyber_sentry.cli playbooks

# Show saved notes/loot
python -m cyber_sentry.cli notes
```

### CLI Commands (interactive mode)

```
/agent <task>       Run autonomous agent on a task
/target <host>      Set target
/playbook <name>    Load and run a playbook
/notes              Show saved notes / loot
/report             Generate Markdown report for current session
/playbooks          List available playbooks
/tools              List available tools
/clear              Clear current session
/quit               Exit  (also /exit, /q)
/help               Show this help  (also /h, /?)
```

## 📋 Playbooks

Prebuilt attack playbooks for structured, repeatable assessments (like PentestAgent):

| Playbook | Category | Description |
|---|---|---|
| `web_pentest` | Web | Full black-box web application pentest |
| `network_audit` | Network | Infrastructure audit with port scanning and SSL review |
| `recon` | Reconnaissance | Passive OSINT + active enumeration, no exploitation |
| `ctf` | CTF | Capture The Flag challenge solver (Web, Forensics, Crypto) |

```bash
# Run a playbook
python -m cyber_sentry.cli run -t example.com --playbook web_pentest --report
```

## 🐳 Docker

```bash
# Build
make docker-build

# Start all services (UI + API + Ollama)
make docker-up

# Run CLI in container
make docker-cli

# Individual services
docker compose up ui          # Streamlit UI → http://localhost:8501
docker compose up api         # FastAPI → http://localhost:8000
docker compose run --rm cli   # Interactive CLI
```

The Docker image pre-installs **nmap, nikto, whois, dig, curl, wget, netcat**.


## 🧠 Architecture

### LangGraph State Machine

```
┌─────────────┐
│  Supervisor │ ──► Creates attack plan
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Guardrail  │ ──► Validates scope & input
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Planner   │ ──► Generates commands
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Tool     │ ──► Executes security tools
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Reflection │ ──► Analyzes results, plans next step
└──────┬──────┘
       │
       ▼ (loop until complete)
```

### Nodes

1. **Supervisor Node**: Analyzes target, creates attack plan
2. **Guardrail Node**: Validates target scope, prevents unauthorized access
3. **Planner Node**: Generates appropriate commands dynamically
4. **Tool Node**: Executes nmap, nikto, gobuster, etc.
5. **Reflection Node**: Analyzes output, decides next action

## 🔧 Configuration

### Environment Variables

```bash
# ── LLM Provider ──────────────────────────────────────────────────────────────
# Choose one: ollama | openai | anthropic | openrouter
# If not set, auto-detected from available API keys (openrouter > openai > anthropic > ollama)
export LLM_PROVIDER="ollama"

# Ollama (local) – default
export OLLAMA_BASE_URL="http://localhost:11434"   # optional, default shown
export DEFAULT_MODEL="llama3"

# OpenAI
export OPENAI_API_KEY="sk-..."

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenRouter  (gives access to 200+ models from OpenAI, Anthropic, Meta, Mistral, …)
# Get your key at https://openrouter.ai/keys
export OPENROUTER_API_KEY="sk-or-..."
export OPENROUTER_SITE_URL="https://yoursite.com"   # optional, shown in OR dashboard
export OPENROUTER_APP_TITLE="Cyber-Sentry AI"       # optional, shown in OR dashboard

# Set authorized scopes (comma-separated)
export AUTHORIZED_SCOPES="example.com,test.local,127.0.0.1,localhost"
```

### Authorized Scopes

Edit `guardrails/scope_validator.py` or use the sidebar in the UI to configure allowed targets.

## 🔌 LLM Providers

Cyber-Sentry supports four LLM backends. The active provider is chosen automatically from
available API keys, or you can set `LLM_PROVIDER` explicitly.

| Provider | Env Variable | Default Model | Notes |
|---|---|---|---|
| **Ollama** (default) | `OLLAMA_BASE_URL` | `llama3` | 100 % local, no API key needed |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o-mini` | Requires `pip install langchain-openai` |
| **Anthropic** | `ANTHROPIC_API_KEY` | `claude-3-haiku-20240307` | Requires `pip install langchain-anthropic` |
| **OpenRouter** | `OPENROUTER_API_KEY` | `openai/gpt-4o-mini` | 200+ models; requires `pip install langchain-openai` |

### Using OpenRouter

[OpenRouter](https://openrouter.ai) is a unified API that gives access to models from OpenAI,
Anthropic, Meta (Llama), Mistral, Google (Gemini), DeepSeek, and many more – all through a
single API key.

```bash
# 1. Get a free key at https://openrouter.ai/keys
export OPENROUTER_API_KEY="sk-or-..."

# 2. Install the required package (same as for OpenAI)
pip install langchain-openai

# 3. Run Cyber-Sentry – it will auto-detect OpenRouter
streamlit run app.py

# Or set the provider and model explicitly
export LLM_PROVIDER="openrouter"
# In the UI: select "openrouter" provider and choose any model from the dropdown
```

Popular free or low-cost OpenRouter models for pentesting tasks:
- `meta-llama/llama-3.1-8b-instruct:free` – fast, free tier
- `mistralai/mistral-7b-instruct:free` – fast, free tier
- `openai/gpt-4o-mini` – cost-effective, strong reasoning
- `deepseek/deepseek-chat` – excellent code/technical tasks

## 🛡️ Security Features

1. **Scope Validation**: Prevents scanning unauthorized targets
2. **Input Sanitization**: Blocks prompt injection attempts
3. **Command Validation**: Sanitizes shell commands
4. **Rate Limiting**: Prevents abuse
5. **Audit Logging**: Records all operations

## 🤖 Features

### Thought Trace UI

- Real-time visualization of agent reasoning
- Shows each step: Think → Act → Observe
- Filter by node type
- Expandable details

### Multi-Agent Architecture

- Specialized agents for different phases
- Dynamic command generation
- Self-correction via reflection

### Tool Integration

- **nmap**: Port scanning
- **nikto**: Web vulnerability scanning
- **gobuster**: Directory enumeration
- **nuclei**: Vulnerability scanning
- **sqlmap**: SQL injection testing
- **whois**: Domain information
- **dig**: DNS lookup

## 📝 Usage Example

1. Open Streamlit UI at http://localhost:8501
2. Enter target (e.g., `example.com`)
3. Select task type or use default
4. Click "Execute Assessment"
5. Watch the Thought Trace for real-time reasoning
6. Review findings in tool results

## 🔨 Development

### Running Tests

```bash
# Full test suite (37 tests, no LLM required)
make test
# or:
python -m pytest tests/ -v
```

### Adding New Tools

1. Add tool function to `tools/network_tools.py`
2. Register in `ToolRegistry`
3. Update prompts in `prompts/system_prompt.py`

### Adding New Playbooks

1. Create `cyber_sentry/playbooks/<name>.yaml` following the existing format
2. The playbook is immediately available via `/playbook <name>` in the CLI and `--playbook <name>` flag

## 📊 Comparison with Similar Projects

| Feature | Cyber-Sentry | PentestGPT | PentestAgent | Pentagi |
|---|:---:|:---:|:---:|:---:|
| Multi-LLM (Ollama/OpenAI/Anthropic/OpenRouter) | ✅ | ✅ | ✅ | ✅ |
| Docker-first deployment | ✅ | ✅ | ✅ | ✅ |
| Interactive CLI | ✅ | ✅ | ✅ | ✅ |
| Attack playbooks | ✅ | ❌ | ✅ | ❌ |
| Notes / loot saving | ✅ | ❌ | ✅ | ✅ |
| Markdown report export | ✅ | ❌ | ✅ | ✅ |
| Streamlit web UI | ✅ | ❌ | ❌ | ✅ |
| FastAPI REST backend | ✅ | ❌ | ❌ | ✅ |
| LangGraph state machine | ✅ | ❌ | ❌ | ❌ |
| Scope validation guardrail | ✅ | ✅ | ✅ | ✅ |
| Prompt injection protection | ✅ | ✅ | ✅ | ✅ |
| Test suite | ✅ | ✅ | ✅ | ✅ |

## 📜 License

MIT License – See [LICENSE](../LICENSE) for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only.
Always ensure you have written permission before scanning any target.
Unauthorized scanning is illegal and unethical.

## 🙏 Acknowledgments

Inspired by:
- [PentestGPT](https://github.com/GreyDGL/PentestGPT)
- [Pentagi](https://github.com/vxcontrol/pentagi)
- [Shannon](https://github.com/KeygraphHQ/shannon)
- [Pentest MCP Server](https://github.com/exjskdjsdfks/pentest-mcp-server)
- [PentestAgent](https://github.com/GH05TCREW/pentestagent)
- [HexStrike](https://github.com/CommonHuman-Lab/hexstrike-ai-community-edition)
