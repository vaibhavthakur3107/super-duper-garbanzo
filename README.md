# 🛡️ Cyber-Sentry AI

> AI-powered autonomous Red Team Pentesting Agent — similar to [PentestGPT](https://github.com/GreyDGL/PentestGPT), [Pentagi](https://github.com/vxcontrol/pentagi), [PentestAgent](https://github.com/GH05TCREW/pentestagent), and [Shannon](https://github.com/KeygraphHQ/shannon).

[![Python](https://img.shields.io/badge/Python-3.10+-green)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED)](Dockerfile)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agent_Graph-blue)](cyber_sentry/main.py)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)](tests/)

---

## 📖 Overview

Cyber-Sentry is a production-ready **multi-agent pentesting system** built with:

- **LangGraph** for agent orchestration (Supervisor → Guardrail → Planner → Tool → Reflection loop)
- **Ollama / OpenAI / Anthropic / OpenRouter** for LLM inference
- **Streamlit** web UI with live Thought-Trace visualisation
- **FastAPI** REST + WebSocket backend
- **Interactive CLI** (REPL with `/agent`, `/playbook`, `/notes`, `/report` commands)
- **Attack Playbooks** (web pentest, network audit, recon, CTF)
- **Notes / Loot** persistence across sessions
- **MCP (Model Context Protocol)** integration for external tool servers
- **Docker** for isolated, reproducible execution

For detailed documentation see [`cyber_sentry/README.md`](cyber_sentry/README.md).

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
python -m cyber_sentry.cli                          # interactive REPL
python -m cyber_sentry.cli -t 192.168.1.1           # pre-set target
python -m cyber_sentry.cli run -t example.com \
    --playbook web_pentest --report                  # one-shot + report

# MCP server management
python -m cyber_sentry.cli mcp list
python -m cyber_sentry.cli mcp add nmap npx gc-nmap-mcp
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

## 🧩 MCP Support

Cyber-Sentry supports [Model Context Protocol](https://modelcontextprotocol.io/) servers, letting you plug in any MCP-compatible tool (nmap, Metasploit, Burp Suite extensions, etc.).

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

Place domain knowledge, CVE notes, or methodologies in `cyber_sentry/knowledge/sources/` — they are injected into the agent context automatically at runtime.

---

## ⚠️ Disclaimer

For educational and authorised security testing only. Always obtain written permission before scanning any target.

