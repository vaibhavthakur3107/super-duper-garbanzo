# 🛡️ Cyber-Sentry AI

A production-ready autonomous Red Team Pentesting Agent built with LangGraph, Ollama (local LLM), and Streamlit.

![Python](https://img.shields.io/badge/Python-3.10+-green)
![LangGraph](https://img.shields.io/badge/LangGraph-0.0.20+-blue)
![Ollama](https://img.shields.io/badge/Ollama-Local-orange)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-red)

## 🎯 Overview

Cyber-Sentry is a multi-agent pentesting system that uses:
- **LangGraph** for agent orchestration with state machine architecture
- **Ollama** (Llama3/Mistral) for local LLM inference
- **Streamlit** for interactive Thought Trace visualization
- **SQLite** for conversation memory storage

## 📂 Project Structure

```
cyber_sentry/
├── main.py                    # LangGraph state machine
├── app.py                     # Streamlit frontend
├── requirements.txt           # Python dependencies
├── agents/                    # Agent implementations (legacy)
├── tools/
│   ├── network_tools.py      # Nmap, Nikto, Gobuster wrappers
│   └── registry.py           # Tool registry
├── guardrails/
│   ├── security.py           # Security guardrails
│   └── scope_validator.py    # Target scope validation
├── prompts/
│   └── system_prompt.py      # LLM prompts
├── db/
│   └── memory.py             # SQLite conversation memory
└── api/                      # REST API (optional)
```

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+**
2. **Ollama** installed and running locally
3. **Security tools** (optional): nmap, nikto, gobuster, nuclei

### Installation

```bash
# Clone and navigate to project
cd cyber_sentry

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Install Ollama

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve

# Pull a model
ollama pull llama3
```

### Install Security Tools (Optional)

```bash
# Ubuntu/Debian
sudo apt-get install nmap nikto

# Or use Docker for isolated execution
```

## 🎮 Running the Application

### Start Streamlit UI

```bash
cd cyber_sentry
streamlit run app.py
```

Open http://localhost:8501 in your browser.

### CLI Usage

```bash
python main.py
```

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
# Set authorized scopes (comma-separated)
export AUTHORIZED_SCOPES="example.com,test.local,127.0.0.1,localhost"

# Ollama URL (if remote)
export OLLAMA_BASE_URL="http://localhost:11434"

# Model selection
export DEFAULT_MODEL="llama3"
```

### Authorized Scopes

Edit `guardrails/scope_validator.py` or use the sidebar in the UI to configure allowed targets.

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
# Test scope validation
python -c "from guardrails.scope_validator import validate_scope; print(validate_scope('example.com'))"

# Test tool execution
python -c "from tools.network_tools import nmap_scan; print(nmap_scan('nmap -sV localhost', 'localhost'))"
```

### Adding New Tools

1. Add tool function to `tools/network_tools.py`
2. Register in `ToolRegistry`
3. Update prompts in `prompts/system_prompt.py`

## 📜 License

MIT License - See LICENSE for details.

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
