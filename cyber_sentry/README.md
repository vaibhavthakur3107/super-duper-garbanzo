# 🔒 Cyber-Sentry AI

A production-ready Red Team Cyber-Sentry AI agent system with multi-agent architecture, ReAct reasoning, tool integration, security guardrails, and an interactive Thought Trace UI.

![Cyber-Sentry AI](https://img.shields.io/badge/Version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![React](https://img.shields.io/badge/React-18.2-blue)

## 🎯 Features

### Multi-Agent Architecture
- **Reconnaissance Agent**: Performs OSINT and network reconnaissance
- **Vulnerability Agent**: Analyzes systems for security vulnerabilities
- **Exploitation Agent**: Validates potential exploits safely
- **Reporting Agent**: Generates comprehensive assessment reports

### ReAct Reasoning
- Implements Reasoning + Acting paradigm
- Full thought trace visualization
- Step-by-step decision tracking

### Tool Integrations
- Network scanning and reconnaissance
- Vulnerability assessment
- SSL/TLS analysis
- WHOIS lookups
- Extensible tool registry

### Security Guardrails
- Scope validation (prevent unauthorized targets)
- Dangerous action blocking
- Rate limiting
- Input validation & sanitization
- Legal compliance checks
- Audit logging
- Output filtering (PII redaction)

### Thought Trace UI
- Real-time thought visualization
- Agent state monitoring
- Task execution interface
- System status dashboard

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Cyber-Sentry AI                         │
├─────────────────────────────────────────────────────────────┤
│                      API Layer (FastAPI)                    │
├──────────────┬──────────────┬──────────────┬───────────────┤
│   Recon      │  Vulnerability│  Exploitation│   Reporting  │
│   Agent      │    Agent      │    Agent     │    Agent     │
├──────────────┴──────────────┴──────────────┴───────────────┤
│                  ReAct Reasoning Engine                     │
├─────────────────────────────────────────────────────────────┤
│  Tool Registry  │  Security Guardrails  │  Memory Storage  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn

### Installation

1. **Clone and install Python dependencies:**
```bash
cd cyber_sentry
pip install -r requirements.txt
```

2. **Install frontend dependencies:**
```bash
cd ui
npm install
```

### Running the Application

1. **Start the backend API:**
```bash
cd cyber_sentry
uvicorn api.main:app --reload --port 8000
```

2. **Start the frontend (in another terminal):**
```bash
cd cyber_sentry/ui
npm run dev
```

3. **Access the UI:**
Open http://localhost:3000 in your browser

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root endpoint |
| `/status` | GET | System status |
| `/health` | GET | Health check |
| `/tasks` | POST | Execute a task |
| `/tasks/{session_id}` | GET | Get task results |
| `/agents` | GET | List agents |
| `/agents/{name}/thoughts` | GET | Get agent thoughts |
| `/tools` | GET | List available tools |
| `/guardrails` | GET | List security guardrails |
| `/ws/thoughts` | WebSocket | Real-time thought stream |

## 🔧 Configuration

### Allowed Domains
Configure allowed target domains in `cyber_sentry/api/main.py`:

```python
guardrails = SecurityGuardrails(allowed_domains=["example.com", "test.local"])
```

### Rate Limiting
Adjust rate limits in `cyber_sentry/guardrails/security.py`:

```python
RateLimitGuardrail(max_requests_per_minute=60)
```

## 📁 Project Structure

```
cyber_sentry/
├── agents/               # Agent implementations
│   ├── __init__.py       # Base agent classes
│   └── specialized.py    # Specialized agent implementations
├── tools/                # Tool integrations
│   └── registry.py       # Tool registry
├── guardrails/           # Security guardrails
│   └── security.py       # Security checks
├── api/                  # FastAPI backend
│   └── main.py           # API endpoints
├── ui/                   # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── App.tsx       # Main app
│   │   └── index.css     # Styles
│   └── package.json
└── requirements.txt      # Python dependencies
```

## 🛡️ Security Features

1. **Scope Validation**: Prevents scanning of unauthorized targets
2. **Dangerous Action Blocking**: Blocks harmful operations
3. **Rate Limiting**: Prevents abuse
4. **Input Validation**: Sanitizes user inputs
5. **Legal Compliance**: Blocks government/critical infrastructure
6. **Audit Logging**: Records all operations
7. **Output Filtering**: Redacts sensitive data

## 🤖 ReAct Reasoning

The system implements the ReAct (Reasoning + Acting) paradigm:

1. **Think**: Agent analyzes the task and context
2. **Act**: Agent selects and executes a tool action
3. **Observe**: Agent processes the result
4. **Iterate**: Agent continues until task completion

Each step is logged and visualized in the Thought Trace UI.

## 📝 Example Usage

### Execute a Task via API

```bash
curl -X POST http://localhost:8000/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "task": "Perform reconnaissance",
    "target": "example.com"
  }'
```

### Expected Response

```json
{
  "session_id": "uuid",
  "status": "completed",
  "task": "Perform reconnaissance Target: example.com",
  "start_time": "2024-01-01T00:00:00",
  "results": [...]
}
```

## 🔨 Development

### Running Tests
```bash
pytest
```

### Linting
```bash
flake8 cyber_sentry/
```

## 📜 License

MIT License - See LICENSE for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. 
Always ensure you have proper authorization before scanning any target.
