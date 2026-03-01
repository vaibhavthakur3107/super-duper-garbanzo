.PHONY: help install install-openai install-anthropic run run-cli docker-build docker-up docker-down test lint

PYTHON  ?= python3
PIP     ?= pip3
VENV    := .venv

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ──────────────────────────────────────────────────────────────────────
install:  ## Install core dependencies (editable install)
	$(PIP) install -e "."

install-openai:  ## Install OpenAI / OpenRouter provider
	$(PIP) install langchain-openai

install-anthropic:  ## Install Anthropic (Claude) provider
	$(PIP) install langchain-anthropic

install-all: install install-openai install-anthropic  ## Install everything

setup: install  ## Create .env from example and install deps
	@[ -f .env ] || cp .env.example .env && echo "Created .env – edit it with your API keys"

# ── Run (local, no Docker needed) ─────────────────────────────────────────────
run-cli:  ## Start interactive CLI agent  ← main entry point
	$(PYTHON) -m dexter_ai.cli

run:  ## Start Streamlit web UI (http://localhost:8501)
	cd dexter_ai && streamlit run app.py

run-mcp:  ## Start MCP server (for Claude Desktop / Cursor / VS Code Copilot)
	$(PYTHON) dexter_ai_mcp.py

run-mcp-compact:  ## Start MCP server in compact mode (minimal tools)
	$(PYTHON) dexter_ai_mcp.py --compact

# ── Docker (same code, containerised) ─────────────────────────────────────────
# Docker and the CLI are ONE thing — Docker just packages it.
# The default command inside the container is the interactive CLI.
# Override the command to run the web UI instead:
#   docker compose run --rm dexter-ai streamlit run dexter_ai/app.py ...
docker-build:  ## Build Docker image
	docker compose build

docker-run:  ## Run interactive CLI inside Docker  ← docker equivalent of run-cli
	docker compose run --rm dexter-ai

docker-up:  ## Start Streamlit web UI via Docker (http://localhost:8501)
	docker compose run --rm dexter-ai \
	  streamlit run dexter_ai/app.py --server.address=0.0.0.0 --server.port=8501 --server.headless=true

docker-down:  ## Stop Docker Compose services
	docker compose down

# ── Quality ────────────────────────────────────────────────────────────────────
test:  ## Run test suite
	$(PYTHON) -m pytest tests/ -v

lint:  ## Run linter
	$(PYTHON) -m flake8 dexter_ai/ --max-line-length=120 --ignore=E501,W503

# ── Convenience ────────────────────────────────────────────────────────────────
pull-ollama:  ## Pull default Ollama model (llama3)
	ollama pull llama3

clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
