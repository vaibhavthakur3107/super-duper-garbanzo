.PHONY: help install install-openai install-anthropic run run-api run-cli docker-build docker-up docker-down test lint

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

# ── Run ────────────────────────────────────────────────────────────────────────
run:  ## Start Streamlit UI (http://localhost:8501)
	cd cyber_sentry && streamlit run app.py

run-api:  ## Start FastAPI backend (http://localhost:8000)
	uvicorn cyber_sentry.api.main:app --reload --host 0.0.0.0 --port 8000

run-cli:  ## Start interactive CLI agent
	$(PYTHON) -m cyber_sentry.cli

run-mcp:  ## Start MCP server (for Claude Desktop / Cursor / VS Code Copilot)
	$(PYTHON) cyber_sentry_mcp.py

run-mcp-compact:  ## Start MCP server in compact mode (minimal tools)
	$(PYTHON) cyber_sentry_mcp.py --compact

# ── Docker ─────────────────────────────────────────────────────────────────────
docker-build:  ## Build Docker image
	docker compose build

docker-up:  ## Start all services with Docker Compose
	docker compose up

docker-down:  ## Stop all Docker Compose services
	docker compose down

docker-cli:  ## Run CLI in Docker container
	docker compose run --rm cli

# ── Quality ────────────────────────────────────────────────────────────────────
test:  ## Run test suite
	$(PYTHON) -m pytest tests/ -v

lint:  ## Run linter
	$(PYTHON) -m flake8 cyber_sentry/ --max-line-length=120 --ignore=E501,W503

# ── Convenience ────────────────────────────────────────────────────────────────
pull-ollama:  ## Pull default Ollama model (llama3)
	ollama pull llama3

clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage
