"""
Cyber-Sentry AI – LLM Provider constants and factory.

Separated from main.py so the CLI, tests, and other modules can import
provider names without pulling in the full LangGraph / LangChain stack.
"""

import os

# ── Provider name constants ───────────────────────────────────────────────────
PROVIDER_OLLAMA = "ollama"
PROVIDER_OPENAI = "openai"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENROUTER = "openrouter"

ALL_PROVIDERS = [PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_OPENROUTER]

# OpenRouter's OpenAI-compatible endpoint
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def get_llm(model: str = "llama3", temperature: float = 0.7, provider: str = None):
    """
    Initialize LLM based on the selected provider.

    Provider selection order:
    1. Explicit ``provider`` argument
    2. ``LLM_PROVIDER`` environment variable
    3. Auto-detect from available API keys (openrouter > openai > anthropic > ollama)
    4. Default to Ollama

    Supported providers:
    - ``ollama``      – local Ollama server (default; requires ``OLLAMA_BASE_URL`` or localhost)
    - ``openai``      – OpenAI API (requires ``OPENAI_API_KEY``)
    - ``anthropic``   – Anthropic API (requires ``ANTHROPIC_API_KEY``)
    - ``openrouter``  – OpenRouter unified API (requires ``OPENROUTER_API_KEY``)
    """
    if provider is None:
        provider = os.environ.get("LLM_PROVIDER", "").lower()

    # Auto-detect from available API keys when provider is not set explicitly
    if not provider:
        if os.environ.get("OPENROUTER_API_KEY"):
            provider = PROVIDER_OPENROUTER
        elif os.environ.get("OPENAI_API_KEY"):
            provider = PROVIDER_OPENAI
        elif os.environ.get("ANTHROPIC_API_KEY"):
            provider = PROVIDER_ANTHROPIC
        else:
            provider = PROVIDER_OLLAMA

    if provider == PROVIDER_OPENROUTER:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise ImportError(
                "langchain-openai is required for OpenRouter support. "
                "Install it with: pip install langchain-openai"
            ) from exc
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENROUTER_API_KEY environment variable is required for OpenRouter provider"
            )
        default_model = "openai/gpt-4o-mini"
        return ChatOpenAI(
            model=model if model != "llama3" else default_model,
            api_key=api_key,
            base_url=OPENROUTER_BASE_URL,
            temperature=temperature,
            streaming=True,
            default_headers={
                # Recommended by OpenRouter for identifying your app
                "HTTP-Referer": os.environ.get(
                    "OPENROUTER_SITE_URL",
                    "https://github.com/vaibhavthakur3107/super-duper-garbanzo",
                ),
                "X-Title": os.environ.get("OPENROUTER_APP_TITLE", "Cyber-Sentry AI"),
            },
        )

    if provider == PROVIDER_OPENAI:
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise ImportError(
                "langchain-openai is required for OpenAI support. "
                "Install it with: pip install langchain-openai"
            ) from exc
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY environment variable is required for OpenAI provider"
            )
        return ChatOpenAI(
            model=model if model != "llama3" else "gpt-4o-mini",
            api_key=api_key,
            temperature=temperature,
            streaming=True,
        )

    if provider == PROVIDER_ANTHROPIC:
        try:
            from langchain_anthropic import ChatAnthropic
        except ImportError as exc:
            raise ImportError(
                "langchain-anthropic is required for Anthropic support. "
                "Install it with: pip install langchain-anthropic"
            ) from exc
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is required for Anthropic provider"
            )
        return ChatAnthropic(
            model=model if model != "llama3" else "claude-3-haiku-20240307",
            api_key=api_key,
            temperature=temperature,
            streaming=True,
        )

    # Default: Ollama (local)
    try:
        from langchain_community.chat_models import ChatOllama
    except ImportError as exc:
        raise ImportError(
            "langchain-community is required for Ollama support. "
            "Install it with: pip install langchain-community"
        ) from exc
    return ChatOllama(
        model=model,
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
        temperature=temperature,
        streaming=True,
    )
