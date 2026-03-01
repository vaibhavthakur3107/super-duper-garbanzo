# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY dexter_ai/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Dexter AI Pentest"
LABEL description="AI-powered Red Team Pentesting Agent"

WORKDIR /app

# Install security tools available in Debian repos
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    whois \
    dnsutils \
    curl \
    wget \
    netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . /app

# Create non-root user for security
RUN useradd -m -u 1000 sentry && \
    chown -R sentry:sentry /app

USER sentry

# Expose Streamlit port and FastAPI port
EXPOSE 8501 8000

# Default: start Streamlit UI
CMD ["streamlit", "run", "dexter_ai/app.py", "--server.address=0.0.0.0", "--server.port=8501"]
