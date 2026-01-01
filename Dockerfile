# Inferno-AI Dockerfile
# Cross-platform containerized penetration testing environment
# Works on: Windows, macOS, Linux

FROM kalilinux/kali-rolling

LABEL maintainer="Inferno-AI Team"
LABEL description="Autonomous Penetration Testing Agent powered by Claude"
LABEL version="1.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ============================================================================
# SYSTEM SETUP
# ============================================================================

# Fix Kali GPG Keys
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --no-install-recommends --allow-unauthenticated \
        kali-archive-keyring \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Core system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python
    python3 python3-pip python3-dev python3-venv \
    # Essential tools
    curl wget git ca-certificates gnupg \
    # Build tools (for pip packages with C extensions)
    build-essential libffi-dev libssl-dev \
    # Network tools
    iputils-ping dnsutils netcat-openbsd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# SECURITY TOOLS INSTALLATION
# ============================================================================

# Install kali-linux-headless (comprehensive pentesting toolkit)
# Includes: nmap, nikto, dirb, gobuster, sqlmap, netcat, hydra, john, etc.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        kali-linux-headless \
        seclists \
        wordlists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Additional security tools not in headless
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Web scanning
    nuclei \
    whatweb \
    wpscan \
    # Recon
    subfinder \
    amass \
    # Exploitation
    exploitdb \
    metasploit-framework \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools (latest versions)
RUN apt-get update && apt-get install -y golang && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/httprobe@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="${PATH}:/root/go/bin"

# ============================================================================
# PYTHON SETUP
# ============================================================================

# Allow pip to install packages system-wide (Kali uses system Python)
RUN mkdir -p /root/.pip && \
    echo "[global]" > /root/.pip/pip.conf && \
    echo "break-system-packages = true" >> /root/.pip/pip.conf

# Upgrade pip
RUN pip3 install --upgrade pip setuptools wheel

# ============================================================================
# INFERNO INSTALLATION
# ============================================================================

WORKDIR /opt/inferno

# Copy requirements first (for Docker layer caching)
COPY requirements.txt pyproject.toml ./

# Install Python dependencies
RUN pip3 install -r requirements.txt || pip3 install anthropic httpx structlog rich typer pydantic python-dotenv

# Copy application code
COPY src/ ./src/
COPY docs/ ./docs/
COPY tests/ ./tests/

# Install Inferno in development mode
RUN pip3 install --break-system-packages -e .

# ============================================================================
# DIRECTORIES AND PERMISSIONS
# ============================================================================

# Create working directories
RUN mkdir -p /opt/inferno/outputs \
    /opt/inferno/logs \
    /root/.inferno \
    /workspace

# Wordlists setup - decompress rockyou and create symlinks
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip -k /usr/share/wordlists/rockyou.txt.gz || true; \
    fi && \
    ln -sf /usr/share/seclists /wordlists && \
    ln -sf /usr/share/wordlists /usr/share/wordlists && \
    ln -sf /usr/share/wordlists/rockyou.txt /rockyou.txt

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

# Default environment variables (override with docker run -e or .env file)
ENV INFERNO_OUTPUT_DIR=/opt/inferno/outputs
ENV INFERNO_LOG_DIR=/opt/inferno/logs
ENV QDRANT_HOST=qdrant
ENV QDRANT_PORT=6333

# ============================================================================
# ENTRYPOINT
# ============================================================================

# Create startup script
RUN echo '#!/bin/bash' > /opt/inferno/start.sh && \
    echo 'set -e' >> /opt/inferno/start.sh && \
    echo '' >> /opt/inferno/start.sh && \
    echo '# Load .env if mounted' >> /opt/inferno/start.sh && \
    echo 'if [ -f /config/.env ]; then' >> /opt/inferno/start.sh && \
    echo '    echo "Loading environment from /config/.env"' >> /opt/inferno/start.sh && \
    echo '    export $(grep -v "^#" /config/.env | xargs)' >> /opt/inferno/start.sh && \
    echo 'fi' >> /opt/inferno/start.sh && \
    echo '' >> /opt/inferno/start.sh && \
    echo '# If no arguments, start shell' >> /opt/inferno/start.sh && \
    echo 'if [ $# -eq 0 ]; then' >> /opt/inferno/start.sh && \
    echo '    exec inferno shell' >> /opt/inferno/start.sh && \
    echo 'else' >> /opt/inferno/start.sh && \
    echo '    exec inferno "$@"' >> /opt/inferno/start.sh && \
    echo 'fi' >> /opt/inferno/start.sh && \
    chmod +x /opt/inferno/start.sh

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import inferno; print('OK')" || exit 1

WORKDIR /workspace

ENTRYPOINT ["/opt/inferno/start.sh"]
CMD []
