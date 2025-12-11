# Configuration Guide

Inferno is configured through environment variables and a `.env` file.

## Table of Contents

- [Configuration Methods](#configuration-methods)
- [Core Settings](#core-settings)
- [Model Configuration](#model-configuration)
- [Memory Configuration](#memory-configuration)
- [Execution Settings](#execution-settings)
- [Network Settings](#network-settings)
- [Output Settings](#output-settings)
- [External APIs](#external-apis)
- [Complete .env Example](#complete-env-example)

## Configuration Methods

### Priority Order

1. **Environment variables** (highest priority)
2. **.env file** in project directory
3. **Default values** (lowest priority)

### Environment Variable Naming

All Inferno settings use the `INFERNO_` prefix:

```bash
# Simple setting
INFERNO_MODEL=claude-opus-4-5-20251101

# Nested setting (use double underscore)
INFERNO_MEMORY__QDRANT_HOST=localhost
INFERNO_EXECUTION__MAX_STEPS=100
```

## Core Settings

### API Authentication

```bash
# Anthropic API key (if not using OAuth)
ANTHROPIC_API_KEY=sk-ant-api03-...

# Prefer OAuth over API key (default: true)
INFERNO_PREFER_OAUTH=true
```

### Model Selection

```bash
# Available models:
# - claude-opus-4-5-20251101 (most capable, recommended)
# - claude-sonnet-4-5-20250929 (balanced)
# - claude-haiku-4-5-20251001 (fastest, cheapest)
INFERNO_MODEL__MODEL_ID=claude-opus-4-5-20251101
```

## Model Configuration

```bash
# Model settings
INFERNO_MODEL__MODEL_ID=claude-opus-4-5-20251101
INFERNO_MODEL__MAX_TOKENS=4096
INFERNO_MODEL__TEMPERATURE=0.7
INFERNO_MODEL__TIMEOUT=420
INFERNO_MODEL__MAX_RETRIES=10
```

| Setting | Default | Range | Description |
|---------|---------|-------|-------------|
| `MODEL_ID` | claude-sonnet-4-5 | - | Claude model to use |
| `MAX_TOKENS` | 4096 | 1-200000 | Maximum response tokens |
| `TEMPERATURE` | 0.7 | 0.0-1.0 | Creativity (0=focused, 1=creative) |
| `TIMEOUT` | 420 | 30-600 | Request timeout in seconds |
| `MAX_RETRIES` | 10 | 1-20 | Retry attempts on failure |

## Memory Configuration

Inferno uses Qdrant for persistent vector memory.

```bash
# Qdrant connection
INFERNO_MEMORY__QDRANT_HOST=localhost
INFERNO_MEMORY__QDRANT_PORT=6333
INFERNO_MEMORY__QDRANT_COLLECTION=inferno_memories

# For Qdrant Cloud (optional)
INFERNO_MEMORY__QDRANT_API_KEY=your-qdrant-cloud-key

# Enable/disable memory system
INFERNO_MEMORY__USE_MEM0=true
```

### Embedding Providers

Choose how vectors are generated:

```bash
# Options: sentence_transformers, ollama, openai, voyage, cohere
INFERNO_MEMORY__EMBEDDING_PROVIDER=sentence_transformers
```

| Provider | Cost | Speed | Setup |
|----------|------|-------|-------|
| `sentence_transformers` | Free | Fast | None (default) |
| `ollama` | Free | Fast | Requires Ollama running |
| `openai` | Paid | Fast | Requires OPENAI_API_KEY |
| `voyage` | Paid | Fast | Requires VOYAGE_API_KEY |
| `cohere` | Paid | Fast | Requires COHERE_API_KEY |

**For Ollama:**
```bash
INFERNO_MEMORY__EMBEDDING_PROVIDER=ollama
INFERNO_MEMORY__OLLAMA_HOST=http://localhost:11434
```

**For cloud providers:**
```bash
# OpenAI
INFERNO_MEMORY__EMBEDDING_PROVIDER=openai
OPENAI_API_KEY=sk-...

# Voyage (Anthropic recommended)
INFERNO_MEMORY__EMBEDDING_PROVIDER=voyage
VOYAGE_API_KEY=...
```

## Execution Settings

Control agent behavior during assessments:

```bash
# Maximum steps before stopping
INFERNO_EXECUTION__MAX_STEPS=500

# Maximum conversation turns
INFERNO_EXECUTION__MAX_TURNS=500

# Total token budget
INFERNO_EXECUTION__MAX_TOTAL_TOKENS=1000000

# Enable streaming responses
INFERNO_EXECUTION__STREAM=true

# Conversation history window
INFERNO_EXECUTION__CONVERSATION_WINDOW_SIZE=50

# Maximum HTTP response size (bytes)
INFERNO_EXECUTION__MAX_RESPONSE_SIZE=500000
```

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_STEPS` | 500 | Hard limit on execution steps |
| `MAX_TURNS` | 500 | Maximum agent-user exchanges |
| `MAX_TOTAL_TOKENS` | 1M | Token budget before stopping |
| `STREAM` | true | Stream responses in real-time |

## Network Settings

Configure HTTP behavior:

```bash
# Request timeouts
INFERNO_NETWORK__DEFAULT_TIMEOUT=30

# SSL verification (disable for testing only)
INFERNO_NETWORK__VERIFY_SSL=true

# Rate limiting
INFERNO_NETWORK__REQUESTS_PER_SECOND=2.0
INFERNO_NETWORK__RATE_LIMIT_MODE=adaptive

# Retry behavior
INFERNO_NETWORK__MAX_RETRIES=3

# User agent rotation (OpSec)
INFERNO_NETWORK__USER_AGENT_ROTATION=true
```

### Rate Limit Modes

| Mode | Behavior |
|------|----------|
| `fixed` | Constant rate, no adaptation |
| `adaptive` | Adjusts based on responses |
| `aggressive` | Faster, may trigger WAFs |
| `stealth` | Slower, evades detection |

## Tool Settings

```bash
# Default command timeout (seconds)
INFERNO_TOOLS__SHELL_TIMEOUT=300

# HTTP request timeout
INFERNO_TOOLS__HTTP_TIMEOUT=30
```

## Output Settings

Configure where and how results are saved:

```bash
# Base output directory
INFERNO_OUTPUT__BASE_DIR=./outputs

# Report format: markdown, html, json
INFERNO_OUTPUT__REPORT_FORMAT=markdown

# Save tool artifacts
INFERNO_OUTPUT__SAVE_ARTIFACTS=true

# Log level: DEBUG, INFO, WARNING, ERROR
INFERNO_OUTPUT__LOG_LEVEL=INFO
```

### Output Directory Structure

```
outputs/
└── example.com/
    └── OP_20240115_103000/
        ├── artifacts/
        │   ├── nmap_scan.xml
        │   ├── gobuster_results.txt
        │   └── ...
        ├── report.md
        └── findings.json
```

## Error Recovery

```bash
# Tool retry attempts
INFERNO_ERROR_RECOVERY__MAX_TOOL_RETRIES=3

# Errors before suppressing a tool
INFERNO_ERROR_RECOVERY__ERROR_THRESHOLD=5

# Automatic recovery
INFERNO_ERROR_RECOVERY__ENABLE_AUTO_RECOVERY=true

# Backoff settings
INFERNO_ERROR_RECOVERY__BACKOFF_MULTIPLIER=2.0
INFERNO_ERROR_RECOVERY__MAX_BACKOFF_SECONDS=60
```

## Observability

Enable tracing and metrics:

```bash
# General observability
INFERNO_OBSERVABILITY__ENABLED=true

# Langfuse integration (optional)
INFERNO_OBSERVABILITY__LANGFUSE_ENABLED=false
INFERNO_OBSERVABILITY__LANGFUSE_HOST=https://cloud.langfuse.com
INFERNO_OBSERVABILITY__LANGFUSE_PUBLIC_KEY=pk-...
INFERNO_OBSERVABILITY__LANGFUSE_SECRET_KEY=sk-...

# What to trace
INFERNO_OBSERVABILITY__TRACE_TOOL_CALLS=true
INFERNO_OBSERVABILITY__TRACE_MEMORY_OPS=true
```

## Cache Settings

Response caching for efficiency:

```bash
INFERNO_CACHE__ENABLED=true
INFERNO_CACHE__MAX_SIZE_MB=100
INFERNO_CACHE__DEFAULT_TTL_SECONDS=300
INFERNO_CACHE__MAX_ENTRIES=10000
```

## External APIs

Optional APIs for enhanced capabilities:

```bash
# NVD (free, recommended)
NVD_API_KEY=your-nvd-key

# Shodan
SHODAN_API_KEY=your-shodan-key

# Censys
CENSYS_API_ID=your-id
CENSYS_API_SECRET=your-secret

# VirusTotal
VIRUSTOTAL_API_KEY=your-vt-key

# SecurityTrails
SECURITYTRAILS_API_KEY=your-st-key

# GitHub
GITHUB_TOKEN=ghp_...
```

## Guardrails

Security guardrails (enabled by default):

```bash
# Master switch for all guardrails
INFERNO_GUARDRAILS=true
```

When enabled, Inferno:
- Blocks dangerous commands (rm -rf /, etc.)
- Detects credential leaks in output
- Prevents Unicode homograph attacks
- Validates command safety

## Complete .env Example

```bash
# =============================================================================
# INFERNO-AI CONFIGURATION
# =============================================================================

# --- Authentication ---
# Option 1: API Key
# ANTHROPIC_API_KEY=sk-ant-api03-...

# Option 2: OAuth (run 'inferno auth login')
# Tokens stored automatically

# --- Model ---
INFERNO_MODEL__MODEL_ID=claude-opus-4-5-20251101
INFERNO_MODEL__MAX_TOKENS=4096
INFERNO_MODEL__TEMPERATURE=0.7

# --- Memory (Qdrant) ---
INFERNO_MEMORY__QDRANT_HOST=localhost
INFERNO_MEMORY__QDRANT_PORT=6333
INFERNO_MEMORY__EMBEDDING_PROVIDER=sentence_transformers

# --- Execution ---
INFERNO_EXECUTION__MAX_STEPS=500
INFERNO_EXECUTION__MAX_TOTAL_TOKENS=1000000

# --- Network ---
INFERNO_NETWORK__RATE_LIMIT_MODE=adaptive
INFERNO_NETWORK__VERIFY_SSL=true

# --- Output ---
INFERNO_OUTPUT__BASE_DIR=./outputs
INFERNO_OUTPUT__REPORT_FORMAT=markdown
INFERNO_OUTPUT__LOG_LEVEL=INFO

# --- External APIs (optional but recommended) ---
NVD_API_KEY=your-nvd-key
# SHODAN_API_KEY=your-shodan-key
# GITHUB_TOKEN=ghp_...

# --- Guardrails ---
INFERNO_GUARDRAILS=true
```

## Configuration Validation

Check your configuration:

```bash
inferno config validate
```

View current settings:

```bash
inferno config show
```

## Next Steps

- [Install Security Tools](TOOLS.md)
- [Learn CLI Usage](USAGE.md)
