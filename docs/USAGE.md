# Usage Guide

Learn how to use Inferno for security assessments.

## Table of Contents

- [Getting Started](#getting-started)
- [Interactive Shell](#interactive-shell)
- [Shell Commands](#shell-commands)
- [Running Assessments](#running-assessments)
- [Working with Targets](#working-with-targets)
- [Assessment Modes](#assessment-modes)
- [Memory and Context](#memory-and-context)
- [Reports](#reports)
- [Examples](#examples)
- [Tips and Best Practices](#tips-and-best-practices)

## Getting Started

### First Run

```bash
# Start the interactive shell
inferno shell
```

You'll see the Inferno prompt:
```
inferno>
```

### Basic Workflow

1. Set a target
2. Define an objective
3. Run the assessment
4. Review findings

```bash
inferno> target https://example.com
inferno> objective Find security vulnerabilities
inferno> run
```

## Interactive Shell

### Starting the Shell

```bash
# Standard start
inferno shell

# With specific model
inferno shell --model claude-opus-4-5-20251101

# With verbose logging
inferno shell --verbose
```

### Shell Interface

```
╭─────────────────────────────────────────────────────────────╮
│  INFERNO - Autonomous Penetration Testing Agent             │
├─────────────────────────────────────────────────────────────┤
│  Target: https://example.com                                │
│  Status: Ready                                              │
│  Memory: 42 items loaded                                    │
╰─────────────────────────────────────────────────────────────╯
inferno>
```

## Shell Commands

### Target Management

```bash
# Set target URL
inferno> target https://example.com

# Set target with scope
inferno> target https://example.com --scope "*.example.com"

# View current target
inferno> target

# Clear target
inferno> target clear
```

### Objective Setting

```bash
# Set assessment objective
inferno> objective Find SQL injection vulnerabilities

# Set multiple objectives
inferno> objective Find all OWASP Top 10 vulnerabilities

# View objective
inferno> objective
```

### Running Assessments

```bash
# Run assessment (standard mode)
inferno> run

# Run with specific persona
inferno> run --persona ctf

# Run in legacy mode (single agent)
inferno> run-legacy

# Run with step limit
inferno> run --max-steps 100
```

### Status and Control

```bash
# View current status
inferno> status

# Pause execution (during run)
Ctrl+C once

# Stop execution
Ctrl+C twice

# Resume after pause
inferno> resume
```

### Memory Commands

```bash
# Search memory
inferno> memory search "SQL injection"

# View recent memories
inferno> memory recent

# Clear memory for target
inferno> memory clear

# Export memory
inferno> memory export findings.json
```

### Reporting

```bash
# Generate report
inferno> report

# Generate specific format
inferno> report --format markdown
inferno> report --format html
inferno> report --format json

# Export for bug bounty
inferno> report --bugbounty
```

### Help

```bash
# General help
inferno> help

# Command-specific help
inferno> help run
inferno> help target
```

### Exit

```bash
inferno> exit
# or
inferno> quit
# or
Ctrl+D
```

## Running Assessments

### Standard Assessment

```bash
inferno> target https://example.com
inferno> objective Perform comprehensive security assessment
inferno> run
```

### Quick Scan

```bash
inferno> target https://example.com
inferno> objective Quick reconnaissance and vulnerability scan
inferno> run --max-steps 50
```

### Focused Assessment

```bash
inferno> target https://example.com/api
inferno> objective Test API endpoints for authentication bypass
inferno> run --persona api
```

## Working with Targets

### URL Targets

```bash
# Web application
inferno> target https://app.example.com

# Specific endpoint
inferno> target https://api.example.com/v1/users

# With port
inferno> target https://example.com:8443
```

### IP Targets

```bash
# Single IP
inferno> target 192.168.1.100

# With port
inferno> target 192.168.1.100:8080
```

### Scope Definition

Define what's in-scope for testing:

```bash
# Wildcard subdomain
inferno> target https://example.com --scope "*.example.com"

# Multiple domains
inferno> target https://example.com --scope "example.com,api.example.com"

# Exclude specific paths
inferno> target https://example.com --exclude "/admin,/internal"
```

## Assessment Modes

### Multi-Agent Swarm (Default)

The default mode uses coordinated specialist agents:

```bash
inferno> run
```

Agents include:
- **Recon** - Initial reconnaissance
- **Scanner** - Vulnerability scanning
- **Exploiter** - Validation and exploitation
- **Reporter** - Finding documentation

### Legacy Mode (Single Agent)

Single agent handles everything:

```bash
inferno> run-legacy
```

Better for:
- Simple targets
- Debugging
- Lower API costs

### Personas

Adjust behavior for different scenarios:

```bash
# Bug bounty hunting
inferno> run --persona bugbounty

# CTF challenges
inferno> run --persona ctf

# Red team engagement
inferno> run --persona redteam

# API testing
inferno> run --persona api
```

| Persona | Focus |
|---------|-------|
| `bugbounty` | High-value vulns, clean reports |
| `ctf` | Flag capture, creative techniques |
| `redteam` | Stealth, lateral movement |
| `api` | API-specific vulnerabilities |
| `web` | Web application security |

## Memory and Context

### How Memory Works

Inferno remembers:
- Previous findings for a target
- Successful techniques
- Failed approaches
- Collected credentials

### Using Memory

```bash
# Memory is automatic, but you can:

# Search past findings
inferno> memory search "admin panel"

# See what Inferno remembers
inferno> memory show

# Start fresh
inferno> memory clear
```

### Cross-Session Learning

Memory persists between sessions:

```bash
# Session 1
inferno> target https://example.com
inferno> run
# Finds: /admin panel with default credentials

# Session 2 (next day)
inferno> target https://example.com
inferno> run
# Agent remembers previous findings and builds on them
```

## Reports

### Automatic Reports

Reports are generated automatically after assessments.

### Manual Report Generation

```bash
# Generate report
inferno> report

# Specify format
inferno> report --format html
inferno> report --format markdown
inferno> report --format json
```

### Bug Bounty Export

Optimized for submission:

```bash
inferno> report --bugbounty
```

Generates:
- Executive summary
- Vulnerability details
- Reproduction steps
- Impact assessment
- Remediation recommendations

### Report Location

Reports saved to:
```
outputs/
└── example.com/
    └── OP_20240115_103000/
        ├── report.md
        ├── findings.json
        └── artifacts/
```

## Examples

### Example 1: Web Application Assessment

```bash
inferno shell

inferno> target https://testapp.example.com
inferno> objective Perform comprehensive web application security assessment focusing on OWASP Top 10
inferno> run

# After completion
inferno> report --format html
```

### Example 2: API Security Testing

```bash
inferno shell

inferno> target https://api.example.com
inferno> objective Test REST API for authentication bypass, IDOR, and injection vulnerabilities
inferno> run --persona api
```

### Example 3: Quick Reconnaissance

```bash
inferno shell

inferno> target example.com
inferno> objective Enumerate subdomains, open ports, and identify technologies
inferno> run --max-steps 30
```

### Example 4: CTF Challenge

```bash
inferno shell

inferno> target http://ctf.example.com:8080
inferno> objective Capture the flag. Look for common web vulnerabilities.
inferno> run --persona ctf
```

### Example 5: Authenticated Testing

```bash
inferno shell

inferno> target https://app.example.com
inferno> objective Test authenticated user functionality for privilege escalation

# Provide credentials in objective
inferno> objective Test with credentials user:password123 for privilege escalation
inferno> run
```

## Tips and Best Practices

### 1. Start Specific

```bash
# Too broad (may waste time)
inferno> objective Hack everything

# Better (focused)
inferno> objective Find SQL injection in the login form
```

### 2. Use Incremental Approach

```bash
# First: Reconnaissance
inferno> objective Enumerate the target and identify attack surface
inferno> run --max-steps 50

# Then: Focused testing
inferno> objective Test identified endpoints for vulnerabilities
inferno> run
```

### 3. Review Progress

```bash
# During long assessments
inferno> status

# Check what's been found
inferno> memory recent
```

### 4. Iterate on Findings

```bash
# Initial finding: XSS in comment field
# Follow up:
inferno> objective Escalate the XSS finding to session hijacking or stored XSS
inferno> run
```

### 5. Manage API Costs

```bash
# Use step limits for exploration
inferno> run --max-steps 50

# Use Haiku for reconnaissance
inferno shell --model claude-haiku-4-5-20251001
```

### 6. Document Your Scope

Always have written authorization. Inferno respects scope:

```bash
# Define scope clearly
inferno> target https://example.com --scope "*.example.com" --exclude "/admin"
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Pause/Interrupt |
| `Ctrl+C Ctrl+C` | Force stop |
| `Ctrl+D` | Exit shell |
| `Ctrl+L` | Clear screen |
| `Tab` | Auto-complete |
| `↑` / `↓` | Command history |

## Troubleshooting

### Assessment Stuck

```bash
# Check status
inferno> status

# If stuck, interrupt and review
Ctrl+C
inferno> memory recent
```

### No Findings

```bash
# Try different persona
inferno> run --persona ctf

# Or be more specific
inferno> objective Focus on SQL injection in form parameters
```

### API Errors

```bash
# Check authentication
inferno auth status

# Reduce request rate
# (Edit .env: INFERNO_NETWORK__REQUESTS_PER_SECOND=1.0)
```

## Next Steps

- [Configuration Guide](CONFIGURATION.md)
- [Security Tools](TOOLS.md)
- [Contributing](../CONTRIBUTING.md)
