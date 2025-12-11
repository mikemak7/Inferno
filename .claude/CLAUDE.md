# Inferno-AI

Autonomous Penetration Testing Agent powered by Claude with a simplified, effective architecture.

## Core Philosophy

**ONE tool to rule them all.** Instead of 81 specialized tools that create cognitive overhead and decision paralysis, Inferno uses a single unified `execute_command` tool. The LLM knows security tools - let it decide what commands to run.

| Old Approach (Broken) | New Approach (Works) |
|-----------------------|----------------------|
| 81 specialized tools | 4 core tools |
| "Which tool?" decision overhead | "Run this command" |
| Complex abstractions | Direct execution |
| Never validated | Built for real CTFs |

## Tech Stack

- **Language**: Python 3.11+
- **AI Framework**: Claude API + Claude Agent SDK
- **Memory**: Mem0 with Qdrant vector database
- **CLI**: Typer + Rich
- **Configuration**: Pydantic + python-dotenv

## Project Structure

```
src/inferno/
├── agent/                   # Main agent execution
│   ├── executor.py          # AgentExecutor
│   ├── sdk_executor.py      # SDKExecutor (primary)
│   ├── loop.py              # AgentLoop
│   └── prompts.py           # SystemPromptBuilder
├── cli/                     # Command-line interface
│   ├── main.py              # Typer app
│   └── shell.py             # Interactive shell
├── config/                  # Configuration
│   └── settings.py          # InfernoSettings
├── core/                    # Core infrastructure
│   ├── scope.py             # CRITICAL: Scope enforcement
│   ├── guardrails.py        # Security policies
│   ├── unicode_security.py  # Homograph detection
│   ├── knowledge.py         # Knowledge graph
│   ├── network.py           # Rate limiting
│   ├── branch_tracker.py    # Decision tracking
│   ├── checkpoint.py        # State persistence
│   └── preflight.py         # Validation
├── tools/                   # ONLY 4 CORE TOOLS
│   ├── execute_command.py   # THE tool - runs everything
│   ├── http.py              # HTTP requests
│   ├── memory.py            # Persistent memory
│   ├── think.py             # Structured reasoning
│   ├── base.py              # BaseTool class
│   ├── decorator.py         # @function_tool
│   └── registry.py          # ToolRegistry
├── swarm/                   # Sub-agent coordination
│   ├── tool.py              # SwarmTool
│   ├── agents.py            # SubAgentConfig
│   ├── meta_coordinator.py  # MetaCoordinator (subagent-driven)
│   └── message_bus.py       # Inter-agent communication
├── prompts/                 # Prompt system
├── handlers/                # Event handlers
├── observability/           # Metrics & tracing
└── reporting/               # Report generation
```

## The Tool System

### Core Tools (Only 4!)

1. **`execute_command`** - THE primary tool. Runs any command:
   ```python
   execute_command("nmap -sV -sC 192.168.1.1")
   execute_command("sqlmap -u 'http://target/page?id=1' --batch")
   execute_command("gobuster dir -u http://target -w wordlist.txt")
   execute_command("curl -X POST http://target/api -d 'data'")
   execute_command("python exploit.py")
   ```

2. **`http_request`** - HTTP requests with advanced features

3. **`memory`** - Persistent memory storage (Mem0/Qdrant)

4. **`think`** - Structured reasoning for complex decisions

### Why This Works

The LLM already knows:
- How to use nmap, sqlmap, gobuster, nikto, hydra, nuclei
- Correct syntax and flags
- When to use each tool
- How to chain commands

Don't force it to first decide "which of 81 tools?" - just let it run commands.

### Using execute_command

```python
from inferno.tools import execute_command

# Basic command
result = await execute_command(command="nmap -sV target.com")

# With timeout
result = await execute_command(
    command="sqlmap -u 'http://target/page?id=1' --batch --dbs",
    timeout=300
)

# Interactive session (SSH, nc, etc.)
result = await execute_command(
    command="ssh user@host",
    interactive=True
)

# Send to existing session
result = await execute_command(
    command="whoami",
    session_id="abc123"
)

# Special commands
execute_command("sessions")           # List active sessions
execute_command("output abc123")      # Get session output
execute_command("kill abc123")        # Kill session
execute_command("env info")           # Environment info
```

### Features Built Into execute_command

- **Auto-environment detection**: Container, SSH, or local
- **Adaptive timeouts**: 30s for quick commands, 30min for full scans
- **Session management**: SSH, nc, python REPL support
- **Security**: Unicode homograph detection, dangerous command blocking
- **Guardrails**: Prompt injection protection

## Key Components

### ScopeManager (`core/scope.py`)
CRITICAL - enforces authorized testing boundaries. Never bypassed.

### Guardrails (`core/guardrails.py`)
Input/output security policies:
- Credential leak detection
- Prompt injection protection
- Dangerous command blocking

### BranchTracker (`core/branch_tracker.py`)
Decision tracking and backtracking:
- Records decision points
- Enables systematic exploration
- Prevents loops

## Configuration

### Authentication

Inferno supports multiple authentication methods (checked in order):
1. **Claude Code OAuth** (macOS Keychain) - Reuses `claude` CLI credentials
2. **OAuth tokens** - For Claude Pro/Team subscribers
3. **Environment variable** - `ANTHROPIC_API_KEY`
4. **Credentials file** - `~/.inferno/credentials.json`

```bash
# If using Claude Code, just login there first:
claude login

# Or set API key directly:
export ANTHROPIC_API_KEY=sk-ant-...
```

### Environment Variables

Variables prefixed with `INFERNO_`:
```bash
INFERNO_API_KEY=sk-ant-...
INFERNO_MODEL=claude-opus-4-5-20251101
INFERNO_GUARDRAILS=true
```

## CLI Usage

```bash
# Interactive mode
inferno shell

# Then in shell:
inferno> target https://target.com
inferno> objective Find vulnerabilities
inferno> run
```

### Architecture (Subagent-Driven by Default)

The `run` command uses **subagent-driven architecture**:
- **MetaCoordinator** ONLY coordinates - it NEVER executes commands
- **Worker subagents** do ALL the work (recon, exploit, validate, report)
- Workers communicate via **MessageBus** (real-time) and **shared memory** (Mem0)
- All findings are **validated** before reporting (no false positives)

Worker types:
| Worker | Job |
|--------|-----|
| `reconnaissance` | nmap, gobuster, subfinder |
| `scanner` | nuclei, vulnerability detection |
| `exploiter` | sqlmap, XSS exploitation |
| `validator` | Independent finding verification |
| `post_exploitation` | Privilege escalation |
| `reporter` | Generate final report |

### Legacy Mode

To use the old architecture (single agent does work directly):
```bash
inferno> run-legacy
```

## Development

### Setup
```bash
pip install -e ".[dev]"
inferno setup
```

### Running Tests
```bash
pytest tests/
```

### Adding New Functionality

Don't add new tools. If you need new capability, either:

1. **Just run the command** via `execute_command`:
   ```python
   execute_command("new-security-tool --options")
   ```

2. **If truly needed**, use the decorator:
   ```python
   from inferno.tools import function_tool, ToolCategory, ToolResult

   @function_tool(category=ToolCategory.CORE)
   async def special_operation(param: str) -> ToolResult:
       '''Only if execute_command truly cannot do this.'''
       ...
   ```

## What Was Deleted (And Why)

| Deleted | Why |
|---------|-----|
| `tools/advanced/` (51 files) | Cognitive overhead, never validated |
| `tools/security/` (11 files) | Wrappers around commands execute_command can run |
| `swarm/patterns/` (6 files) | Over-engineered, 1 pattern suffices |
| `swarm/validation_agent.py` | Just re-run the exploit |
| `modules/` (10 files) | Abstraction layers with no value |
| `core/` over-engineering | cdn_detector, geo_detector, etc. |

**Result**: From 214 Python files to 107. From 81 tools to 4.

## What's Kept (And Why)

| Kept | Why |
|------|-----|
| `core/scope.py` | Security critical |
| `core/guardrails.py` | Prompt injection protection |
| `core/branch_tracker.py` | Unique, useful feature |
| `core/network.py` | Rate limiting |
| `tools/http.py` | Advanced HTTP features |
| `tools/memory.py` | Cross-session learning |
| `tools/think.py` | Structured reasoning |

## Testing Against Real CTFs

The measure of success: Can Inferno solve real HackTheBox machines?

```python
from inferno.agent.sdk_executor import SDKExecutor

executor = SDKExecutor(settings)
result = await executor.run(
    target="10.10.10.x",
    objective="Obtain root flag",
    persona="ctf"
)
```

If it can't get root on machines that humans solve, it's broken. Ship when it works.
