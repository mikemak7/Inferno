"""
Unified Execute Command Tool - The ONE tool to run everything.

This is the primary tool for Inferno. Instead of 81 specialized tools,
the agent uses this single tool to run any command it needs:
- nmap, sqlmap, gobuster, hydra
- curl, wget, nc, ssh
- python, bash, any script
- Everything else

Design Philosophy:
- Let the LLM decide what command to run (it knows pentest tools)
- Don't force tool selection decisions before execution
- Reduce cognitive load: "run this command" not "which of 81 tools?"
"""

from __future__ import annotations

import asyncio
import os
import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from inferno.tools.base import ToolCategory, ToolResult
from inferno.tools.decorator import function_tool
from inferno.tools.shell_session import (
    create_shell_session,
    format_sessions_table,
    get_session,
    resolve_session_id,
    send_to_session,
    terminate_all_sessions,
    terminate_session,
)
from inferno.tools.shell_session import (
    get_session_output as shell_get_output,
)

logger = structlog.get_logger(__name__)


# ============================================================================
# Session Management (Using ShellSession)
# ============================================================================

def list_sessions() -> str:
    """List all active sessions with friendly IDs."""
    return format_sessions_table()


async def get_session_output_async(session_id: str) -> str:
    """Get output from a session (async wrapper)."""
    return shell_get_output(session_id, clear=True)


async def kill_session(session_id: str) -> str:
    """Kill a session."""
    return terminate_session(session_id)


# ============================================================================
# Security: Unicode Homograph Detection
# ============================================================================

def detect_unicode_homographs(text: str) -> tuple[bool, str]:
    """
    Detect and normalize Unicode homograph characters used to bypass security.
    Returns (has_homographs, normalized_text)
    """
    homograph_map = {
        # Cyrillic to Latin
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
        '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P',
        '\u0421': 'C', '\u0425': 'X',
        # Greek to Latin
        '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u',
        '\u03c7': 'x', '\u0391': 'A', '\u039f': 'O', '\u03a1': 'P',
    }

    has_homographs = any(char in text for char in homograph_map)
    normalized = text
    for homograph, replacement in homograph_map.items():
        normalized = normalized.replace(homograph, replacement)
    normalized = unicodedata.normalize('NFKD', normalized)

    return has_homographs, normalized


# ============================================================================
# Security: Command Safety Validation
# ============================================================================

BLOCKED_COMMANDS = frozenset({
    "rm -rf /", "rm -rf /*", "dd if=/dev/zero", "mkfs", "fdisk",
    ":(){ :|:& };:", "chmod -R 777 /", "> /dev/sda", "mv / /dev/null",
    "wget -O- | sh", "curl | sh", "shutdown", "reboot", "init 0",
})

DANGEROUS_PATTERNS = [
    r"rm\s+(-[rf]+\s+)*[/~]",
    r":\(\)\s*\{\s*:\|:&\s*\}",
    r">\s*/dev/sd[a-z]",
    r"dd\s+.*of=/dev/",
    r"mkfs\.",
    r"chmod\s+(-[rR]+\s+)*777\s+/",
    r"curl.*\|\s*(ba)?sh",
    r"wget.*\|\s*(ba)?sh",
    r"nc\s+.*-[el].*\|\s*(ba)?sh",
    r"bash\s+-i\s+>&\s*/dev/tcp/",
]

# Pre-compile dangerous patterns for performance (10-50x faster)
_COMPILED_DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), pattern)
    for pattern in DANGEROUS_PATTERNS
]

# Pre-compile whitespace normalization pattern
_WHITESPACE_PATTERN = re.compile(r'\s+')


def is_command_safe(command: str) -> tuple[bool, str | None]:
    """Check if command is safe to execute."""
    command_lower = command.lower().strip()
    normalized = _WHITESPACE_PATTERN.sub(' ', command_lower)

    for blocked in BLOCKED_COMMANDS:
        if blocked in normalized:
            return False, f"Blocked: {blocked}"

    # Use pre-compiled patterns for performance
    for compiled_pattern, pattern_str in _COMPILED_DANGEROUS_PATTERNS:
        if compiled_pattern.search(normalized):
            return False, f"Dangerous pattern: {pattern_str}"

    return True, None


# ============================================================================
# Curl Interception for Auto-Bypass (WAF Evasion)
# ============================================================================

@dataclass
class CurlParsed:
    """Parsed curl command components."""

    url: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    data: str | None = None
    data_raw: str | None = None
    form_data: dict[str, str] = field(default_factory=dict)
    cookies: str | None = None
    user_agent: str | None = None
    verbose: bool = False
    include_headers: bool = False
    follow_redirects: bool = False
    insecure: bool = False
    output_file: str | None = None
    extra_args: list[str] = field(default_factory=list)


def _is_curl_command(cmd: str) -> bool:
    """Check if command is a curl request."""
    stripped = cmd.strip()
    return stripped.startswith("curl ") or stripped == "curl"


def _parse_curl_command(cmd: str) -> CurlParsed:
    """Parse curl command into components."""
    parsed = CurlParsed()

    try:
        # Use shlex to properly split the command
        parts = shlex.split(cmd)
    except ValueError:
        # Fallback to simple split if shlex fails
        parts = cmd.split()

    if not parts or parts[0] != "curl":
        return parsed

    i = 1
    while i < len(parts):
        arg = parts[i]

        # Method
        if arg in ("-X", "--request") and i + 1 < len(parts):
            parsed.method = parts[i + 1].upper()
            i += 2
            continue

        # Data
        if arg in ("-d", "--data", "--data-binary", "--data-urlencode") and i + 1 < len(parts):
            parsed.data = parts[i + 1]
            if parsed.method == "GET":
                parsed.method = "POST"
            i += 2
            continue

        # Raw data
        if arg == "--data-raw" and i + 1 < len(parts):
            parsed.data_raw = parts[i + 1]
            if parsed.method == "GET":
                parsed.method = "POST"
            i += 2
            continue

        # Headers
        if arg in ("-H", "--header") and i + 1 < len(parts):
            header = parts[i + 1]
            if ":" in header:
                key, value = header.split(":", 1)
                parsed.headers[key.strip()] = value.strip()
            i += 2
            continue

        # User agent
        if arg in ("-A", "--user-agent") and i + 1 < len(parts):
            parsed.user_agent = parts[i + 1]
            i += 2
            continue

        # Cookie
        if arg in ("-b", "--cookie") and i + 1 < len(parts):
            parsed.cookies = parts[i + 1]
            i += 2
            continue

        # Form data
        if arg in ("-F", "--form") and i + 1 < len(parts):
            form = parts[i + 1]
            if "=" in form:
                key, value = form.split("=", 1)
                parsed.form_data[key] = value
            i += 2
            continue

        # Output file
        if arg in ("-o", "--output") and i + 1 < len(parts):
            parsed.output_file = parts[i + 1]
            i += 2
            continue

        # Flags
        if arg in ("-v", "--verbose"):
            parsed.verbose = True
            i += 1
            continue
        if arg in ("-i", "--include"):
            parsed.include_headers = True
            i += 1
            continue
        if arg in ("-L", "--location"):
            parsed.follow_redirects = True
            i += 1
            continue
        if arg in ("-k", "--insecure"):
            parsed.insecure = True
            i += 1
            continue
        if arg in ("-s", "--silent", "-S", "--show-error"):
            i += 1
            continue

        # Skip other flags with values
        if arg.startswith("-") and i + 1 < len(parts) and not parts[i + 1].startswith("-"):
            parsed.extra_args.extend([arg, parts[i + 1]])
            i += 2
            continue
        if arg.startswith("-"):
            parsed.extra_args.append(arg)
            i += 1
            continue

        # URL (anything not starting with -)
        if not arg.startswith("-"):
            parsed.url = arg
            i += 1
            continue

        i += 1

    return parsed


def _rebuild_curl_command(parsed: CurlParsed, new_payload: str) -> str:
    """Rebuild curl command with mutated payload."""
    parts = ["curl"]

    # Method (only if not GET)
    if parsed.method != "GET":
        parts.extend(["-X", parsed.method])

    # Headers
    for key, value in parsed.headers.items():
        parts.extend(["-H", f"{key}: {value}"])

    # User agent
    if parsed.user_agent:
        parts.extend(["-A", parsed.user_agent])

    # Cookie
    if parsed.cookies:
        parts.extend(["-b", parsed.cookies])

    # Flags
    if parsed.verbose:
        parts.append("-v")
    if parsed.include_headers:
        parts.append("-i")
    if parsed.follow_redirects:
        parts.append("-L")
    if parsed.insecure:
        parts.append("-k")

    # Output file
    if parsed.output_file:
        parts.extend(["-o", parsed.output_file])

    # Data with new payload
    if parsed.data is not None:
        parts.extend(["-d", new_payload])
    elif parsed.data_raw is not None:
        parts.extend(["--data-raw", new_payload])

    # Extra args
    parts.extend(parsed.extra_args)

    # URL
    if parsed.url:
        parts.append(parsed.url)

    # Use shlex.join to properly quote
    return shlex.join(parts)


def _detect_payload_context(payload: str) -> str:
    """Detect what type of payload this is (sql, xss, cmd, path, generic)."""
    payload_lower = payload.lower()

    # SQL patterns
    sql_patterns = [
        r"select\s+", r"union\s+", r"insert\s+", r"update\s+", r"delete\s+",
        r"drop\s+", r"or\s+\d+=\d+", r"and\s+\d+=\d+", r"'\s*or\s*'", r"--",
        r";\s*select", r"'\s*union", r"order\s+by", r"group\s+by",
    ]
    if any(re.search(p, payload_lower) for p in sql_patterns):
        return "sql"

    # XSS patterns
    xss_patterns = [
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"<img\s+", r"<svg\s+", r"alert\s*\(", r"document\.",
    ]
    if any(re.search(p, payload_lower) for p in xss_patterns):
        return "xss"

    # Command injection patterns
    cmd_patterns = [
        r";\s*\w+", r"\|\s*\w+", r"`\w+`", r"\$\(\w+\)",
        r"&&\s*\w+", r"\|\|\s*\w+",
    ]
    if any(re.search(p, payload_lower) for p in cmd_patterns):
        return "cmd"

    # Path traversal patterns
    path_patterns = [r"\.\./", r"\.\.\\", r"/etc/", r"c:\\"]
    if any(re.search(p, payload_lower) for p in path_patterns):
        return "path"

    return "generic"


def _is_response_blocked(output: str) -> tuple[bool, int | None]:
    """Check if curl output indicates a blocked response."""
    # Check for HTTP status codes that indicate blocking
    status_match = re.search(r"HTTP/[\d.]+\s+(\d{3})", output)
    status_code = int(status_match.group(1)) if status_match else None

    blocked_statuses = {403, 406, 429, 503}
    if status_code in blocked_statuses:
        return True, status_code

    # Check for WAF block messages in body
    block_patterns = [
        r"access denied",
        r"request blocked",
        r"forbidden",
        r"security violation",
        r"waf",
        r"firewall",
        r"cloudflare",
        r"incapsula",
        r"sucuri",
        r"wordfence",
    ]
    output_lower = output.lower()
    if any(re.search(p, output_lower) for p in block_patterns):
        return True, status_code

    return False, status_code


async def _execute_curl_with_auto_bypass(
    command: str,
    output: str,
    timeout: int,
    cwd: Path | None,
) -> tuple[str, bool]:
    """
    Attempt to bypass WAF by mutating payload and retrying.

    Returns:
        Tuple of (final_output, bypass_succeeded)
    """
    # Only proceed if enabled (default: enabled)
    if os.getenv("INFERNO_AUTO_BYPASS", "true").lower() == "false":
        return output, False

    parsed = _parse_curl_command(command)

    # Get the payload to mutate
    payload = parsed.data or parsed.data_raw
    if not payload:
        # No payload to mutate, can't bypass
        return output, False

    try:
        from inferno.core.payload_mutator import get_payload_mutator
        from inferno.core.response_analyzer import get_response_analyzer

        mutator = get_payload_mutator()
        analyzer = get_response_analyzer()

        # Analyze what's blocking us
        is_blocked, status_code = _is_response_blocked(output)
        if not is_blocked:
            return output, False

        # Get detailed analysis
        analysis = analyzer.analyze(
            body=output,
            status_code=status_code or 403,
            headers={},
            original_payload=payload,
        )

        # Generate mutations
        context = _detect_payload_context(payload)
        waf_type = analysis.waf_type.value if analysis.waf_type else None

        mutation_result = mutator.mutate(
            payload=payload,
            context=context,
            max_mutations=5,
            waf_type=waf_type,
        )

        if not mutation_result.mutations:
            return output, False

        # Try mutations
        bypass_output = output
        bypass_output += f"\n\n{'='*60}\n"
        bypass_output += f"[AUTO-BYPASS] WAF detected: {analysis.waf_type.value if analysis.waf_type else 'unknown'}\n"
        bypass_output += f"[AUTO-BYPASS] Block type: {analysis.block_type.value}\n"
        bypass_output += f"[AUTO-BYPASS] Trying {len(mutation_result.mutations)} mutations...\n"

        for i, mutation in enumerate(mutation_result.mutations[:3]):  # Try top 3
            mutated_cmd = _rebuild_curl_command(parsed, mutation.mutated)

            bypass_output += f"\n[AUTO-BYPASS] Attempt {i+1}: {mutation.mutation_type.value}\n"
            bypass_output += f"  Payload: {mutation.mutated[:100]}{'...' if len(mutation.mutated) > 100 else ''}\n"

            # Execute mutated command
            try:
                process = await asyncio.create_subprocess_shell(
                    mutated_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=cwd,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
                retry_output = stdout.decode("utf-8", errors="replace")
                if stderr:
                    retry_output += "\n" + stderr.decode("utf-8", errors="replace")

                # Check if retry succeeded
                retry_blocked, retry_status = _is_response_blocked(retry_output)
                if not retry_blocked:
                    # SUCCESS!
                    mutator.record_result(payload, mutation.mutated, success=True)
                    bypass_output += "  [SUCCESS] Bypass worked!\n"
                    bypass_output += f"{'='*60}\n"
                    bypass_output += f"\n{retry_output}"

                    logger.info(
                        "curl_auto_bypass_success",
                        mutation_type=mutation.mutation_type.value,
                        original_payload_preview=payload[:50],
                    )
                    return bypass_output, True
                else:
                    bypass_output += f"  [FAILED] Still blocked (status: {retry_status})\n"
                    mutator.record_result(payload, mutation.mutated, success=False)

            except TimeoutError:
                bypass_output += "  [FAILED] Timeout\n"
            except Exception as e:
                bypass_output += f"  [FAILED] Error: {e}\n"

        # All mutations failed
        bypass_output += "\n[AUTO-BYPASS] All mutations failed.\n"
        bypass_output += "[AUTO-BYPASS] Manual bypasses to try:\n"
        for bypass in analysis.suggested_bypasses[:5]:
            bypass_output += f"  - {bypass}\n"
        bypass_output += f"{'='*60}\n"

        return bypass_output, False

    except ImportError as e:
        logger.warning("curl_bypass_import_error", error=str(e))
        return output, False
    except Exception as e:
        logger.error("curl_bypass_error", error=str(e))
        return output, False


async def _execute_docker_curl_with_auto_bypass(
    command: str,
    output: str,
    timeout: int,
    workdir: str,
    docker_manager: Any,
) -> tuple[str, bool]:
    """
    Attempt to bypass WAF by mutating payload and retrying via Docker.

    Returns:
        Tuple of (final_output, bypass_succeeded)
    """
    # Only proceed if enabled (default: enabled)
    if os.getenv("INFERNO_AUTO_BYPASS", "true").lower() == "false":
        return output, False

    parsed = _parse_curl_command(command)

    # Get the payload to mutate
    payload = parsed.data or parsed.data_raw
    if not payload:
        return output, False

    try:
        from inferno.core.payload_mutator import get_payload_mutator
        from inferno.core.response_analyzer import get_response_analyzer

        mutator = get_payload_mutator()
        analyzer = get_response_analyzer()

        # Analyze what's blocking us
        is_blocked, status_code = _is_response_blocked(output)
        if not is_blocked:
            return output, False

        # Get detailed analysis
        analysis = analyzer.analyze(
            body=output,
            status_code=status_code or 403,
            headers={},
            original_payload=payload,
        )

        # Generate mutations
        context = _detect_payload_context(payload)
        waf_type = analysis.waf_type.value if analysis.waf_type else None

        mutation_result = mutator.mutate(
            payload=payload,
            context=context,
            max_mutations=5,
            waf_type=waf_type,
        )

        if not mutation_result.mutations:
            return output, False

        # Try mutations via Docker
        bypass_output = output
        bypass_output += f"\n\n{'='*60}\n"
        bypass_output += f"[AUTO-BYPASS] WAF detected: {analysis.waf_type.value if analysis.waf_type else 'unknown'}\n"
        bypass_output += f"[AUTO-BYPASS] Block type: {analysis.block_type.value}\n"
        bypass_output += f"[AUTO-BYPASS] Trying {len(mutation_result.mutations)} mutations (Docker)...\n"

        for i, mutation in enumerate(mutation_result.mutations[:3]):
            mutated_cmd = _rebuild_curl_command(parsed, mutation.mutated)

            bypass_output += f"\n[AUTO-BYPASS] Attempt {i+1}: {mutation.mutation_type.value}\n"
            bypass_output += f"  Payload: {mutation.mutated[:100]}{'...' if len(mutation.mutated) > 100 else ''}\n"

            try:
                # Execute via Docker
                result = await docker_manager.execute_in_kali(
                    mutated_cmd,
                    timeout=timeout,
                    workdir=workdir,
                )
                retry_output = result["stdout"]
                if result["stderr"]:
                    retry_output += "\n" + result["stderr"]

                # Check if retry succeeded
                retry_blocked, retry_status = _is_response_blocked(retry_output)
                if not retry_blocked:
                    # SUCCESS!
                    mutator.record_result(payload, mutation.mutated, success=True)
                    bypass_output += "  [SUCCESS] Bypass worked!\n"
                    bypass_output += f"{'='*60}\n"
                    bypass_output += f"\n{retry_output}"

                    logger.info(
                        "docker_curl_auto_bypass_success",
                        mutation_type=mutation.mutation_type.value,
                        original_payload_preview=payload[:50],
                    )
                    return bypass_output, True
                else:
                    bypass_output += f"  [FAILED] Still blocked (status: {retry_status})\n"
                    mutator.record_result(payload, mutation.mutated, success=False)

            except Exception as e:
                bypass_output += f"  [FAILED] Error: {e}\n"

        # All mutations failed
        bypass_output += "\n[AUTO-BYPASS] All mutations failed.\n"
        bypass_output += "[AUTO-BYPASS] Manual bypasses to try:\n"
        for bypass in analysis.suggested_bypasses[:5]:
            bypass_output += f"  - {bypass}\n"
        bypass_output += f"{'='*60}\n"

        return bypass_output, False

    except ImportError as e:
        logger.warning("docker_curl_bypass_import_error", error=str(e))
        return output, False
    except Exception as e:
        logger.error("docker_curl_bypass_error", error=str(e))
        return output, False


# ============================================================================
# Timeout Calculation
# ============================================================================

def calculate_timeout(command: str, default: int = 120) -> int:
    """Calculate adaptive timeout based on command type."""
    cmd_lower = command.lower()

    # Very long (30 min) - full port scans, deep crawls
    if re.search(r'nmap.*-p-|masscan.*--rate\s+[0-9]{4,}|sqlmap.*--crawl', cmd_lower):
        return 1800

    # Long (10 min) - security tools
    if re.search(r'^(nmap|masscan|sqlmap|nikto|gobuster|ffuf|hydra|john|hashcat|nuclei|wfuzz)', cmd_lower):
        return 600

    # Medium (2 min) - network tools
    if re.search(r'^(curl|wget|dig|nc|ssh|ping|whois|git)', cmd_lower):
        return 120

    # Quick (30s) - basic commands
    if re.search(r'^(echo|cat|head|tail|grep|ls|pwd|whoami|id)', cmd_lower):
        return 30

    return default


# ============================================================================
# Environment Detection
# ============================================================================

def detect_environment() -> dict[str, Any]:
    """Detect the execution environment."""
    env = {
        "type": "local",
        "container": os.getenv("INFERNO_CONTAINER"),
        "ssh_host": os.getenv("SSH_HOST"),
        "ssh_user": os.getenv("SSH_USER"),
        "workspace": os.getenv("INFERNO_WORKSPACE", os.getcwd()),
    }

    if env["container"]:
        env["type"] = "container"
    elif env["ssh_host"] and env["ssh_user"]:
        env["type"] = "ssh"

    return env


def get_environment_info() -> str:
    """Get human-readable environment info."""
    env = detect_environment()
    lines = ["Current Environment:"]

    if env["type"] == "container":
        lines.append(f"  Container: {env['container'][:12]}")
    elif env["type"] == "ssh":
        lines.append(f"  SSH: {env['ssh_user']}@{env['ssh_host']}")
    else:
        lines.append("  Local execution")

    lines.append(f"  Workspace: {env['workspace']}")
    return "\n".join(lines)


# ============================================================================
# Main Execute Command Tool
# ============================================================================

@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="execute_command",
    description="""Execute any command on the target system.

This is the PRIMARY tool for running commands. Use it for:
- Security tools: nmap, sqlmap, gobuster, nikto, hydra, nuclei, etc.
- System commands: ls, cat, grep, find, whoami, id, etc.
- Network tools: curl, wget, nc, ssh, ping, dig, etc.
- Scripts: python, bash, perl, ruby, etc.
- Everything else - just run the command you need.

The system auto-detects the environment (local, container, SSH) and
handles timeouts adaptively based on command type.

Special commands for session management:
- "sessions" - list active sessions with friendly IDs (S1, S2, S3...)
- "output S1" - get output from session S1 (or use full ID)
- "kill S1" - terminate session S1
- "kill all" - terminate all sessions
- "env info" - show current execution environment

Sessions support friendly IDs (S1, S2, etc.) for easier reference.
You can also use #1, 1, or the full session ID.
""",
)
async def execute_command(
    command: str,
    timeout: int | None = None,
    interactive: bool = False,
    session_id: str | None = None,
    working_dir: str | None = None,
) -> ToolResult:
    """
    Execute any command on the target system.

    Args:
        command: The complete command to execute (e.g., "nmap -sV target.com",
                 "sqlmap -u 'http://target/page?id=1' --batch", "ls -la")
        timeout: Command timeout in seconds. Auto-calculated if not specified.
                 Max: 3600 (1 hour).
        interactive: Set True for commands needing persistent sessions
                    (ssh, nc, python REPL, etc.)
        session_id: Send command to existing session instead of starting new one.
        working_dir: Working directory for command execution.

    Returns:
        Command output or session info for interactive commands.

    Examples:
        execute_command("nmap -sV -sC 192.168.1.1")
        execute_command("sqlmap -u 'http://target/vuln?id=1' --batch --dbs")
        execute_command("gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt")
        execute_command("curl -X POST http://target/api -d 'user=admin'")
        execute_command("ssh user@host", interactive=True)  # Creates session S1
        execute_command("whoami", session_id="S1")  # Send to session S1
        execute_command("output S1")  # Get output from session S1
        execute_command("sessions")  # List all sessions
        execute_command("kill S1")  # Terminate session S1
    """
    # Handle special session management commands
    cmd_lower = command.strip().lower()

    if cmd_lower in ("sessions", "session list", "list sessions"):
        return ToolResult(success=True, output=list_sessions())

    if cmd_lower.startswith("output "):
        sid = command.split(None, 1)[1]
        output = await get_session_output_async(sid)
        return ToolResult(success=True, output=output)

    if cmd_lower.startswith("kill "):
        sid = command.split(None, 1)[1]
        result = await kill_session(sid)
        return ToolResult(success=True, output=result)

    if cmd_lower == "kill all" or cmd_lower == "terminate all":
        result = terminate_all_sessions()
        return ToolResult(success=True, output=result)

    if cmd_lower in ("env info", "environment info"):
        return ToolResult(success=True, output=get_environment_info())

    if not command.strip():
        return ToolResult(success=False, output="", error="No command provided")

    # Security: Check for Unicode homograph bypass
    guardrails_enabled = os.getenv("INFERNO_GUARDRAILS", "true").lower() != "false"
    if guardrails_enabled:
        has_homographs, normalized = detect_unicode_homographs(command)
        if has_homographs:
            dangerous = ['curl', 'wget', 'nc', 'bash', 'sh ', 'exec', 'eval']
            if any(d in normalized.lower() for d in dangerous):
                if '$(' in normalized or '`' in normalized:
                    return ToolResult(
                        success=False, output="",
                        error="Blocked: Unicode homograph bypass attempt detected"
                    )

    # Security: Check command safety
    is_safe, reason = is_command_safe(command)
    if not is_safe:
        logger.warning("blocked_command", command=command[:100], reason=reason)
        return ToolResult(success=False, output="", error=f"Command blocked: {reason}")

    # Calculate timeout
    if timeout is None:
        timeout = calculate_timeout(command)
    else:
        timeout = min(timeout, 3600)

    # Set working directory
    cwd: Path | str | None = None
    if working_dir:
        cwd = Path(working_dir)
        if not cwd.exists():
            return ToolResult(
                success=False, output="",
                error=f"Working directory does not exist: {working_dir}"
            )
    elif os.getenv("INFERNO_ARTIFACTS_DIR"):
        cwd = os.environ["INFERNO_ARTIFACTS_DIR"]

    # Handle sending to existing session
    if session_id:
        resolved_sid = resolve_session_id(session_id)
        if resolved_sid:
            session = get_session(resolved_sid)
            if session and session.is_running:
                result = send_to_session(resolved_sid, command)
                await asyncio.sleep(0.5)  # Wait for response
                output = shell_get_output(resolved_sid, clear=True)
                friendly = session.friendly_id or resolved_sid[:8]
                return ToolResult(
                    success=True,
                    output=output or result,
                    metadata={"session_id": resolved_sid, "friendly_id": friendly}
                )
        return ToolResult(success=False, output="", error=f"Session not found: {session_id}")

    # Handle interactive commands with ShellSession (PTY-based)
    if interactive:
        try:
            # Create a new PTY-based shell session
            new_sid = create_shell_session(
                command=command,
                workspace_dir=str(cwd) if cwd else None,
            )

            if new_sid.startswith("Failed:"):
                return ToolResult(success=False, output="", error=new_sid)

            # Get the session to retrieve friendly ID
            session = get_session(new_sid)
            friendly = session.friendly_id if session else new_sid[:8]

            return ToolResult(
                success=True,
                output=f"Interactive session started: {friendly} ({new_sid[:8]})\n"
                       f"Use 'output {friendly}' to get output\n"
                       f"Use session_id='{friendly}' to send commands\n"
                       f"Use 'kill {friendly}' to terminate",
                metadata={"session_id": new_sid, "friendly_id": friendly}
            )
        except Exception as e:
            logger.error("session_start_failed", error=str(e))
            return ToolResult(success=False, output="", error=f"Failed to start session: {e}")

    # Standard command execution
    logger.info("executing_command", command=command[:200], timeout=timeout)

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except TimeoutError:
            # Graceful termination
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except TimeoutError:
                process.kill()
                await process.wait()

            return ToolResult(
                success=False, output="",
                error=f"Command timed out after {timeout}s",
                metadata={"timeout": timeout}
            )

        # Decode output
        stdout_str = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_str = stderr.decode("utf-8", errors="replace") if stderr else ""

        # Combine output
        if stdout_str and stderr_str:
            output = f"{stdout_str}\n\nSTDERR:\n{stderr_str}"
        else:
            output = stdout_str or stderr_str

        # Truncate large output
        max_size = 100000
        if len(output) > max_size:
            output = output[:max_size] + f"\n\n[Output truncated at {max_size} chars]"

        success = process.returncode == 0

        logger.info(
            "command_complete",
            return_code=process.returncode,
            output_length=len(output),
        )

        # ================================================================
        # CURL AUTO-BYPASS: If curl command got blocked, try mutations
        # ================================================================
        if _is_curl_command(command):
            is_blocked, status_code = _is_response_blocked(output)
            if is_blocked:
                logger.info(
                    "curl_blocked_detected",
                    status_code=status_code,
                    command_preview=command[:100],
                )
                # Try auto-bypass with payload mutations
                bypass_output, bypass_succeeded = await _execute_curl_with_auto_bypass(
                    command=command,
                    output=output,
                    timeout=timeout,
                    cwd=cwd,
                )
                return ToolResult(
                    success=bypass_succeeded,
                    output=bypass_output,
                    error=None if bypass_succeeded else f"Blocked (status: {status_code})",
                    metadata={
                        "return_code": process.returncode,
                        "command": command,
                        "auto_bypass_attempted": True,
                        "auto_bypass_succeeded": bypass_succeeded,
                    }
                )
        # ================================================================

        return ToolResult(
            success=success,
            output=output,
            error=None if success else f"Exit code: {process.returncode}",
            metadata={"return_code": process.returncode, "command": command}
        )

    except Exception as e:
        logger.error("command_error", error=str(e), exc_info=True)
        return ToolResult(success=False, output="", error=f"Execution failed: {e}")


# ============================================================================
# Minimal Tools for Container-Based Execution (3-Tool Architecture)
# ============================================================================
# These tools are designed for the minimal prompt system with Docker execution.
# They provide a cleaner API and integrate with the Kali container.

# Global Docker manager instance (lazy loaded)
_docker_manager = None


def _get_docker_manager():
    """Get or create the Docker manager instance."""
    global _docker_manager
    if _docker_manager is None:
        from inferno.setup.docker_manager import DockerManager
        _docker_manager = DockerManager()
    return _docker_manager


@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="generic_linux_command",
    description="""Execute any Linux command in the Kali container.

Use for ALL command-line tools:
- Network: nmap, masscan, ping, dig, whois, nc, curl, wget
- Web: gobuster, ffuf, nikto, wpscan, sqlmap, nuclei
- Recon: subfinder, amass, sublist3r, assetfinder
- Exploit: msfconsole, searchsploit, hydra, john, hashcat
- Utils: grep, find, cat, head, tail, awk, sed, jq

Wordlists are available at /wordlists/
Workspace for saving files: /workspace/
""",
)
async def generic_linux_command(
    command: str,
    timeout: int = 300,
    workdir: str = "/workspace",
) -> ToolResult:
    """
    Execute any Linux command in the Kali container.

    Args:
        command: The command to execute (e.g., "nmap -sV target.com")
        timeout: Timeout in seconds (default: 300, max: 3600)
        workdir: Working directory (default: /workspace)

    Returns:
        ToolResult with stdout, stderr, and return code.

    Examples:
        generic_linux_command("nmap -sV -sC 10.10.10.1")
        generic_linux_command("gobuster dir -u http://target -w /wordlists/common-dirs.txt")
        generic_linux_command("sqlmap -u 'http://target/page?id=1' --batch --dbs")
        generic_linux_command("curl -s http://target/api/users | jq .")
    """
    if not command.strip():
        return ToolResult(success=False, output="", error="No command provided")

    # Security checks (reuse existing)
    guardrails_enabled = os.getenv("INFERNO_GUARDRAILS", "true").lower() != "false"
    if guardrails_enabled:
        has_homographs, normalized = detect_unicode_homographs(command)
        if has_homographs:
            dangerous = ['curl', 'wget', 'nc', 'bash', 'sh ', 'exec', 'eval']
            if any(d in normalized.lower() for d in dangerous):
                if '$(' in normalized or '`' in normalized:
                    return ToolResult(
                        success=False, output="",
                        error="Blocked: Unicode homograph bypass attempt detected"
                    )

    is_safe, reason = is_command_safe(command)
    if not is_safe:
        return ToolResult(success=False, output="", error=f"Command blocked: {reason}")

    # Cap timeout
    timeout = min(timeout, 3600)

    # Execute in Docker container
    docker = _get_docker_manager()
    result = await docker.execute_in_kali(command, timeout=timeout, workdir=workdir)

    output = result["stdout"]
    if result["stderr"]:
        if output:
            output += f"\n\nSTDERR:\n{result['stderr']}"
        else:
            output = result["stderr"]

    # Truncate large output
    max_size = 100000
    if len(output) > max_size:
        output = output[:max_size] + f"\n\n[Output truncated at {max_size} chars]"

    # ================================================================
    # CURL AUTO-BYPASS: If curl command got blocked, try mutations
    # ================================================================
    if _is_curl_command(command):
        is_blocked, status_code = _is_response_blocked(output)
        if is_blocked:
            logger.info(
                "docker_curl_blocked_detected",
                status_code=status_code,
                command_preview=command[:100],
            )
            # Try auto-bypass with Docker execution
            bypass_output, bypass_succeeded = await _execute_docker_curl_with_auto_bypass(
                command=command,
                output=output,
                timeout=timeout,
                workdir=workdir,
                docker_manager=docker,
            )
            return ToolResult(
                success=bypass_succeeded,
                output=bypass_output,
                error=None if bypass_succeeded else f"Blocked (status: {status_code})",
                metadata={
                    "return_code": result["return_code"],
                    "command": command,
                    "auto_bypass_attempted": True,
                    "auto_bypass_succeeded": bypass_succeeded,
                }
            )
    # ================================================================

    return ToolResult(
        success=result["success"],
        output=output,
        error=None if result["success"] else f"Exit code: {result['return_code']}",
        metadata={"return_code": result["return_code"], "command": command}
    )


@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="execute_code",
    description="""Execute Python or Bash code/scripts in the Kali container.

Use for:
- Custom exploits and payloads
- Data processing and parsing
- Complex logic that can't be done with simple commands
- Multi-step automation

Supports: python, python3, bash, sh
""",
)
async def execute_code(
    code: str,
    language: str = "python",
    timeout: int = 300,
    save_as: str | None = None,
) -> ToolResult:
    """
    Execute code in the Kali container.

    Args:
        code: The code to execute (multi-line supported)
        language: Programming language (python, python3, bash, sh)
        timeout: Timeout in seconds (default: 300, max: 3600)
        save_as: Optional filename to save the script in /workspace/

    Returns:
        ToolResult with execution output.

    Examples:
        execute_code('''
import requests
r = requests.get("http://target/api")
print(r.json())
''', language="python")

        execute_code('''
for i in $(seq 1 100); do
    curl -s "http://target/user/$i"
done
''', language="bash")
    """
    if not code.strip():
        return ToolResult(success=False, output="", error="No code provided")

    # Validate language
    supported = {"python", "python3", "bash", "sh"}
    if language not in supported:
        return ToolResult(
            success=False, output="",
            error=f"Unsupported language: {language}. Use: {supported}"
        )

    timeout = min(timeout, 3600)
    docker = _get_docker_manager()

    # If save_as is provided, save the script first
    if save_as:
        save_path = f"/workspace/{save_as}"
        # Escape single quotes in code for shell
        escaped_code = code.replace("'", "'\\''")
        save_cmd = f"cat > {save_path} << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"
        await docker.execute_in_kali(save_cmd, timeout=10)

        # Make executable if bash/sh
        if language in ("bash", "sh"):
            await docker.execute_in_kali(f"chmod +x {save_path}", timeout=5)

    # Build execution command
    if language in ("python", "python3"):
        # Use heredoc for Python
        cmd = f"python3 << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"
    else:
        # Bash/sh
        cmd = f"bash << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"

    result = await docker.execute_in_kali(cmd, timeout=timeout, workdir="/workspace")

    output = result["stdout"]
    if result["stderr"]:
        if output:
            output += f"\n\nSTDERR:\n{result['stderr']}"
        else:
            output = result["stderr"]

    metadata = {"return_code": result["return_code"], "language": language}
    if save_as:
        metadata["saved_to"] = f"/workspace/{save_as}"

    return ToolResult(
        success=result["success"],
        output=output,
        error=None if result["success"] else f"Exit code: {result['return_code']}",
        metadata=metadata
    )


# Export all tools
# Note: web_request removed - use HTTPTool instead (or curl via generic_linux_command)
__all__ = [
    "execute_code",
    "execute_command",
    "generic_linux_command",
]
