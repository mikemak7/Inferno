# Strategic Prompt Templates

Comprehensive Mako-based templates for injecting rich contextual intelligence into Inferno-AI agent prompts.

## Overview

These templates transform raw assessment data into actionable strategic guidance for the agent. Each template focuses on a specific aspect of the assessment and provides:

- Current state analysis
- Prioritized action items
- Attack patterns and techniques
- Tool recommendations
- Success indicators

## Templates

### 1. Application Model Context (`application_model_context.md`)

Injects understanding of the target application's structure and attack surface.

**Context Variables:**
- `model`: ApplicationModel object with endpoints, parameters, tech stack

**Provides:**
- Technology stack fingerprinting with attack implications
- Discovered endpoints ranked by attack surface
- Identity parameters for IDOR testing (HIGH PRIORITY)
- Authentication patterns and testing strategies
- Response fingerprints for blind attack detection
- Business logic workflows
- High-value attack surfaces

**Usage:**
```python
from inferno.prompts.mako_engine import get_mako_engine, TemplateContext

engine = get_mako_engine()
context = TemplateContext(
    model=application_model,  # ApplicationModel instance
)
guidance = engine.render("strategic/application_model_context.md", context)
```

**Key Features:**
- Automatic prioritization of endpoints by parameter count and auth requirements
- Tech stack-specific attack recommendations (PHP→LFI, Node.js→Prototype pollution)
- Identity parameter detection for IDOR opportunities
- Response fingerprinting for blind attacks

---

### 2. Attack Plan Context (`attack_plan_context.md`)

Provides strategic assessment roadmap and progress tracking.

**Context Variables:**
- `plan`: AttackPlan object with phases, steps, findings, token budget

**Provides:**
- Current phase and overall progress (15% → 100%)
- Phase-specific objectives and checklists
- Prioritized attack steps (next 10 actions)
- Attack chains to explore
- Token budget allocation and tracking
- Findings summary by severity
- Branch points for backtracking
- Recommended next targets

**Usage:**
```python
context = TemplateContext(
    plan=attack_plan,  # AttackPlan instance
)
guidance = engine.render("strategic/attack_plan_context.md", context)
```

**Phases:**
1. RECONNAISSANCE (15%) - Fingerprint, enumerate, gather intel
2. MAPPING (30%) - Catalog parameters, workflows, identify roles
3. VULNERABILITY_DISCOVERY (60%) - Test for vulns systematically
4. EXPLOITATION (85%) - Develop exploits, chain attacks
5. POST_EXPLOITATION (95%) - Persist, pivot, exfiltrate
6. REPORTING (100%) - Document findings, generate PoCs

**Key Features:**
- CTF mode optimization (speed over thoroughness)
- Token budget management (alert at 50%, 75% usage)
- Stuck detection (N turns without progress → recommendations)
- Branch tracking for systematic exploration

---

### 3. Parameter Role Guidance (`parameter_role_guidance.md`)

Role-based parameter testing strategies with attack patterns and payloads.

**Context Variables:**
- `parameter_roles`: Dict[str, List[Parameter]] - Parameters grouped by role
- `parameter_correlations`: List[Correlation] - Cross-parameter relationships

**Provides:**
- Role-specific attack patterns for 7 parameter types:
  - **IDENTITY** - IDOR, horizontal/vertical privilege escalation
  - **COMMAND** - OS command injection, SQLi, SSTI, XXE, code injection
  - **TEMPLATE** - SSTI, XSS, HTML injection
  - **FILTER** - SQL/NoSQL injection, LDAP injection
  - **NAVIGATION** - Path traversal, LFI, RFI
  - **REDIRECT** - Open redirect, SSRF, DNS rebinding
  - **CONFIGURATION** - Mass assignment, business logic bypass
- Testing priorities by role (IDENTITY = CRITICAL)
- Recommended payloads and tools
- Encoding/obfuscation techniques for WAF bypass
- Multi-stage validation strategies

**Usage:**
```python
context = TemplateContext(
    parameter_roles={
        'IDENTITY': [param1, param2, ...],
        'COMMAND': [param3, param4, ...],
        # ...
    },
    parameter_correlations=[corr1, corr2, ...],
)
guidance = engine.render("strategic/parameter_role_guidance.md", context)
```

**Key Features:**
- 90% of bug bounties involve IDENTITY params (broken access control)
- Attack patterns with code examples for each role
- WAF bypass techniques (encoding, obfuscation, mutation)
- Cross-parameter attack strategies (pollution, precedence)

---

### 4. Chain Discovery Context (`chain_discovery_context.md`)

Attack chain intelligence for multi-step exploitation.

**Context Variables:**
- `chains`: List[AttackChain] - Discovered attack chains with scores
- `chain_patterns`: List[Pattern] - Active patterns detected
- `correlation_triggers`: List[Trigger] - Finding combinations that create chains
- `ctf_mode`: bool - CTF optimization flag

**Provides:**
- Chains ranked by score (8.0+ = high value)
- Step-by-step exploitation flows
- 10 common chain patterns:
  1. Info Disclosure → Privilege Escalation
  2. XSS → Account Takeover
  3. SSRF → Cloud Metadata → RCE
  4. SQLi → File Write → RCE
  5. Auth Bypass → IDOR → Data Exfiltration
  6. CSRF → Privileged Action
  7. Race Condition → Business Logic Bypass
  8. Deserialization → RCE
  9. XXE → File Read → Credential Extraction
  10. Subdomain Takeover → Phishing/Cookie Theft
- Chain execution strategy (CTF vs Bug Bounty)
- Parallel execution recommendations
- Failed chain analysis

**Usage:**
```python
context = TemplateContext(
    chains=[chain1, chain2, ...],
    chain_patterns=[pattern1, pattern2, ...],
    correlation_triggers=[trigger1, trigger2, ...],
    ctf_mode=True,
)
guidance = engine.render("strategic/chain_discovery_context.md", context)
```

**Key Features:**
- Automatic chain detection heuristics (SQLi + File Write = RCE)
- Chain dependency graphs for execution ordering
- Parallel execution support via sub-agents
- PoC generation for successful chains

---

## Integration with Mako Engine

All templates use Mako syntax for dynamic content:

```mako
## Conditionals
% if model.endpoints:
Found ${len(model.endpoints)} endpoints
% else:
No endpoints discovered yet
% endif

## Loops
% for endpoint in model.endpoints[:10]:
- ${endpoint.method} ${endpoint.path}
% endfor

## Functions (defs)
<%def name="format_step(step, idx)">
${idx}. ${step.action} [Priority: ${step.priority}/10]
</%def>

## Inline Python
<%
sorted_chains = sorted(chains, key=lambda c: c.score, reverse=True)
%>
```

## Rendering Templates

### Basic Usage

```python
from inferno.prompts.mako_engine import get_mako_engine, TemplateContext
from inferno.prompts.strategic import get_template_path

engine = get_mako_engine()

# Render by path
template_path = get_template_path("application_model")
context = TemplateContext(model=app_model)
guidance = engine.render(str(template_path), context)
```

### Integration with Prompt Builder

```python
from inferno.agent.prompts import SystemPromptBuilder

builder = SystemPromptBuilder()

# Add strategic context to system prompt
builder.add_section("Application Intelligence", app_model_guidance)
builder.add_section("Attack Plan", attack_plan_guidance)
builder.add_section("Parameter Testing", parameter_guidance)
builder.add_section("Attack Chains", chain_guidance)

system_prompt = builder.build()
```

### Dynamic Injection During Assessment

```python
from inferno.agent.sdk_executor import SDKExecutor

class IntelligentExecutor(SDKExecutor):
    async def _build_enhanced_prompt(self, turn_number: int):
        """Build prompt with strategic context."""
        base_prompt = self._build_system_prompt()

        # Render strategic templates with current state
        app_context = self._render_template("application_model",
                                           model=self.app_model)
        plan_context = self._render_template("attack_plan",
                                            plan=self.attack_plan)
        param_context = self._render_template("parameter_roles",
                                             parameter_roles=self.param_roles)
        chain_context = self._render_template("chain_discovery",
                                             chains=self.discovered_chains)

        # Combine
        return f"{base_prompt}\n\n{app_context}\n\n{plan_context}\n\n{param_context}\n\n{chain_context}"
```

## Context Object Schemas

### ApplicationModel

```python
@dataclass
class ApplicationModel:
    base_url: str
    endpoints: List[Endpoint]
    tech_stack: Dict[str, int]  # {tech: confidence%}
    auth_patterns: List[AuthPattern]
    identity_parameters: List[Parameter]
    response_fingerprints: List[Fingerprint]
    workflows: List[Workflow]
    high_value_targets: List[Target]
    data_flows: List[DataFlow]
    parameter_relationships: List[Relationship]
```

### AttackPlan

```python
@dataclass
class AttackPlan:
    current_phase: str  # RECONNAISSANCE, MAPPING, etc.
    attack_steps: List[AttackStep]
    attack_chains: List[AttackChain]
    findings: List[Finding]
    total_token_budget: int
    tokens_used: int
    time_remaining: Optional[str]
    ctf_mode: bool
    next_targets: List[Target]
    branch_points: List[BranchPoint]
    scope_restrictions: List[str]
    rate_limits: Dict[str, RateLimit]
    waf_detected: bool
```

### AttackChain

```python
@dataclass
class AttackChain:
    name: str
    score: float  # 0-10
    impact: str  # CRITICAL, HIGH, MEDIUM, LOW
    complexity: str  # EASY, MEDIUM, HARD
    steps: List[ChainStep]
    prerequisites: List[str]
    impact_description: str
    tested: bool
    success: bool
    failure_reason: Optional[str]
    poc: Optional[str]
    cvss_score: Optional[float]
```

## Best Practices

1. **Progressive Enhancement**: Start with basic prompts, add strategic context as data accumulates
2. **Conditional Rendering**: Templates gracefully handle missing data with helpful guidance
3. **Token Efficiency**: Templates are comprehensive but use conditionals to avoid bloat
4. **Actionable Guidance**: Every section provides specific next steps, not just information
5. **Tool Integration**: Templates reference specific Inferno tools by name
6. **Context Freshness**: Re-render templates each turn to reflect latest state

## Performance

- Templates render in <50ms even with large datasets
- Efficient conditionals prevent rendering unused sections
- Mako compilation caches templates for fast re-rendering
- Strategic context typically adds 2-5K tokens to prompts

## Examples

See `examples/strategic_prompts/` for complete usage examples.

## Contributing

When adding new strategic templates:

1. Use Mako syntax (not basic `{{ }}` if possible)
2. Handle missing data gracefully with `% if` conditionals
3. Provide actionable guidance, not just information dumps
4. Include tool recommendations with specific names
5. Add success indicators for each recommended action
6. Update `TEMPLATES` dict in `__init__.py`
7. Document context schema in this README
