# SwarmCoordinator - Intelligent Agent Orchestration

The `SwarmCoordinator` provides proactive agent orchestration for Inferno-AI, replacing reactive "stuck-based" spawning with strategic planning and deployment.

## Overview

Traditional agent spawning is reactive - agents are spawned only when the main agent gets "stuck" (errors, no findings, etc.). The SwarmCoordinator introduces **proactive orchestration**:

- **Pre-planning**: Analyzes target and objective to create an assessment plan
- **Rule-based spawning**: Automatically spawns agents based on context triggers
- **Attack chain synthesis**: Connects findings into exploitable sequences
- **Shared knowledge**: All agents share discoveries via knowledge graph

## Key Features

### 1. Assessment Planning

Pre-plans the entire assessment based on target analysis:

```python
from inferno.swarm import SwarmCoordinator

coordinator = SwarmCoordinator(client, registry, knowledge_graph)
coordinator.set_swarm_tool(swarm_tool)

plan = await coordinator.plan_assessment(
    target="https://example.com",
    objective="Full security assessment",
    ctf_mode=False,
)

# Plan contains:
# - phases: [INITIAL, RECONNAISSANCE, SCANNING, EXPLOITATION, VALIDATION, REPORTING]
# - initial_spawns: Agents to spawn immediately (recon, scanner)
# - spawn_rules: Conditional rules for dynamic spawning
# - estimated_duration_minutes: Time estimate
```

### 2. Proactive Spawn Rules

Agents are spawned automatically based on context triggers:

| Rule | Trigger | Agents Spawned | Priority |
|------|---------|----------------|----------|
| `assessment_start` | Initial phase | `reconnaissance`, `scanner` | 10 |
| `waf_detected` | WAF detected | `analyzer` | 9 |
| `sqli_found` | SQL injection found | `exploiter` | 9 |
| `rce_found` | RCE found | `exploiter`, `post_exploitation` | 10 |
| `jwt_found` | JWT tokens found | `analyzer` | 8 |
| `credentials_found` | Credentials discovered | `post_exploitation` | 8 |
| `api_discovered` | API endpoints found | `scanner` | 7 |
| `file_upload_found` | File upload vuln | `exploiter` | 8 |
| `high_severity_cluster` | 3+ high/critical findings | `validator` | 6 |

Example:

```python
# Automatically checks spawn rules
decision = coordinator.get_spawn_decision(
    current_phase=Phase.SCANNING,
    metrics=coordinator._get_current_metrics(),
    recent_findings=all_findings,
)

if decision:
    # Rule triggered - agents will be spawned
    print(f"Rule '{decision['rule']}' triggered")
    print(f"Spawning: {decision['agents']}")
```

### 3. Attack Chain Synthesis

Identifies exploitable sequences of vulnerabilities:

```python
chains = await coordinator.synthesize_findings()

for chain in chains:
    print(f"{chain.name} - {chain.severity}")
    print(f"  Steps: {len(chain.steps)}")
    print(f"  Impact: {chain.impact}")
    print(f"  Exploitability: {chain.estimated_exploitability:.1%}")
```

**Detected patterns:**

1. **SQLi → Data Extraction**: SQL injection leading to database access
2. **SSRF → Internal Network Access**: SSRF enabling internal recon
3. **File Upload → RCE**: File upload chained with code execution
4. **XSS + CSRF → Account Takeover**: Combined client-side attacks

### 4. CTF Mode

Optimized for Capture The Flag competitions:

```python
plan = await coordinator.plan_assessment(
    target="http://ctf.example.com",
    objective="Capture the flag",
    ctf_mode=True,  # Aggressive parallel spawning
)

# CTF mode enables:
# - Parallel initial spawning (recon + scanner simultaneously)
# - Shorter estimated duration (15 min vs 30 min)
# - Exploitation phase by default
# - Aggressive spawn rule thresholds
```

## Architecture

### Data Models

**AssessmentPlan**:
```python
@dataclass
class AssessmentPlan:
    target: str
    objective: str
    phases: list[Phase]
    initial_spawns: list[AgentSpawnSpec]
    spawn_rules: dict[str, dict[str, Any]]
    estimated_duration_minutes: int
    ctf_mode: bool
```

**AgentSpawnSpec**:
```python
@dataclass
class AgentSpawnSpec:
    agent_type: SubAgentType
    task: str
    context: str = ""
    priority: int = 1  # 1-10
    dependencies: list[str] = []  # Agent IDs
    metadata: dict[str, Any] = {}
```

**AgentInstance**:
```python
@dataclass
class AgentInstance:
    agent_id: str
    agent_type: SubAgentType
    task: str
    spawned_at: datetime
    completed_at: datetime | None
    status: str  # running, completed, failed
    findings: list[dict[str, Any]]
    tokens_used: int
    turns_used: int
    error: str | None
```

**AttackChain**:
```python
@dataclass
class AttackChain:
    chain_id: str
    name: str
    steps: list[Finding]
    impact: str
    severity: Severity
    requires_interaction: bool
    estimated_exploitability: float  # 0.0-1.0
```

### Workflow

1. **Planning Phase**:
   ```python
   plan = await coordinator.plan_assessment(target, objective, ctf_mode)
   ```
   - Analyzes objective keywords (web, ctf, api, network)
   - Determines assessment phases
   - Creates initial spawn specs
   - Configures spawn rules

2. **Execution Phase**:
   ```python
   result = await coordinator.execute_plan(plan, max_agents=10, max_parallel=3)
   ```
   - Spawns initial agents (reconnaissance, scanner)
   - Monitors for spawn rule triggers
   - Dynamically spawns additional agents
   - Waits for all agents to complete

3. **Finding Handling**:
   ```python
   await coordinator.handle_finding(agent_id, finding)
   ```
   - Adds to global findings list
   - Updates agent instance
   - Stores in knowledge graph
   - May trigger spawn rules

4. **Synthesis Phase**:
   ```python
   chains = await coordinator.synthesize_findings()
   ```
   - Groups related findings
   - Identifies attack chain patterns
   - Calculates exploitability scores

## Usage Examples

### Basic Assessment

```python
from anthropic import AsyncAnthropic
from inferno.swarm import SwarmCoordinator, SwarmTool
from inferno.tools.registry import ToolRegistry

client = AsyncAnthropic(api_key="...")
registry = ToolRegistry()

coordinator = SwarmCoordinator(client, registry, operation_id="op_001")
swarm_tool = SwarmTool(client, registry, operation_id="op_001")
coordinator.set_swarm_tool(swarm_tool)

# Plan and execute
plan = await coordinator.plan_assessment(
    target="https://example.com",
    objective="Full security assessment",
)

result = await coordinator.execute_plan(plan, max_agents=10)

print(f"Spawned: {len(result.agents_spawned)} agents")
print(f"Findings: {len(result.findings)}")
print(f"Attack chains: {len(result.attack_chains)}")
```

### Manual Agent Spawning

```python
# Spawn specific agent with dependencies
recon_id = await coordinator.spawn_agent(
    agent_type="reconnaissance",
    task="Enumerate subdomains of example.com",
)

# Wait for recon, then spawn scanner
scanner_id = await coordinator.spawn_agent(
    agent_type="scanner",
    task="Scan discovered endpoints",
    dependencies=[recon_id],
)
```

### Custom Spawn Rules

```python
# Add custom spawn rule
plan.spawn_rules["graphql_detected"] = {
    "trigger": lambda ctx: any("graphql" in f.get("location", "") for f in ctx["findings"]),
    "agents": [SubAgentType.SCANNER],
    "parallel": False,
    "priority": 8,
    "description": "GraphQL introspection and testing",
    "task_template": "Test GraphQL endpoint for introspection and injection",
}
```

### Reporting Findings

```python
# Report finding from agent
await coordinator.handle_finding(
    agent_id="scanner_001",
    finding={
        "vuln_type": "xss",
        "severity": "high",
        "target": "https://example.com/search",
        "location": "/search?q=",
        "title": "Reflected XSS in Search",
        "description": "User input reflected without sanitization",
        "evidence": "Payload: <script>alert(1)</script>",
        "remediation": "Implement output encoding",
        "cvss_score": 7.3,
    }
)
```

## Integration with Existing Systems

### Knowledge Graph Integration

```python
from inferno.core.knowledge import KnowledgeGraph

kg = KnowledgeGraph()
coordinator = SwarmCoordinator(client, registry, knowledge_graph=kg)

# Findings are automatically added to knowledge graph
await coordinator.handle_finding(agent_id, finding)

# Query knowledge graph
entries = await kg.search("sql injection", limit=5)
```

### Validation Agent Integration

```python
from inferno.swarm.validation_agent import ValidationOrchestrator

validator = ValidationOrchestrator(client, registry)
coordinator = SwarmCoordinator(client, registry)

# Findings can be validated
for finding in coordinator._all_findings:
    validated = await validator.validate_pending()
```

## Configuration

### Environment Variables

- `INFERNO_MAX_SWARM_AGENTS`: Maximum total agents (default: 10)
- `INFERNO_MAX_PARALLEL_AGENTS`: Maximum parallel agents (default: 3)
- `INFERNO_CTF_MODE`: Enable CTF optimizations (default: false)

### Performance Tuning

```python
# Adjust spawning limits
result = await coordinator.execute_plan(
    plan,
    max_agents=20,       # Allow up to 20 agents
    max_parallel=5,      # Run 5 in parallel
)

# Customize spawn rule priorities
for rule in plan.spawn_rules.values():
    if "sqli" in rule["description"].lower():
        rule["priority"] = 10  # Highest priority
```

## Best Practices

1. **Always set SwarmTool before execution**:
   ```python
   coordinator.set_swarm_tool(swarm_tool)
   ```

2. **Use CTF mode for time-sensitive assessments**:
   ```python
   plan = await coordinator.plan_assessment(target, objective, ctf_mode=True)
   ```

3. **Monitor active agents**:
   ```python
   metrics = coordinator._get_current_metrics()
   print(f"Active: {metrics['active_agents']}, Completed: {metrics['completed_agents']}")
   ```

4. **Synthesize findings after completion**:
   ```python
   result = await coordinator.execute_plan(plan)
   chains = await coordinator.synthesize_findings()
   ```

5. **Integrate with knowledge graph for cross-agent sharing**:
   ```python
   coordinator = SwarmCoordinator(client, registry, knowledge_graph=kg)
   ```

## Limitations

- Maximum 50 total agents per assessment
- Spawn rules evaluated sequentially (first match wins)
- Attack chain synthesis uses predefined patterns
- No real-time agent communication (use message bus for that)

## Future Enhancements

- [ ] Machine learning-based spawn predictions
- [ ] Dynamic spawn rule learning from past assessments
- [ ] Real-time agent collaboration patterns
- [ ] Custom attack chain templates
- [ ] Multi-target coordinated assessments
- [ ] Cost-aware agent spawning
- [ ] Priority-based agent scheduling

## See Also

- `swarm/tool.py` - SwarmTool implementation
- `swarm/agents.py` - Sub-agent configurations
- `swarm/validation_agent.py` - Finding validation
- `swarm/synthesis.py` - Attack chain synthesis
- `core/knowledge.py` - Knowledge graph
