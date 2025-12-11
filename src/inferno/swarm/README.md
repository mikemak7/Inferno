# Swarm Coordination System

The Inferno-AI swarm system enables multiple specialized agents to work together efficiently through:

1. **MessageBus** - Real-time inter-agent communication
2. **SynthesisEngine** - Finding correlation and attack chain discovery
3. **SwarmTool** - Sub-agent spawning and coordination

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Meta-Agent                            │
│                  (Strategic Decisions)                       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        │ spawns via SwarmTool
                        ▼
        ┌───────────────┴───────────────┐
        │                               │
   ┌────▼─────┐                    ┌───▼──────┐
   │  Recon   │◄──MessageBus───────►│ Scanner  │
   │  Agent   │                     │  Agent   │
   └────┬─────┘                     └───┬──────┘
        │                               │
        │   findings broadcast          │ findings broadcast
        │                               │
        └───────────┬───────────────────┘
                    ▼
          ┌─────────────────┐
          │ SynthesisEngine │
          │   (correlates   │
          │    findings)    │
          └─────────────────┘
                    │
                    ▼
          Attack Chain Discovery
          Next Target Suggestions
```

## Components

### MessageBus

Async message bus for inter-agent communication.

**Features:**
- Broadcast and direct messaging
- Message type filtering (FINDING, REQUEST, RESPONSE, STATUS, etc.)
- Priority-based delivery
- Request/response correlation
- Thread-safe async operations

**Usage:**

```python
from inferno.swarm import get_message_bus, MessageType

# Initialize bus
bus = get_message_bus()
await bus.start()

# Subscribe agent to receive messages
async def finding_handler(message):
    print(f"Received: {message.payload}")

await bus.subscribe("agent_001", finding_handler)

# Broadcast a finding
finding = {"type": "sqli", "severity": "high"}
await bus.broadcast_finding("scanner_001", finding, priority=75)

# Request context from another agent
context = await bus.request_context(
    requester="exploiter_001",
    target_agent="scanner_001",
    context_type="sql_injection_details",
    timeout_seconds=30.0,
)

# Cleanup
await bus.stop()
```

**Message Types:**
- `FINDING` - New vulnerability/finding discovered (priority: 75)
- `CONTEXT` - Contextual information sharing
- `REQUEST` - Request for information/action
- `RESPONSE` - Response to request
- `STATUS` - Agent status update (priority: 30)
- `COMPLETE` - Task completion notification
- `ERROR` - Error notification

### SynthesisEngine

Correlates findings from multiple agents into multi-step attack chains.

**Features:**
- Pattern-based chain detection (37 built-in patterns)
- Graph-based vulnerability correlation
- Attack chain scoring and prioritization
- Next target recommendations

**Usage:**

```python
from inferno.swarm import get_synthesis_engine

# Initialize engine
synthesis = get_synthesis_engine()

# Add findings from agents
finding1 = {
    "finding_id": "f001",
    "vuln_type": "file_upload",
    "severity": "high",
    "endpoint": "/upload.php",
    "method": "POST",
    "parameters": ["file"],
    "agent_id": "recon_001",
}
synthesis.add_finding(finding1)

finding2 = {
    "finding_id": "f002",
    "vuln_type": "lfi",
    "severity": "high",
    "endpoint": "/view.php",
    "method": "GET",
    "parameters": ["page"],
    "agent_id": "scanner_001",
}
synthesis.add_finding(finding2)

# Synthesize attack chains
chains = await synthesis.synthesize()

for chain in chains:
    print(f"Chain: {chain.name}")
    print(f"  Score: {chain.score:.2f}")
    print(f"  Difficulty: {chain.total_difficulty}")
    print(f"  Impact: {chain.total_impact}")
    print(f"  Probability: {chain.probability:.1%}")
    print(f"  Viable: {chain.is_viable}")

# Get recommendations for next targets
next_targets = synthesis.get_next_targets([finding1, finding2])
print(f"Suggested targets: {next_targets}")

# Generate report
print(synthesis.get_report())
```

**Attack Chain Patterns:**

The engine knows 37 attack chain patterns including:

**Upload Chains:**
- file_upload + lfi → Upload to LFI/RCE (difficulty multiplier: 3.0)
- file_upload + path_traversal → Upload to Path Traversal (2.5x)
- file_upload + xxe → Upload to XXE (2.8x)

**SSRF Chains:**
- ssrf + cloud_metadata → SSRF to Cloud Credentials (2.5x)
- ssrf + internal_service → SSRF to Internal Access (2.0x)
- ssrf + rce → SSRF to RCE (3.5x)

**SQLi Chains:**
- sqli + file_write → SQLi to File Write/RCE (3.0x)
- sqli + file_read → SQLi to File Disclosure (2.0x)
- sqli + auth_bypass → SQLi to Auth Bypass (1.5x)

**XSS Chains:**
- xss + csrf → XSS to CSRF (1.8x)
- xss + session_hijack → XSS to Session Hijacking (2.0x)
- stored_xss + admin_access → Stored XSS to Admin Compromise (2.5x)

See `synthesis.py` for the complete list of patterns.

**Chain Scoring:**

Chains are scored using:
```
score = (Impact × Probability) / Difficulty
```

Where:
- **Impact** (1-10): Based on highest severity in chain
  - critical: 10
  - high: 7
  - medium: 5
  - low: 3
  - info: 1
- **Difficulty** (1-10): Sum of step difficulties × pattern multiplier
- **Probability** (0.0-1.0): Success likelihood based on difficulty

**Viability Requirements:**
- Minimum impact: 5
- Minimum probability: 0.3 (30%)
- At least one step

### SwarmTool

Spawns specialized sub-agents for parallel execution (see `tool.py`).

**Sub-Agent Types:**
- `reconnaissance` - OSINT, subdomain enum, service discovery
- `scanner` - Vulnerability detection, CVE matching
- `exploiter` - SQLi, XSS, RCE exploitation
- `post_exploitation` - Privilege escalation, lateral movement
- `analyzer` - Response analysis, JS parsing
- `validator` - Independent finding verification

## Integration Example

Complete example integrating MessageBus and SynthesisEngine:

```python
from inferno.swarm import (
    get_message_bus,
    get_synthesis_engine,
    MessageType,
)

async def main():
    # Initialize components
    bus = get_message_bus()
    synthesis = get_synthesis_engine()
    await bus.start()

    # Handler for findings
    async def on_finding(message):
        if message.message_type == MessageType.FINDING:
            finding = message.payload["finding"]
            synthesis.add_finding(finding)
            print(f"Received finding: {finding['vuln_type']}")

    # Subscribe agents
    await bus.subscribe("recon", on_finding)
    await bus.subscribe("scanner", on_finding)

    # Agents broadcast findings
    await bus.broadcast_finding("recon", {
        "finding_id": "f001",
        "vuln_type": "ssrf",
        "severity": "critical",
        "endpoint": "/proxy",
        "method": "GET",
        "parameters": ["url"],
        "agent_id": "recon",
    })

    await bus.broadcast_finding("scanner", {
        "finding_id": "f002",
        "vuln_type": "cloud_metadata",
        "severity": "high",
        "endpoint": "/proxy",
        "method": "GET",
        "parameters": ["url"],
        "agent_id": "scanner",
    })

    # Wait for message processing
    await asyncio.sleep(0.5)

    # Synthesize chains
    chains = await synthesis.synthesize()
    print(f"\nDiscovered {len(chains)} attack chains:")
    for chain in chains:
        print(f"  - {chain.name} (score: {chain.score:.2f})")

    # Get next targets
    all_findings = [synthesis.get_finding(f"f{i:03d}") for i in range(1, 3)]
    targets = synthesis.get_next_targets([
        {
            "finding_id": f.finding_id,
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "method": f.method,
            "parameters": f.parameters,
            "agent_id": f.agent_id,
        }
        for f in all_findings if f
    ])
    print(f"\nRecommended next targets: {targets}")

    # Cleanup
    await bus.stop()
    synthesis.clear()
```

## Testing

Run the comprehensive test suite:

```bash
# MessageBus tests
pytest tests/unit/test_message_bus.py -v

# SynthesisEngine tests
pytest tests/unit/test_synthesis.py -v

# Run demo
python examples/swarm_coordination_demo.py
```

## Performance Characteristics

**MessageBus:**
- Max queue size per agent: 1000 messages
- Message TTL: 3600 seconds (1 hour)
- Async non-blocking delivery
- Automatic cleanup of old messages

**SynthesisEngine:**
- Default min chain length: 2 steps
- Default max chain length: 5 steps
- Pattern matching: O(n²) where n = number of findings
- Graph-based discovery: O(n²) grouped by endpoint

## Global Singletons

Both components provide global singleton access:

```python
from inferno.swarm import (
    get_message_bus,
    get_synthesis_engine,
    reset_message_bus,
    reset_synthesis_engine,
)

# Get singleton instances
bus = get_message_bus()
synthesis = get_synthesis_engine()

# Reset for testing
await reset_message_bus()
reset_synthesis_engine()
```

## Configuration

**MessageBus:**
```python
bus = MessageBus(
    max_queue_size=1000,        # Max messages per agent queue
    message_ttl_seconds=3600,   # Message history retention
)
```

**SynthesisEngine:**
```python
synthesis = SynthesisEngine(
    min_chain_length=2,    # Minimum steps for valid chain
    max_chain_length=5,    # Maximum steps to explore
    min_chain_score=1.0,   # Minimum score for viable chain
)
```

## Advanced Features

### Request/Response Pattern

```python
# Agent A requests data from Agent B
async def request_handler(message):
    if message.message_type == MessageType.REQUEST:
        # Prepare response
        response = AgentMessage(
            message_id=str(uuid.uuid4()),
            sender_agent="agent_b",
            recipient_agent=message.sender_agent,
            message_type=MessageType.RESPONSE,
            payload={"data": "requested_data"},
            timestamp=datetime.utcnow(),
            correlation_id=message.message_id,  # Link to request
        )
        await bus.publish(response)

await bus.subscribe("agent_b", request_handler)

# Make request with automatic response correlation
result = await bus.request_context(
    requester="agent_a",
    target_agent="agent_b",
    context_type="vulnerability_details",
)
```

### Custom Chain Patterns

Add custom patterns to `CHAIN_PATTERNS` in `synthesis.py`:

```python
CHAIN_PATTERNS = [
    # ... existing patterns ...

    # Custom pattern
    ("my_vuln_type", "another_vuln", "Custom Attack Chain", 2.5),
]
```

### Message Filtering

```python
# Subscribe with type filter
await bus.subscribe(
    "agent_a",
    handler,
    message_types={MessageType.FINDING, MessageType.ERROR},
)

# Subscribe with priority threshold
await bus.subscribe(
    "agent_b",
    handler,
    priority_threshold=70,  # Only receive priority >= 70
)
```

## Thread Safety

Both MessageBus and SynthesisEngine are designed for async/await usage:

- MessageBus uses `asyncio.Lock` for thread-safe operations
- Message queues use `asyncio.Queue` for non-blocking I/O
- All public methods are `async` and should be awaited

## Error Handling

```python
# MessageBus
try:
    await bus.publish(message)
except RuntimeError as e:
    # Bus not running
    print(f"Error: {e}")

try:
    result = await bus.request_context(
        requester="a",
        target_agent="b",
        context_type="test",
        timeout_seconds=5.0,
    )
except asyncio.TimeoutError:
    # No response within timeout
    print("Request timed out")

# SynthesisEngine
try:
    node = synthesis.add_finding(finding_data)
except Exception as e:
    # Invalid finding data
    print(f"Error adding finding: {e}")
```

## Logging

Both components use `structlog` for structured logging:

```python
# MessageBus logs
message_bus.initialized
message_bus.started
message_bus.subscribed
message_bus.published
message_bus.finding_broadcast
message_bus.context_received
message_bus.stopped

# SynthesisEngine logs
synthesis_engine.initialized
synthesis_engine.finding_added
synthesis_engine.pattern_matched
synthesis_engine.graph_chain
synthesis_engine.synthesis_complete
synthesis_engine.targets_suggested
synthesis_engine.cleared
```

Set log level to DEBUG to see detailed operation logs.
