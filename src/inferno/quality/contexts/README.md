# Technology Context Modules

Technology-specific context modules for Inferno-AI's quality gate system. These modules help filter false positives and adjust severity ratings based on technology-specific patterns commonly found in bug bounty programs.

## Overview

The technology context system addresses a critical problem in automated security testing: **different technologies have different expectations about what constitutes a vulnerability**. For example:

- **Blockchain**: Wallet addresses and transaction hashes are public by design
- **APIs**: Documentation endpoints (Swagger, OpenAPI) are often intentionally public
- **Web Apps**: Version disclosure and debug headers are low-impact

## Available Contexts

### BlockchainContext

Filters public-by-design blockchain features that are often incorrectly reported as information disclosure:

**Public by Design** (filtered):
- Wallet addresses (0x prefixed 40 hex characters)
- Balance information
- Transaction hashes
- Public RPC methods (eth_blockNumber, eth_getBalance, etc.)
- Gas prices and block numbers
- On-chain data enumeration

**Severity Adjustments**:
- Admin RPC methods (admin_*, debug_*, miner_*) → HIGH
- Public RPC exposure → INFO

**Example**:
```python
from inferno.quality.contexts import BlockchainContext
from inferno.quality.candidate import FindingCandidate
from inferno.reporting.models import Severity

context = BlockchainContext()
candidate = FindingCandidate(
    title="Wallet Address Disclosure",
    description="Found exposed wallet addresses",
    initial_severity=Severity.MEDIUM,
    evidence="Address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    affected_asset="https://example.com/api/wallet",
    vuln_type="information_disclosure",
)

adjustment = context.evaluate(candidate)
# Result: Filtered as public-by-design, adjusted to INFO
```

### APIContext

Filters intentionally exposed API documentation while flagging internal endpoint exposure:

**Public by Design** (filtered when no internal endpoints):
- swagger.json, swagger.yaml
- openapi.json, openapi.yaml
- /api-docs, /swagger-ui, /redoc endpoints
- GraphQL introspection (if explicitly enabled)

**Severity Adjustments**:
- API docs with internal/admin endpoints → HIGH
- Public API docs only → INFO
- GraphQL introspection with internal queries → HIGH
- GraphQL introspection (public only) → LOW

**Internal Endpoint Indicators**:
- `/admin`, `/internal`, `/debug`, `/private`, `/test`, `/dev`
- `/management`, `/actuator`, `/metrics`

**Example**:
```python
from inferno.quality.contexts import APIContext

context = APIContext()
candidate = FindingCandidate(
    title="Swagger Documentation Exposed",
    description="Swagger UI publicly accessible",
    initial_severity=Severity.MEDIUM,
    evidence="swagger.json found at /api-docs with endpoints: /api/users, /api/products",
    affected_asset="https://example.com/api-docs",
    vuln_type="information_disclosure",
)

adjustment = context.evaluate(candidate)
# Result: Public by design, adjusted to INFO (no internal endpoints)
```

### GenericWebContext

Adjusts severity for common web findings based on actual risk:

**Severity Overrides**:

| Finding Type | Default → Adjusted | Condition |
|-------------|-------------------|-----------|
| Stack traces | MEDIUM → LOW | No credentials |
| Stack traces | LOW → HIGH | Credentials exposed |
| Version disclosure | MEDIUM → INFO | Always |
| X-Powered-By header | MEDIUM → INFO | Always |
| Debug mode | MEDIUM → LOW | No credentials |
| Debug mode | LOW → HIGH | Credentials exposed |
| Error messages | MEDIUM → INFO | No credentials |
| Technology disclosure | MEDIUM → INFO | Always |

**Credential Detection**:
- Password patterns
- API keys
- Secrets and tokens
- Database connection strings
- AWS access keys
- Private keys

**Example**:
```python
from inferno.quality.contexts import GenericWebContext

context = GenericWebContext()

# Example 1: Version disclosure
candidate1 = FindingCandidate(
    title="Version Disclosure",
    initial_severity=Severity.MEDIUM,
    evidence="Server: Apache/2.4.41",
    # ...
)
adjustment1 = context.evaluate(candidate1)
# Result: Adjusted to INFO

# Example 2: Stack trace with credentials
candidate2 = FindingCandidate(
    title="Stack Trace",
    initial_severity=Severity.LOW,
    evidence="Database: mysql://admin:P@ssw0rd@localhost",
    # ...
)
adjustment2 = context.evaluate(candidate2)
# Result: Upgraded to HIGH
```

## Architecture

### BaseTechnologyContext

Abstract base class that all technology contexts inherit from:

```python
from inferno.quality.contexts.base import BaseTechnologyContext

class CustomContext(BaseTechnologyContext):
    def is_public_by_design(self, candidate) -> tuple[bool, str]:
        """Check if finding is public by design."""
        pass

    def suggest_severity(self, candidate) -> Severity | None:
        """Suggest severity adjustment."""
        pass

    def get_context_adjustments(self, candidate) -> list[ContextAdjustment]:
        """Get all adjustments for this finding."""
        pass

    def applies_to(self, candidate) -> bool:
        """Check if this context should be applied."""
        pass
```

### Integration with Quality Gate System

The contexts integrate seamlessly with the existing quality gate system:

```python
from inferno.quality.candidate import FindingCandidate, ContextAdjustment
from inferno.quality.contexts import BlockchainContext, APIContext, GenericWebContext

# Initialize contexts
contexts = [
    BlockchainContext(),
    APIContext(),
    GenericWebContext(),  # Fallback for all findings
]

# Evaluate a finding
candidate = FindingCandidate(...)

for context in contexts:
    if context.applies_to(candidate):
        adjustment = context.evaluate(candidate)
        if adjustment:
            # Apply the adjustment
            candidate.add_context_adjustment(adjustment)
            if adjustment.is_by_design:
                candidate.is_public_by_design = True
                candidate.data_intentionally_public = True
            if adjustment.adjusted_severity != candidate.initial_severity:
                candidate.adjusted_severity = adjustment.adjusted_severity
                candidate.severity_rationale = adjustment.rationale
```

## Files

- **base.py**: Abstract base class and core interfaces
- **blockchain.py**: Blockchain-specific context (Ethereum, Web3, etc.)
- **api.py**: API documentation context (Swagger, OpenAPI, GraphQL)
- **generic.py**: Generic web application context (fallback)
- **__init__.py**: Package exports

## Usage in Bug Bounty Mode

When Inferno-AI runs in bug bounty mode, these contexts automatically:

1. **Filter false positives** - Public-by-design features are marked and filtered
2. **Adjust severity** - Ratings are adjusted based on actual risk
3. **Reduce noise** - Only actionable findings are reported
4. **Improve accuracy** - Technology-specific knowledge prevents misclassification

This results in higher-quality submissions that match bug bounty program expectations.

## Testing

See `examples/quality_contexts_demo.py` for a comprehensive demonstration of all contexts in action.

Run the demo:
```bash
python examples/quality_contexts_demo.py
```

## Future Contexts

Potential future context modules:

- **CloudContext**: AWS/Azure/GCP-specific patterns
- **MobileContext**: iOS/Android app-specific patterns
- **IoTContext**: IoT device-specific patterns
- **DatabaseContext**: Database-specific patterns
- **AuthContext**: Authentication/authorization-specific patterns

## Contributing

When adding new technology contexts:

1. Inherit from `BaseTechnologyContext`
2. Implement all abstract methods
3. Use regex patterns for matching
4. Document public-by-design patterns clearly
5. Provide severity adjustment rationale
6. Add examples to demo script
7. Update this README

## References

- OWASP Top 10
- Bug Bounty Program Guidelines
- Common Vulnerability Scoring System (CVSS)
- Blockchain Security Best Practices
- API Security Best Practices
