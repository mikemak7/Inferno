# Comprehensive Testing Guide for Inferno-AI

This guide provides detailed instructions for running the new comprehensive test suite that validates vulnerability detection accuracy.

## New Test Files Created

```
tests/
├── unit/
│   ├── test_ssrf_detector.py          # SSRF detection unit tests
│   ├── test_idor_scanner.py           # IDOR detection unit tests
│   └── test_scope.py                  # Existing scope tests
├── integration/
│   └── test_vulnerability_validation_flow.py  # Complete detection workflows
├── accuracy/
│   └── test_owasp_benchmark.py        # Accuracy benchmarks
└── docs/
    └── TESTING_STRATEGY.md            # Comprehensive testing strategy
```

## Quick Start

### Install Test Dependencies
```bash
pip install -e ".[dev]"
```

### Run All New Tests
```bash
# Unit tests for vulnerability detectors
pytest tests/unit/test_ssrf_detector.py -v
pytest tests/unit/test_idor_scanner.py -v

# Integration tests for complete workflows
pytest tests/integration/test_vulnerability_validation_flow.py -v -m integration

# Accuracy benchmarks
pytest tests/accuracy/test_owasp_benchmark.py -v -m accuracy
```

## Test Coverage Overview

### Unit Tests (70% of test suite)

#### SSRF Detector Tests (`test_ssrf_detector.py`)

**Coverage Areas:**
- Payload generation (localhost, cloud metadata, protocol smuggling)
- Response analysis (detecting localhost access, cloud metadata, file access)
- SSRF type determination (basic, blind, protocol-based)
- Payload injection in URLs
- Callback ID generation for blind SSRF
- Edge case handling (timeouts, network errors)

**Run SSRF Tests:**
```bash
pytest tests/unit/test_ssrf_detector.py -v
```

**Key Test Classes:**
- `TestSSRFPayloadGeneration` - Payload creation logic
- `TestSSRFDetection` - Detection algorithm validation
- `TestSSRFValidation` - Real scenario validation
- `TestSSRFEdgeCases` - Boundary conditions

#### IDOR Scanner Tests (`test_idor_scanner.py`)

**Coverage Areas:**
- ID parameter detection (numeric, UUID, in paths and responses)
- Access control validation
- Sensitive data extraction
- Horizontal privilege escalation detection
- Multi-user access comparison
- Sequential ID enumeration

**Run IDOR Tests:**
```bash
pytest tests/unit/test_idor_scanner.py -v
```

**Key Test Classes:**
- `TestIDORParameterDetection` - ID finding logic
- `TestIDORAccessControl` - Authorization checking
- `TestIDORHorizontalPrivilegeEscalation` - User-to-user attacks
- `TestIDORUnauthenticatedAccess` - Critical unauthenticated access

### Integration Tests (20% of test suite)

#### Vulnerability Validation Flow (`test_vulnerability_validation_flow.py`)

**Coverage Areas:**
- SQL injection detection → validation → filtering
- SSRF detection with localhost and cloud metadata access
- IDOR horizontal privilege escalation workflows
- Exploit chain validation (SQLi → Creds → Admin → RCE)
- Multi-tool coordination
- Rate limiting and network coordination
- Error recovery and retry logic

**Run Integration Tests:**
```bash
pytest tests/integration/ -v -m integration
```

**Key Test Classes:**
- `TestSQLInjectionDetectionFlow` - Complete SQLi workflow
- `TestSSRFDetectionFlow` - SSRF detection and validation
- `TestIDORDetectionFlow` - IDOR detection with FP filtering
- `TestExploitChainValidation` - Multi-step attack chains
- `TestMultiToolCoordination` - Tool integration

### Accuracy Benchmarks (Validation Layer)

#### OWASP Benchmark Tests (`test_owasp_benchmark.py`)

**Coverage Areas:**
- A03:2021 - SQL Injection accuracy metrics
- A01:2021 - IDOR/Access Control accuracy
- A10:2021 - SSRF accuracy
- False positive rate measurement
- Comprehensive accuracy reporting

**Run Accuracy Benchmarks:**
```bash
pytest tests/accuracy/test_owasp_benchmark.py -v -m accuracy
```

**Generate Comprehensive Report:**
```bash
pytest tests/accuracy/test_owasp_benchmark.py::TestComprehensiveAccuracyReport::test_generate_accuracy_report -v -s
```

**Expected Output:**
```
==============================================================
INFERNO-AI ACCURACY BENCHMARK REPORT
==============================================================
Test Date: 2024-12-05
Version: 1.0.0

Vulnerability Type    Precision    Recall       F1 Score     Accuracy
------------------------------------------------------------
SQL Injection             92.59%      89.29%      90.91%      89.58%
IDOR                      84.62%      91.67%      88.00%      87.50%
SSRF                      94.74%      90.00%      92.31%      91.67%
------------------------------------------------------------
OVERALL                   90.48%      90.28%      90.38%      89.58%
==============================================================
```

## Understanding Test Results

### Accuracy Metrics Explained

**Precision** = TP / (TP + FP)
- How many detected vulnerabilities are actually real
- High precision = few false positives

**Recall** = TP / (TP + FN)
- How many real vulnerabilities are detected
- High recall = few missed vulnerabilities

**F1 Score** = 2 × (Precision × Recall) / (Precision + Recall)
- Harmonic mean of precision and recall
- Balanced measure of accuracy

**Example:**
```
True Positives (TP): 25    # Correctly identified vulnerabilities
False Positives (FP): 2    # Safe endpoints flagged as vulnerable
True Negatives (TN): 18    # Safe endpoints correctly identified
False Negatives (FN): 3    # Missed vulnerabilities

Precision = 25 / (25 + 2) = 92.59%
Recall = 25 / (25 + 3) = 89.29%
F1 Score = 2 × (0.9259 × 0.8929) / (0.9259 + 0.8929) = 90.91%
```

### Minimum Thresholds

Tests will fail if accuracy falls below these thresholds:

| Metric | SQL Injection | IDOR | SSRF | Overall |
|--------|--------------|------|------|---------|
| Precision | ≥80% | ≥75% | ≥85% | ≥80% |
| Recall | ≥85% | ≥80% | ≥90% | ≥85% |
| F1 Score | ≥82% | ≥77% | ≥87% | ≥82% |
| False Positive Rate | <5% | <8% | <3% | <5% |

## Running Specific Test Scenarios

### Test SSRF Detection Accuracy
```bash
# Test localhost access detection
pytest tests/unit/test_ssrf_detector.py::TestSSRFValidation::test_detect_localhost_ssrf -v

# Test cloud metadata detection
pytest tests/unit/test_ssrf_detector.py::TestSSRFValidation::test_detect_cloud_metadata_access -v

# Test no false positives on blocked requests
pytest tests/unit/test_ssrf_detector.py::TestSSRFValidation::test_no_false_positive_on_blocked_request -v
```

### Test IDOR Detection Accuracy
```bash
# Test horizontal privilege escalation
pytest tests/unit/test_idor_scanner.py::TestIDORHorizontalPrivilegeEscalation::test_detect_horizontal_idor -v

# Test unauthenticated access detection
pytest tests/unit/test_idor_scanner.py::TestIDORUnauthenticatedAccess::test_detect_unauthenticated_idor -v

# Test no false positives when properly blocked
pytest tests/unit/test_idor_scanner.py::TestIDORHorizontalPrivilegeEscalation::test_no_false_positive_when_blocked -v
```

### Test Complete Workflows
```bash
# SQLi detection to validation flow
pytest tests/integration/test_vulnerability_validation_flow.py::TestSQLInjectionDetectionFlow -v

# SSRF to cloud compromise chain
pytest tests/integration/test_vulnerability_validation_flow.py::TestExploitChainValidation::test_ssrf_to_cloud_compromise_chain -v
```

## Test Validation Examples

### Example 1: Validating SSRF Detection

The tests validate that the SSRF detector:
1. **Generates correct payloads** for different attack vectors
2. **Detects localhost access** from response indicators
3. **Identifies cloud metadata** exposure
4. **Avoids false positives** on WAF blocks
5. **Handles errors gracefully** without crashing

```python
# Real test from test_ssrf_detector.py
def test_analyze_cloud_metadata_response(self, detector):
    """Test detection of cloud metadata access."""
    response_text = '''
    {
        "ami-id": "ami-0123456789",
        "security-credentials": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
    }
    '''
    indicators = detector._analyze_response(response_text)
    assert indicators["cloud_metadata"]  # Should detect metadata
    assert indicators["accessible"]      # Should be accessible
```

### Example 2: Validating IDOR Detection

The tests validate that the IDOR scanner:
1. **Finds ID parameters** in URLs and responses
2. **Detects horizontal privilege escalation** (user accessing other user's data)
3. **Identifies unauthenticated access** (critical severity)
4. **Filters public data** to avoid false positives
5. **Handles authorization errors** correctly

```python
# Real test from test_idor_scanner.py
@pytest.mark.asyncio
async def test_detect_horizontal_idor(self, scanner):
    """Test detection of horizontal IDOR vulnerability."""
    # User1 (ID 100) trying to access User2's data (ID 200)
    result = await scanner.execute(
        operation="scan",
        url="http://api.example.com/users/100/profile",
        user1_auth={"user_id": "100"},
        target_ids=["200"]
    )

    findings = result.metadata["findings"]
    horizontal_findings = [f for f in findings if f["type"] == "horizontal"]
    assert len(horizontal_findings) > 0  # Should detect IDOR
```

## Continuous Integration

### Run in CI/CD Pipeline

```yaml
# .github/workflows/test-security.yml
name: Security Testing

on: [push, pull_request]

jobs:
  vulnerability-detection-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Run vulnerability detector tests
        run: |
          pytest tests/unit/test_ssrf_detector.py -v --cov
          pytest tests/unit/test_idor_scanner.py -v --cov

      - name: Run integration tests
        run: pytest tests/integration/ -v -m integration

      - name: Run accuracy benchmarks
        run: pytest tests/accuracy/ -v -m accuracy

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Debugging Failed Tests

### View Detailed Output
```bash
pytest tests/unit/test_ssrf_detector.py -vv -s
```

### Run with PDB Debugger
```bash
pytest tests/unit/test_ssrf_detector.py --pdb
```

### Run Only Failed Tests
```bash
pytest --lf  # Last failed
pytest --ff  # Failed first
```

### Check Coverage
```bash
pytest tests/unit/test_ssrf_detector.py --cov=src/inferno/tools/advanced --cov-report=term-missing
```

## Extending Tests

### Adding New Vulnerability Type Tests

1. **Create test file**: `tests/unit/test_<vuln_type>_detector.py`

2. **Follow structure**:
```python
class TestPayloadGeneration:
    """Test payload generation logic."""
    pass

class TestDetection:
    """Test detection algorithm."""
    pass

class TestValidation:
    """Test with real scenarios."""
    pass

class TestEdgeCases:
    """Test boundary conditions."""
    pass
```

3. **Add accuracy benchmark** in `tests/accuracy/test_owasp_benchmark.py`

4. **Update documentation** in this guide

### Adding Integration Test Scenarios

1. **Identify workflow**: Detection → Validation → Exploitation
2. **Create test class** in `test_vulnerability_validation_flow.py`
3. **Mock responses** for each step
4. **Verify chain completeness**

## Performance Expectations

### Test Execution Times

| Test Suite | Expected Time |
|-----------|---------------|
| Unit tests (all) | < 10 seconds |
| Integration tests (all) | < 30 seconds |
| Accuracy benchmarks | < 20 seconds |
| Complete suite | < 60 seconds |

### Run Performance Analysis
```bash
pytest tests/ --durations=10
```

Shows the 10 slowest tests.

## Best Practices for Test Maintenance

1. **Keep tests fast** - Mock expensive operations
2. **Keep tests isolated** - No shared state
3. **Keep tests deterministic** - No randomness
4. **Update tests with code changes** - Don't let tests rot
5. **Add tests for bugs** - Prevent regressions
6. **Review test coverage** - Aim for 80%+ critical code

## Troubleshooting

### "Module not found" errors
```bash
# Ensure package is installed
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:/Users/ademkok/Inferno-AI/src"
```

### Async test errors
```bash
# Ensure pytest-asyncio is installed
pip install pytest-asyncio

# Check pytest.ini has asyncio_mode = auto
```

### Mock import errors
```bash
# Ensure mocking is correct
from unittest.mock import Mock, AsyncMock, patch
```

## Next Steps

1. **Run existing tests** to establish baseline
2. **Add tests for remaining tools** (SQLmap integration, XSS detection, etc.)
3. **Create E2E tests** against DVWA, Juice Shop
4. **Set up CI/CD** with accuracy tracking
5. **Monitor metrics** over time

## Questions?

- See `/docs/TESTING_STRATEGY.md` for comprehensive strategy
- See `/tests/README.md` for test suite overview
- Check existing test files for examples
- Review conftest.py for available fixtures
