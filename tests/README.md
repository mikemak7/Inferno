# Inferno-AI Test Suite

This directory contains the comprehensive test suite for Inferno-AI, following the testing pyramid approach.

## Directory Structure

```
tests/
├── conftest.py           # Shared fixtures and pytest configuration
├── unit/                 # Unit tests (70% of tests)
│   └── test_scope.py    # Scope management tests
├── integration/          # Integration tests (20% of tests)
└── e2e/                  # End-to-end tests (10% of tests)
```

## Test Categories

### Unit Tests (`tests/unit/`)
Fast, isolated tests for individual functions and classes.
- Test single components in isolation
- Mock external dependencies
- Execution time: milliseconds
- Coverage target: 80%+ for critical code

**Current tests:**
- `test_scope.py` - Security-critical scope validation tests

### Integration Tests (`tests/integration/`)
Tests for component interactions and external services.
- Database operations (Qdrant)
- API endpoint testing
- Service integrations
- Execution time: seconds

### End-to-End Tests (`tests/e2e/`)
Complete user workflow tests.
- Full assessment runs
- Real environment testing
- Critical user paths
- Execution time: minutes

## Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run Unit Tests Only
```bash
pytest tests/unit -v
```

### Run with Coverage
```bash
pytest tests/unit --cov=src/inferno --cov-report=html
```

### Run Integration Tests (requires Qdrant)
```bash
pytest tests/integration -v -m integration --qdrant
```

### Run Specific Test File
```bash
pytest tests/unit/test_scope.py -v
```

### Run Tests in Parallel
```bash
pytest tests/unit -n auto
```

## Fixtures (conftest.py)

### Core Fixtures
- `event_loop` - Async event loop for testing
- `temp_dir` - Temporary directory for test artifacts
- `operation_dir` - Full operation directory structure

### Mock API Clients
- `mock_anthropic_client` - Mocked Anthropic API client
- `mock_anthropic_tool_response` - Mock tool use response

### Configuration Fixtures
- `sample_scope_config` - Standard scope configuration
- `ctf_scope_config` - CTF mode scope configuration
- `sample_settings` - Test InfernoSettings instance

### Memory/Storage Fixtures
- `mock_qdrant_client` - Mocked Qdrant client
- `mock_embedder` - Mocked sentence transformer
- `sample_memory_entries` - Sample memory data

### Tool Fixtures
- `mock_tool_registry` - Mocked tool registry
- `sample_http_response` - Sample HTTP response data

### Credential Fixtures
- `mock_credential` - Valid test credential
- `expired_credential` - Expired credential for testing

### Agent/Loop Fixtures
- `sample_loop_config` - LoopConfig for agent testing
- `sample_assessment_config` - Assessment configuration

## Test Markers

Tests can be marked with custom markers:

```python
@pytest.mark.slow
def test_expensive_operation():
    """This test takes a while."""
    pass

@pytest.mark.integration
def test_database_integration():
    """Requires external services."""
    pass

@pytest.mark.security
def test_scope_bypass_prevention():
    """Security-critical test."""
    pass
```

Run tests by marker:
```bash
pytest -v -m "not slow"  # Skip slow tests
pytest -v -m security    # Run only security tests
```

## CI/CD Integration

Tests run automatically on GitHub Actions:

- **Lint Job**: Ruff linter + mypy type checking
- **Unit Tests**: Python 3.11 & 3.12, with coverage
- **Integration Tests**: With Qdrant service container
- **Security Scan**: Bandit security analysis

See `.github/workflows/test.yml` for details.

## Writing New Tests

### Test Naming Convention
```python
def test_should_[expected_behavior]_when_[condition]():
    """Clear description of what is tested."""
    # Arrange
    setup_data = create_test_data()

    # Act
    result = function_under_test(setup_data)

    # Assert
    assert result.expected_field == expected_value
```

### Best Practices

1. **Use AAA Pattern**: Arrange, Act, Assert
2. **One assertion per test** (when possible)
3. **Use descriptive test names**
4. **Mock external dependencies**
5. **Keep tests independent**
6. **Use fixtures for common setup**
7. **Test edge cases and error paths**
8. **Add docstrings to complex tests**

### Example Test
```python
def test_scope_blocks_out_of_scope_domain(sample_scope_config):
    """Test that out-of-scope domains are blocked."""
    from inferno.core.scope import ScopeManager

    # Arrange
    scope = ScopeManager(sample_scope_config)
    url = "https://attacker.com/malicious"

    # Act
    in_scope, reason = scope.is_in_scope(url)

    # Assert
    assert not in_scope
    assert "out of scope" in reason.lower()
```

## Coverage Goals

- **Critical Security Code**: 100% (scope, auth, commands)
- **Core Agent Logic**: 90%+
- **Tool Implementation**: 80%+
- **Overall Project**: 80%+

View coverage report:
```bash
pytest tests/unit --cov=src/inferno --cov-report=html
open htmlcov/index.html
```

## Debugging Tests

### Run with detailed output
```bash
pytest tests/unit/test_scope.py -vv
```

### Stop on first failure
```bash
pytest tests/unit -x
```

### Run last failed tests
```bash
pytest tests/unit --lf
```

### Interactive debugging
```bash
pytest tests/unit --pdb
```

## Adding New Test Files

When adding new test files:

1. Place in appropriate directory (`unit/`, `integration/`, `e2e/`)
2. Name file `test_*.py`
3. Use existing fixtures from `conftest.py`
4. Add new fixtures to `conftest.py` if reusable
5. Update this README with new test coverage

## Dependencies

Test dependencies are specified in `pyproject.toml` under `[project.optional-dependencies]`:

```toml
[project.optional-dependencies]
dev = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.1.0",
    "pytest-xdist>=3.3.0",
    # ... other test dependencies
]
```

Install with:
```bash
pip install -e ".[dev]"
```

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- [Test-Driven Development](https://testdriven.io/)
