# Secrets Sentry Test Suite

Comprehensive test suite for the Secrets Sentry secret detection tool.

## Overview

This test suite provides extensive coverage for all components:

- **Unit Tests** (`tests/unit/`): Test individual components in isolation
- **Integration Tests** (`tests/integration/`): Test component interactions and workflows
- **Fixtures** (`fixtures/`): Realistic fake secrets and test data

## Test Structure

```
tests/
├── unit/
│   ├── test_entropy.py      # Entropy detection tests
│   ├── test_patterns.py     # Pattern matching tests
│   ├── test_heuristics.py   # Heuristic detection tests
│   └── test_scanner.py      # Main scanner tests
├── integration/
│   └── test_full_scan.py    # End-to-end integration tests
├── conftest.py              # Shared pytest fixtures
└── README.md                # This file

fixtures/
└── test_secrets.py          # Test data (FAKE secrets only!)
```

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/unit/test_entropy.py

# Run specific test
pytest tests/unit/test_entropy.py::TestCalculateEntropy::test_empty_string
```

### Using the Test Runner Script

```bash
# Run all tests with coverage
./run_tests.sh

# Fast mode (skip slow tests)
./run_tests.sh --fast

# No coverage report
./run_tests.sh --no-coverage

# Parallel execution (requires pytest-xdist)
./run_tests.sh --parallel

# Run only unit tests
./run_tests.sh --unit

# Run only integration tests
./run_tests.sh --integration
```

### Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests only
pytest -m integration

# Skip slow tests
pytest -m "not slow"

# Git-related tests only
pytest -m git
```

## Test Coverage

The test suite aims for 90%+ code coverage and includes:

### Entropy Detection (`test_entropy.py`)
- ✓ Shannon entropy calculation with known values
- ✓ High entropy string detection
- ✓ Minimum length filtering
- ✓ Allowlist functionality
- ✓ Unicode and special character handling
- ✓ Edge cases (empty strings, very long strings)

### Pattern Detection (`test_patterns.py`)
- ✓ All 20+ secret patterns individually tested
- ✓ AWS keys (access key, secret key)
- ✓ OpenAI API keys
- ✓ Slack tokens and webhooks
- ✓ Discord tokens and webhooks
- ✓ GitHub tokens (PAT, OAuth)
- ✓ JWT tokens
- ✓ Private keys (RSA, EC, OpenSSH, DSA)
- ✓ Firebase/Google API keys
- ✓ Stripe keys (live, restricted)
- ✓ Twilio keys and SIDs
- ✓ Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- ✓ Generic patterns (API keys, secrets, base64)
- ✓ False positive prevention (UUIDs, hashes)
- ✓ Capture group extraction
- ✓ Confidence levels

### Heuristic Detection (`test_heuristics.py`)
- ✓ Suspicious filename detection (.env, credentials.json, etc.)
- ✓ Suspicious file extensions (.pem, .key, .p12, etc.)
- ✓ Suspicious filename patterns (secret, password, token, etc.)
- ✓ File exclusion patterns (node_modules, .venv, etc.)
- ✓ Binary file detection
- ✓ Warning message generation
- ✓ Case-insensitive matching
- ✓ Priority handling (exact match vs pattern)

### Main Scanner (`test_scanner.py`)
- ✓ Finding class structure and serialization
- ✓ Scanner initialization (default and custom params)
- ✓ File scanning with various content types
- ✓ Directory scanning (recursive, nested)
- ✓ Exclusion pattern handling
- ✓ Binary file skipping
- ✓ Duplicate detection (pattern + entropy)
- ✓ Multi-line secret detection
- ✓ Unicode content handling
- ✓ Summary generation
- ✓ Various file format support (Python, JS, JSON, YAML, .env)

### Integration Tests (`test_full_scan.py`)
- ✓ Complete scan workflow
- ✓ Custom exclusion patterns
- ✓ Multiple file type scanning
- ✓ Findings persistence (save/load)
- ✓ High confidence filtering
- ✓ Git history scanning (if GitPython available)
- ✓ Config and storage integration
- ✓ End-to-end scenarios
- ✓ Multi-detector coordination
- ✓ Performance testing

## Test Fixtures

The `fixtures/test_secrets.py` file contains:

- **FAKE_SECRETS**: Valid format examples for all 20+ patterns
- **FALSE_POSITIVES**: UUIDs, hashes, and other non-secrets
- **EDGE_CASES**: Unicode, very long strings, special characters
- **TEST_FILES**: Complete file contents for various formats
- **SUSPICIOUS_FILENAMES**: Files that should trigger heuristics
- **CLEAN_FILENAMES**: Files that should not trigger warnings

**IMPORTANT**: All secrets in the fixtures are FAKE and meant only for testing!

## Writing New Tests

### Test Naming Convention

```python
class TestFeatureName:
    """Tests for FeatureName."""

    def test_specific_behavior(self):
        """Test that specific behavior works correctly."""
        # Arrange
        detector = Detector()

        # Act
        result = detector.method()

        # Assert
        assert result == expected
```

### Using Fixtures

```python
def test_with_temp_file(temp_file):
    """Test using temporary file fixture."""
    with open(temp_file, 'w') as f:
        f.write("content")
    # File will be cleaned up automatically

def test_with_project_structure(project_structure):
    """Test using realistic project structure."""
    # project_structure is a Path object to temp directory
    # with realistic file structure already created
```

### Parametrized Tests

```python
@pytest.mark.parametrize("secret_key,expected_rule", [
    ("aws_access_key", "AWS_ACCESS_KEY"),
    ("github_pat", "GITHUB_PAT"),
    ("openai_key", "OPENAI_API_KEY"),
])
def test_various_secrets(secret_key, expected_rule):
    """Test detection of various secret types."""
    detector = PatternDetector()
    secret = FAKE_SECRETS[secret_key]
    findings = detector.scan_line(secret, 1)
    assert any(f["rule"] == expected_rule for f in findings)
```

## Continuous Integration

The test suite is designed to work with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements-test.txt
    pytest --cov=src --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Test Performance

Expected test execution times (on modern hardware):

- Unit tests: ~2-5 seconds
- Integration tests: ~3-8 seconds
- Full suite with coverage: ~5-15 seconds
- Parallel execution (with -n auto): ~3-8 seconds

## Debugging Failed Tests

```bash
# Verbose output
pytest -vv

# Show local variables on failure
pytest --showlocals

# Drop into debugger on failure
pytest --pdb

# Run specific failed test
pytest tests/unit/test_patterns.py::TestAWSPatterns::test_aws_access_key_valid -vv

# Show print statements
pytest -s
```

## Coverage Reports

After running tests with coverage:

```bash
# View HTML report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux

# View terminal summary
pytest --cov=src --cov-report=term-missing

# Generate XML for CI
pytest --cov=src --cov-report=xml
```

## Best Practices

1. **Keep tests fast**: Unit tests should run in milliseconds
2. **Use fixtures**: Share common setup via pytest fixtures
3. **Test edge cases**: Empty strings, unicode, very long inputs
4. **Mock external dependencies**: File I/O, git operations
5. **Clear docstrings**: Every test should explain what it tests
6. **Parametrize similar tests**: Use `@pytest.mark.parametrize`
7. **Organize by feature**: Group related tests in classes
8. **Test error conditions**: Don't just test happy paths

## Contributing

When adding new features:

1. Write tests first (TDD)
2. Ensure tests pass: `pytest`
3. Check coverage: `pytest --cov=src`
4. Aim for 90%+ coverage on new code
5. Add fixtures for reusable test data
6. Document complex test scenarios

## Troubleshooting

### Import Errors

```bash
# Ensure src is in PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:${PWD}"
pytest
```

### Git Tests Failing

Git-related tests require GitPython:
```bash
pip install GitPython
pytest -m git
```

### Slow Tests

Skip slow tests during development:
```bash
pytest -m "not slow"
```

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Documentation](https://coverage.readthedocs.io/)
- [Pytest Best Practices](https://docs.pytest.org/en/stable/goodpractices.html)
