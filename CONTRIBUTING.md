# Contributing to Secrets Sentry

Thank you for your interest in contributing to Secrets Sentry! This document provides guidelines and instructions for development.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Git
- pip

### Installation

1. Clone the repository:
```bash
git clone [<repository-url>](https://github.com/NodeSaint/SecretSentry)
cd SecretsSentry
```

2. Create a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install Playwright browsers (for E2E tests):
```bash
playwright install
```

## Project Structure

```
secrets-sentry/
├── src/                    # Source code
│   ├── scanner/           # Detection modules
│   ├── migration/         # Auto-fix modules
│   ├── hooks/             # Pre-commit hook
│   ├── api/               # API endpoints
│   ├── dashboard/         # Web UI
│   ├── notifications/     # Webhook integrations
│   ├── reports/           # Report generation
│   └── utils/             # Shared utilities
├── tests/                 # Test suite
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── e2e/              # End-to-end tests
├── fixtures/             # Test data
├── scripts/              # CLI scripts
└── data/                 # Runtime data (gitignored)
```

## Running Tests

### All Tests
```bash
pytest
```

### Unit Tests Only
```bash
pytest tests/unit/
```

### Integration Tests
```bash
pytest tests/integration/
```

### End-to-End Tests
```bash
pytest tests/e2e/
```

### With Coverage
```bash
pytest --cov=src --cov-report=html
```

## Code Style

We follow PEP 8 with some modifications:

- Line length: 100 characters
- Use type hints for all function signatures
- Use docstrings for all public functions and classes

### Formatting

We use Black for code formatting:

```bash
black src/ tests/
```

### Linting

We use Ruff for linting:

```bash
ruff check src/ tests/
```

## Making Changes

### Branching Strategy

1. Create a feature branch from `main`:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes and commit:
```bash
git add .
git commit -m "feat: add your feature description"
```

3. Push to your fork and create a pull request

### Commit Message Format

We follow Conventional Commits:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

Examples:
```
feat: add Discord webhook support
fix: correct entropy calculation for edge cases
docs: update README with new configuration options
test: add unit tests for pattern detector
```

## Adding New Secret Patterns

To add a new secret detection pattern:

1. Add the regex pattern to `src/scanner/patterns.py`:
```python
PATTERNS = {
    "YOUR_SERVICE": {
        "pattern": r"your-regex-pattern",
        "confidence": 0.9,
        "remediation": "Instructions for fixing this secret type"
    }
}
```

2. Add test cases to `tests/unit/test_patterns.py`:
```python
def test_your_service_detection():
    detector = PatternDetector()
    result = detector.scan("code with your-secret-here")
    assert result.rule == "YOUR_SERVICE"
```

3. Document the pattern in `README.md` under "Supported Secret Types"

## Adding New Notification Channels

To add support for a new notification channel:

1. Create a new module in `src/notifications/`:
```python
# src/notifications/your_service.py
import httpx

async def send_notification(webhook_url: str, scan_results: dict):
    # Implementation
    pass
```

2. Add integration to `src/notifications/notifier.py`

3. Add configuration to settings schema

4. Add tests to `tests/integration/test_notifications.py`

## Testing Guidelines

### Unit Tests
- Test individual functions in isolation
- Mock external dependencies
- Use fixtures for test data

### Integration Tests
- Test interactions between modules
- Use real implementations where possible
- Test error handling

### E2E Tests
- Test complete user workflows
- Use Playwright for browser automation
- Keep tests fast and reliable

## Documentation

When adding new features:

1. Update docstrings in the code
2. Update README.md if it affects user-facing functionality
3. Update project.md for architectural changes
4. Add examples to relevant sections

## Pull Request Process

1. Ensure all tests pass
2. Update documentation
3. Add a clear description of your changes
4. Link any related issues
5. Request review from maintainers

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] All tests passing
- [ ] Commits follow conventional format
- [ ] No merge conflicts

## Questions or Issues?

If you have questions or encounter issues:

1. Check existing issues on GitHub
2. Search the documentation
3. Open a new issue with details

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Focus on the code, not the person
- Help others learn and grow

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
