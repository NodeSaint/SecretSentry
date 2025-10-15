# Changelog

All notable changes to Secrets Sentry will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-15

### Initial Release

First public release of Secrets Sentry - a comprehensive security tool for detecting, migrating, and preventing hardcoded secrets from being leaked to GitHub.

### Features

#### Secret Detection
- **42 secret patterns** covering major providers:
  - AWS (Access Keys, Secret Keys)
  - OpenAI API Keys
  - Slack Tokens
  - Discord Tokens
  - GitHub Personal Access Tokens
  - Anthropic API Keys
  - Azure Keys
  - Google Cloud/Firebase API Keys
  - Stripe API Keys
  - Twilio Auth Tokens
  - Database Connection Strings (PostgreSQL, MySQL, MongoDB, Redis)
  - JWT Tokens
  - Private Keys (RSA, EC, OpenSSH)
  - Generic API Keys and Base64 Secrets

- **Shannon entropy detection** with configurable threshold (default: 4.0)
- **Filename-based heuristics** for suspicious files (`.env`, `config.*`, `*.pem`, etc.)
- **Git history scanning** to find secrets in previous commits
- **Configurable exclusion patterns** to skip irrelevant files

#### Secret Remediation
- **Interactive fix workflow** to review and migrate secrets
- **Automatic code refactoring** using AST-based tools:
  - Python support with `pasta` library (preserves formatting)
  - JavaScript/TypeScript support with smart regex
  - Generic file type support
- **Environment variable migration** with SCREAMING_SNAKE_CASE naming
- **Automatic backup creation** before modifications
- **Unified diff generation** with syntax highlighting

#### Prevention
- **Pre-commit hook integration** using the `pre-commit` framework
- **Automatic blocking** of commits containing high-confidence secrets (≥0.8)
- **Beautiful error messages** with remediation suggestions
- **Fail-open design** for safety
- **Easy installation** with interactive CLI

#### Web Dashboard
- **FastAPI-based web interface** at http://localhost:8000
- **Summary statistics** (scans run, leaks found, fixed, remaining)
- **Findings table** with filters and search
- **Settings management** interface
- **Webhook testing** for notifications
- **Health check endpoint** for monitoring

#### Additional Tools
- **Clipboard utility** (`scripts/secrets_copy.py`) for easy secret migration
- **Verification command** to check environment variables are set
- **Comprehensive CLI** with `--help` for all commands

### Documentation
- Comprehensive README with usage examples
- Quick Start guide for new users
- Contributing guidelines
- Extensive inline code documentation

### Technical Details
- **Python 3.9+** required
- **203 unit and integration tests** (97% passing)
- **Type hints** throughout codebase
- **Pydantic-based** configuration system
- **Atomic JSON storage** with safety guarantees
- **GitPython** for history scanning
- **Rich** for beautiful CLI output

### File Structure
```
SecretsSentry/
├── src/
│   ├── scanner/        # Detection engine
│   ├── migration/      # Code refactoring
│   ├── hooks/          # Pre-commit integration
│   └── utils/          # Configuration & storage
├── scripts/
│   ├── scan.py         # Scan command
│   ├── fix.py          # Interactive remediation
│   ├── verify.py       # Verify environment variables
│   ├── serve.py        # Web dashboard
│   ├── install_hook.py # Pre-commit hook installer
│   └── secrets_copy.py # Clipboard utility
└── tests/              # Comprehensive test suite
```

### Security Features
- **Automatic redaction** of secrets in output (shows only last 4 characters)
- **No secrets in logs** or error messages
- **Atomic file operations** to prevent data loss
- **Backup creation** before any file modifications
- **Git history scanning** to find historical leaks

### Notes
- Test suite includes 203 tests with 97% pass rate
- Web dashboard provides health checks and findings API
- Notifications and reports can be extended by contributing to the project

### Installation

```bash
# Clone the repository
git clone https://github.com/NodeSaint/SecretSentry.git
cd SecretSentry

# Install dependencies
pip install -r requirements.txt

# Run a scan
python -m scripts.scan
```

### Quick Start

```bash
# 1. Scan for secrets
python -m scripts.scan

# 2. Review and create migration plan
python -m scripts.fix

# 3. Add secrets to environment variables
# (manually or use scripts.secrets_copy)

# 4. Verify setup
python -m scripts.verify

# 5. Install pre-commit hook
python -m scripts.install_hook
```

### For the Vibecoders Community

This project was built with the hope that **vibecoders** everywhere will use it to ensure they're not accidentally leaking secrets in their code. Whether you're a solo developer, part of a team, or contributing to open source - protecting your API keys and credentials is essential.

**We encourage all vibecoders to:**
- Run Secrets Sentry before pushing code to GitHub
- Install the pre-commit hook for automatic protection
- Share this tool with your coding community
- Help keep the vibecoding ecosystem secure

Let's build together, securely!

### Credits

Built with security and usability in mind. Every change is auditable, every step is reversible.

---

**Full Changelog**: https://github.com/NodeSaint/SecretSentry/commits/v1.0.0
