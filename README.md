# Secrets Sentry

**Detect, migrate, and prevent hardcoded secrets from being leaked to GitHub.**

A security tool that scans your codebase for accidentally hardcoded API keys, tokens, and other secrets that should be stored in environment variables instead. Prevent credential leaks before they reach your repository.

## Why Use Secrets Sentry?

Accidentally committing API keys, tokens, or passwords to GitHub is a common security mistake that can lead to:

- **Unauthorized access** to your services and data
- **Financial loss** from compromised cloud accounts
- **Data breaches** exposing customer information
- **Account suspension** by service providers

Secrets Sentry helps you:
- ✅ Find hardcoded secrets in your code before they reach GitHub
- ✅ Automatically refactor code to use environment variables
- ✅ Block future commits containing secrets with pre-commit hooks
- ✅ Scan git history for previously leaked secrets

## Features

- **Scan** code and git history for leaked secrets (entropy + patterns + heuristics)
- **Auto-migrate** hardcoded secrets to environment variables and refactor code automatically
- **Pre-commit hooks** block new secrets from being committed to GitHub
- **Web dashboard** for viewing findings and managing settings
- **Notifications** via Slack/Discord webhooks
- **Automated reports** and branch/PR creation with fixes

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Scan Your Repository

```bash
# Scan working tree only
python -m scripts.scan

# Scan including git history (last 100 commits)
python -m scripts.scan --history

# Scan with custom commit depth
python -m scripts.scan --history --depth 50
```

### Install Pre-Commit Hook

```bash
python -m scripts.install_hook
```

### Start Dashboard

```bash
python -m scripts.serve

# Or with custom port
python -m scripts.serve --port 3000
```

Visit `http://localhost:8000` to view the dashboard.

### Auto-Fix Secrets

```bash
# Interactive mode (confirms each fix)
python -m scripts.fix

# Auto mode (fixes all without confirmation)
python -m scripts.fix --auto
```

## Configuration

Settings are stored in `data/settings.json`:

```json
{
  "entropyThreshold": 4.0,
  "minTokenLength": 20,
  "historyDepth": 100,
  "excludePatterns": [
    "node_modules/**",
    ".venv/**",
    "dist/**",
    "build/**"
  ],
  "webhooks": {
    "slack": "https://hooks.slack.com/services/...",
    "discord": "https://discord.com/api/webhooks/..."
  },
  "notifications": {
    "enabled": true,
    "channels": ["slack", "discord"]
  }
}
```

## Supported Secret Types

Secrets Sentry detects 10+ types of secrets:

- AWS Access Keys & Secret Keys
- OpenAI API Keys
- Slack Tokens
- Discord Tokens
- GitHub Personal Access Tokens
- JWT Tokens
- Private Keys (RSA, EC, OpenSSH)
- Firebase API Keys
- Stripe API Keys
- Twilio Auth Tokens
- Generic high-entropy secrets

## How It Works

1. **Detection**: Uses Shannon entropy calculation, regex patterns, and filename heuristics to find hardcoded secrets
2. **Migration**: Generates SCREAMING_SNAKE_CASE env var names, refactors code to use `os.environ` or `process.env`
3. **Guidance**: Provides instructions to add secrets to your environment variables (`.env` file, system env, or hosting platform)
4. **Prevention**: Pre-commit hook scans staged files and blocks commits containing secrets before they reach GitHub

## Dashboard

The web dashboard provides:

- Summary tiles (scans run, leaks found, fixed, remaining)
- Findings table with filters
- Settings management
- Webhook testing
- "Run Scan Now" button for on-demand scans

## Notifications

Configure Slack and Discord webhooks to receive scan completion notifications:

1. Create an incoming webhook in Slack or Discord
2. Add the webhook URL to `data/settings.json` or via the dashboard
3. Test the webhook using the "Test Webhook" button

## Pre-Commit Hook

The pre-commit hook:

- Runs automatically before each commit
- Scans staged files for secrets
- Blocks commit if secrets are detected
- Provides clear error messages with remediation steps

To override in emergencies:

```bash
git commit --allow-once "Emergency hotfix for production incident #123"
```

## Reports

Scan reports are saved to `reports/scan_<timestamp>.md` and include:

- Summary statistics
- Detailed findings table (with redacted snippets)
- Redacted code diffs
- List of created environment variables
- Next steps for remediation

## Branch & PR Creation

After running a fix, Secrets Sentry:

1. Creates a new branch: `chore/secret-migration-<date>`
2. Commits atomic changes with descriptive messages
3. Optionally creates a PR (if GitHub integration is configured)

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](./LICENSE) file.

## Resources

- [project.md](./project.md) - Full project specification
- [GitHub Security Best Practices](https://docs.github.com/en/code-security/getting-started/best-practices-for-preventing-data-leaks-in-your-organization)
- [OWASP Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

## Support

For issues, questions, or contributions, please see [CONTRIBUTING.md](./CONTRIBUTING.md).
