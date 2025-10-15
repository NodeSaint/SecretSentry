# Secrets Sentry CLI Scripts

Beautiful, production-ready CLI interface for Secrets Sentry built with Click and Rich.

## Installation

First, install the required dependencies:

```bash
pip install -r requirements.txt
```

## Available Commands

### 1. Scan - Secret Detection

Scan your repository for hardcoded secrets and credentials.

```bash
# Scan working tree
python -m scripts.scan

# Scan git history
python -m scripts.scan --history

# Custom depth and confidence threshold
python -m scripts.scan --history --depth 500 --confidence 0.8

# Add custom exclude patterns
python -m scripts.scan --exclude "tests/**" --exclude "*.test.js"

# Quiet mode (minimal output)
python -m scripts.scan --quiet

# Custom output file
python -m scripts.scan --output custom-findings.json
```

**Features:**
- Progress bar for large scans
- Color-coded confidence levels (red=high, yellow=medium, blue=low)
- Summary statistics
- Git history scanning support
- Configurable confidence thresholds
- Custom exclude patterns
- Beautiful formatted output

### 2. Fix - Interactive Remediation

Interactively review and fix detected secrets.

```bash
# Interactive mode (recommended)
python -m scripts.fix

# Auto-fix all findings
python -m scripts.fix --auto

# Preview changes without applying
python -m scripts.fix --dry-run

# Use custom findings file
python -m scripts.fix --input custom-findings.json
```

**Features:**
- Step-by-step secret review
- Automatic environment variable name generation
- Custom naming support
- Generates `.env.instructions` file
- Migration tracking
- Dry-run mode for previewing changes

### 3. Verify - Environment Check

Verify that all required environment variables are set.

```bash
# Verify all required secrets
python -m scripts.verify

# Show value previews
python -m scripts.verify --verbose

# Use custom instructions file
python -m scripts.verify --instructions my-secrets.txt
```

**Features:**
- Checks all environment variables from migration plan
- Color-coded status (green=set, red=missing)
- Value preview mode (with masking)
- Exit code 0 if all set, 1 if any missing
- Helpful setup instructions

### 4. Serve - Web Dashboard

Start the web dashboard to view and manage findings.

```bash
# Start with defaults (port 8000)
python -m scripts.serve

# Custom host and port
python -m scripts.serve --host 127.0.0.1 --port 3000

# Development mode with auto-reload
python -m scripts.serve --reload

# Disable access logs
python -m scripts.serve --no-access-log
```

**Features:**
- Beautiful web interface
- REST API endpoints
- Real-time findings display
- Statistics dashboard
- Automatic OpenAPI documentation at `/docs`
- Network IP detection for remote access

**API Endpoints:**
- `GET /` - Dashboard home page
- `GET /api/health` - Health check
- `GET /api/findings` - List all findings
- `GET /api/stats` - Get statistics
- `GET /docs` - Interactive API documentation

### 5. Secrets Copy - Clipboard Utility

Interactive clipboard utility to help set up environment variables.

```bash
# Interactive mode
python -m scripts.secrets_copy

# Auto-advance mode (3 second delay)
python -m scripts.secrets_copy --auto-advance

# Use custom instructions file
python -m scripts.secrets_copy --instructions my-secrets.txt
```

**Features:**
- Step-by-step clipboard copying
- Copies both key names and values
- Detects already-set variables
- Auto-advance mode for faster setup
- Progress tracking
- Helpful instructions for environment setup

## Typical Workflow

Here's the recommended workflow for using Secrets Sentry:

```bash
# 1. Scan your repository
python -m scripts.scan

# 2. Review and plan fixes
python -m scripts.fix

# 3. Set environment variables (use clipboard helper or manually)
python -m scripts.secrets_copy

# 4. Verify all secrets are set
python -m scripts.verify

# 5. (Optional) Start dashboard to monitor findings
python -m scripts.serve
```

## Output Examples

### Scan Output

```
🔍 Scanning repository...
━━━━━━━━━━━━━━━━━━━━━━━ 100% ━━━━━━━━━━━━━━━━━━━━━━━

╭─────────────── 📊 Scan Results ───────────────╮
│ Total findings:      5                         │
│ High confidence:     3                         │
│ Medium confidence:   2                         │
│ Low confidence:      0                         │
│ Files affected:      3                         │
╰────────────────────────────────────────────────╯

⚠️  Findings:

config.py
  🔴 line 12  AWS_ACCESS_KEY  api_key = "AKIA***MPLE"  (0.95)
  🔴 line 45  OPENAI_API_KEY  key = "sk-***xyz123"  (0.95)

💾 Results saved to: data/findings.json
```

### Fix Output

```
╭──────────── 📝 Secret Remediation ─────────────╮
│ Found 5 secret(s) to review                    │
│ Review each finding and decide whether to      │
│ migrate it to an environment variable.         │
╰────────────────────────────────────────────────╯

[1/5] config.py:12
  Rule: AWS_ACCESS_KEY
  Confidence: 0.95
  Snippet: api_key = "AKIA***MPLE"

  Suggested env var: AWS_ACCESS_KEY_ID
  Remediation: Move to environment variable

  Fix this secret? [y/n/q/a=all] › y

✅ Marked for fixing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

╭────────────── ✨ Fix Summary ──────────────────╮
│ Secrets to migrate:  3                         │
│ Files to update:     2                         │
│ Env vars to create:  3                         │
╰────────────────────────────────────────────────╯

📄 Instructions saved to: .env.instructions

Next steps:
  1. Review .env.instructions
  2. Set environment variables using your preferred method
  3. Run: python -m scripts.verify
```

### Verify Output

```
╭───── 🔍 Environment Verification ─────╮
│ Checking 3 environment variable(s)    │
╰───────────────────────────────────────╯

┌─────────────────────────┬─────────┐
│ Environment Variable    │ Status  │
├─────────────────────────┼─────────┤
│ AWS_ACCESS_KEY_ID       │ ✅ Set  │
│ OPENAI_API_KEY          │ ✅ Set  │
│ SLACK_WEBHOOK_URL       │ ❌ Miss │
└─────────────────────────┴─────────┘

╭────────────────────────────────────╮
│ ⚠️  Status: 2/3 variable(s) set    │
│ 1 variable(s) missing              │
╰────────────────────────────────────╯

Missing variables:
  • SLACK_WEBHOOK_URL
```

## Error Handling

All scripts include comprehensive error handling:

- **Exit code 0**: Success
- **Exit code 1**: Error or findings detected
- **Exit code 130**: User cancelled (Ctrl+C)

Scripts provide helpful error messages and suggestions for resolution.

## Tips

1. **First-time setup**: Run all commands in order to get familiar with the workflow
2. **CI/CD integration**: Use `python -m scripts.scan --quiet` in CI pipelines
3. **Custom patterns**: Add project-specific exclude patterns to avoid false positives
4. **Dashboard**: Keep the dashboard running during development for real-time monitoring
5. **Git history**: Scan history periodically to catch secrets committed in the past

## Troubleshooting

### Import Errors

If you see `ModuleNotFoundError`, install dependencies:

```bash
pip install -r requirements.txt
```

### Pyperclip Issues

On Linux, pyperclip requires additional packages:

```bash
# Ubuntu/Debian
sudo apt-get install xclip

# Fedora
sudo dnf install xclip
```

### Port Already in Use

If port 8000 is taken:

```bash
python -m scripts.serve --port 8001
```

## Architecture

All scripts follow these principles:

- **Rich UI**: Beautiful terminal output using Rich library
- **Click Framework**: Professional CLI with help text and validation
- **Error Handling**: Graceful failure with helpful messages
- **Exit Codes**: Proper exit codes for CI/CD integration
- **Progress Feedback**: Progress bars and spinners for long operations
- **Interruptible**: Ctrl+C handling in all commands
- **Standalone**: Each script can be run independently

## Contributing

When adding new CLI commands:

1. Use Click for argument parsing
2. Use Rich for terminal output
3. Add comprehensive `--help` text
4. Handle errors gracefully
5. Use proper exit codes
6. Add progress indicators for long operations
7. Update this README

## License

Part of Secrets Sentry - see main LICENSE file.
