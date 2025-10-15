# Secrets Sentry - Quick Start Guide

Get started with Secrets Sentry in 5 minutes!

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Quick Start: 4-Step Workflow

### Step 1: Scan for Secrets

Scan your repository to detect hardcoded secrets:

```bash
python -m scripts.scan
```

This will:
- Scan all files in your repository
- Detect hardcoded secrets using pattern matching and entropy analysis
- Save findings to `data/findings.json`
- Display results with color-coded confidence levels

**Example output:**
```
🔍 Scanning repository...
━━━━━━━━━━━━━━━━━━━━━━━ 100% ━━━━━━━━━━━━━━━━━━━━━━━

📊 Scan Results:
  Total findings: 3
  High confidence: 2
  Files affected: 2

⚠️  Findings:
  config.py:12  [AWS_ACCESS_KEY] AKIA***MPLE (confidence: 0.95)
```

### Step 2: Interactive Remediation

Review findings and create a migration plan:

```bash
python -m scripts.fix
```

For each finding:
- Review the secret and its location
- Choose whether to migrate it to an environment variable
- Accept or customize the suggested variable name

This creates a `.env.instructions` file with your migration plan.

**Pro tip:** Use `--auto` to automatically fix all findings, or `--dry-run` to preview changes.

### Step 3: Set Environment Variables

#### Option A: Automated (Clipboard Helper)

Use the interactive clipboard utility:

```bash
python -m scripts.secrets_copy
```

This will copy each secret to your clipboard, pause for you to paste it into your environment configuration, then continue.

#### Option B: Manual

Add secrets to your environment using one of these methods:
1. **`.env` file**: Create/update `.env` file in your project root
2. **System environment**: Export variables in your shell (`.bashrc`, `.zshrc`)
3. **Hosting platform**: Use your platform's secrets manager (Heroku Config Vars, Vercel Environment Variables, AWS Secrets Manager, etc.)

Reference `.env.instructions` for the list of variables to set.

### Step 4: Verify Setup

Verify all secrets are properly set:

```bash
python -m scripts.verify
```

This checks that all required environment variables exist and shows their status.

**Success output:**
```
✅ All 3 environment variable(s) are set!

Next steps:
  1. Run your application to test
  2. Delete: rm .env.instructions
```

## Advanced Usage

### Scan Git History

Scan commit history for secrets that were committed in the past:

```bash
python -m scripts.scan --history --depth 100
```

### Run Web Dashboard

Start a web interface to view and manage findings:

```bash
python -m scripts.serve
```

Access at: http://localhost:8000

### Custom Confidence Threshold

Only report high-confidence findings:

```bash
python -m scripts.scan --confidence 0.9
```

### Exclude Patterns

Add custom patterns to exclude from scanning:

```bash
python -m scripts.scan --exclude "tests/**" --exclude "*.test.js"
```

## Command Reference

| Command | Purpose | Common Options |
|---------|---------|----------------|
| `scripts.scan` | Detect secrets | `--history`, `--confidence`, `--exclude` |
| `scripts.fix` | Remediate secrets | `--auto`, `--dry-run` |
| `scripts.verify` | Check env vars | `--verbose` |
| `scripts.serve` | Start dashboard | `--port`, `--reload` |
| `scripts.secrets_copy` | Clipboard helper | `--auto-advance` |

## CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/security.yml
- name: Scan for secrets
  run: python -m scripts.scan --quiet --confidence 0.8
```

Exit codes:
- `0` = No secrets found
- `1` = Secrets detected or error
- `130` = User cancelled (Ctrl+C)

## File Structure

```
SecretsSentry/
├── scripts/           # CLI commands
│   ├── scan.py       # Secret detection
│   ├── fix.py        # Interactive remediation
│   ├── verify.py     # Verify env vars
│   ├── serve.py      # Web dashboard
│   └── secrets_copy.py  # Clipboard utility
├── data/             # Scan results and logs
│   ├── findings.json    # Detected secrets
│   ├── settings.json    # Configuration
│   └── migration_log.json  # Migration history
└── .env.instructions # Migration plan (temporary)
```

## Configuration

Settings are stored in `data/settings.json`:

```json
{
  "scan": {
    "entropy_threshold": 4.0,
    "min_token_length": 20,
    "confidence_threshold": 0.7,
    "exclude_patterns": ["node_modules/**", ".venv/**"]
  }
}
```

Modify using the `load_settings()` and `save_settings()` functions.

## Best Practices

1. **Scan regularly**: Run scans before commits or in CI/CD
2. **High confidence first**: Fix high-confidence findings immediately
3. **Never commit .env.instructions**: Contains sensitive data
4. **Rotate leaked secrets**: If secrets are in git history, rotate them
5. **Use git history scan**: Check for historical leaks periodically
6. **Custom exclude patterns**: Add project-specific patterns to reduce noise

## Troubleshooting

### "No findings to review"

Run `python -m scripts.scan` first to detect secrets.

### "Module not found" errors

Install dependencies: `pip install -r requirements.txt`

### Pyperclip not working (Linux)

Install xclip: `sudo apt-get install xclip`

### Port 8000 already in use

Use different port: `python -m scripts.serve --port 8001`

## Security Notes

⚠️ **Important:**

- Never commit `.env.instructions` to git
- Delete `.env.instructions` after migration
- If secrets are in git history, rotate them immediately
- Use your hosting platform's secrets manager (not .env files) for production secrets
- Review all findings manually before deploying

## Getting Help

For detailed documentation:
- Scripts README: `scripts/README.md`
- Project README: `README.md`
- API Docs: Run `python -m scripts.serve` and visit `/docs`

For help on any command:
```bash
python -m scripts.scan --help
python -m scripts.fix --help
python -m scripts.verify --help
python -m scripts.serve --help
python -m scripts.secrets_copy --help
```

## Example Session

Here's a complete workflow example:

```bash
# 1. Initial scan
$ python -m scripts.scan
# Output: Found 3 secrets in 2 files

# 2. Review and plan fixes
$ python -m scripts.fix
# Interactive: Review each secret, create migration plan

# 3. Set environment variables
$ python -m scripts.secrets_copy
# Interactive: Copies each secret to clipboard for easy setup

# 4. Verify all set
$ python -m scripts.verify
# Output: ✅ All 3 environment variable(s) are set!

# 5. (Optional) Start dashboard
$ python -m scripts.serve
# Dashboard running at http://localhost:8000

# 6. Clean up
$ rm .env.instructions
```

## Next Steps

- Read the [full documentation](README.md)
- Explore the [scripts README](scripts/README.md)
- Check the [contribution guide](CONTRIBUTING.md)
- Set up pre-commit hooks for automated scanning

---

**Happy secret hunting! 🔒**
