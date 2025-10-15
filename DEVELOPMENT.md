# Development Workflow

This guide explains how to contribute to Secrets Sentry while maintaining clean, OSINT-proof releases.

## Philosophy

- **Public `main` branch**: Always release-ready, no internal docs, OSINT-proof
- **Internal planning**: Use gitignored files that never enter version control
- **Clean releases**: Only user-facing documentation and production code

## Setup for Development

```bash
# Clone the repository
git clone https://github.com/NodeSaint/SecretSentry.git
cd SecretSentry

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt

# Run tests
pytest
```

## Working on New Features

### 1. Create Internal Planning Directory (Gitignored)

```bash
# Create directory for internal planning docs
mkdir internal

# Add your planning documents
# internal/feature_plan.md
# internal/progress.md
# internal/testing_notes.md
```

These files are automatically gitignored and will **never** be committed.

### 2. Develop Your Feature

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Write code, tests, and user-facing docs
# Commit frequently
git add src/ tests/ README.md
git commit -m "feat: Add new feature"

# Internal docs stay in internal/ and are not committed
```

### 3. Prepare for Pull Request

Before submitting a PR, ensure:

```bash
# Run full test suite
pytest

# Check no internal docs are staged
git status
# Should NOT see any files matching:
# - internal/
# - PLAN_*.md
# - PROGRESS_*.md
# - V2_*.md
# - demo_*.py

# Update user-facing docs only
# - README.md (if feature is user-facing)
# - CHANGELOG.md (add to Unreleased section)
# - CONTRIBUTING.md (if workflow changes)
```

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR** (v2.0.0): Breaking changes
- **MINOR** (v1.1.0): New features, backward compatible
- **PATCH** (v1.0.1): Bug fixes, backward compatible

### Creating a Release (Maintainers Only)

```bash
# 1. Ensure you're on main with latest changes
git checkout main
git pull

# 2. Update CHANGELOG.md
# Move items from [Unreleased] to [X.Y.Z] - YYYY-MM-DD

# 3. Verify no internal docs are present
find . -name "PLAN_*.md" -o -name "PROGRESS_*.md" -o -name "V[0-9]*_*.md"
# Should return nothing (or only gitignored files)

# 4. Commit release prep
git add CHANGELOG.md
git commit -m "chore: Prepare vX.Y.Z release"

# 5. Tag the release
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# 6. Push to GitHub
git push origin main --tags

# 7. Create GitHub Release
gh release create vX.Y.Z --title "vX.Y.Z" --notes-file RELEASE_NOTES.md
```

## What Gets Committed vs Gitignored

### ✅ Always Commit (User-Facing)
- Source code (`src/`, `scripts/`)
- Tests (`tests/`)
- User documentation (README.md, QUICKSTART.md, CONTRIBUTING.md)
- Configuration (requirements.txt, pyproject.toml, .gitignore)
- CHANGELOG.md (public-facing release notes only)

### ❌ Never Commit (Internal)
These patterns are automatically gitignored:

- `internal/` directory
- `.dev/` directory
- `PLAN_*.md`
- `PROGRESS_*.md`
- `TODO_*.md`
- `NOTES_*.md`
- `*_INTERNAL.md`
- `*_PLANNING.md`
- `V[0-9]*_*.md` (e.g., V2.0_PLAN.md)
- `demo_*.py`
- `experiment_*.py`

## OSINT-Proof Checklist

Before every release, verify:

- [ ] No `TODO`, `FIXME`, `WIP` in user-facing docs
- [ ] No version roadmaps (v2.0, v3.0 plans) in public docs
- [ ] No "coming soon" or "planned features" statements
- [ ] No internal planning documents committed
- [ ] No personal information (names, emails, paths)
- [ ] CHANGELOG contains only factual present-state information
- [ ] No test failures or known issues mentioned (unless critical security warning)

## Example Workflow

```bash
# Start new feature for v1.1.0
mkdir -p internal
echo "# V1.1.0 Plan" > internal/v1.1_plan.md

# Work on the feature
git checkout -b feature/notifications
# Edit code...
git add src/notifications/
git commit -m "feat: Add Slack notification support"

# internal/v1.1_plan.md is NOT committed (gitignored)

# Ready to release
git checkout main
git merge feature/notifications

# Update CHANGELOG.md with user-facing notes only
# No mention of internal planning or future roadmap

git add CHANGELOG.md
git commit -m "chore: Prepare v1.1.0 release"
git tag -a v1.1.0 -m "Release v1.1.0"
git push origin main --tags
```

## CI/CD Integration

Our GitHub Actions workflows automatically:
- Run tests on every PR
- Check code quality
- Verify no secrets are committed (except test fixtures)

See `.github/workflows/` for details.

## Questions?

- Check [CONTRIBUTING.md](./CONTRIBUTING.md) for general contribution guidelines
- Open an issue for questions or clarifications
- Join discussions in GitHub Discussions

---

**Remember**: Keep `main` clean and release-ready at all times. Use gitignored `internal/` directory for planning documents.
