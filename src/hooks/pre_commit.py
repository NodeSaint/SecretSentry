"""
Pre-commit hook for Secrets Sentry.

Scans staged files for secrets before allowing commit.
Blocks commits containing high-confidence secrets.
"""

import sys
import subprocess
from pathlib import Path
from typing import List, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.scanner.scanner import Scanner
from src.utils.config import load_settings


def get_staged_files() -> List[str]:
    """
    Get list of staged files from git.

    Returns:
        List of file paths
    """
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'],
            capture_output=True,
            text=True,
            check=True
        )
        files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        return files
    except subprocess.CalledProcessError:
        return []


def get_file_content_staged(file_path: str) -> str:
    """
    Get the staged content of a file (what would be committed).

    Args:
        file_path: Path to file

    Returns:
        Staged file content
    """
    try:
        result = subprocess.run(
            ['git', 'show', f':{file_path}'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        # If git show fails, read from working directory
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            return ""


def main() -> int:
    """
    Main pre-commit hook entry point.

    Returns:
        0 if commit should proceed, 1 if commit should be blocked
    """
    try:
        # Load settings
        try:
            settings = load_settings()
            confidence_threshold = settings.scan.confidence_threshold
        except Exception:
            # Use default if settings can't be loaded
            confidence_threshold = 0.8

        # Get staged files
        staged_files = get_staged_files()

        if not staged_files:
            # No files to check
            return 0

        # Initialize scanner
        scanner = Scanner()

        # Scan staged files
        all_findings = []
        for file_path in staged_files:
            # Skip binary files and common exclusions
            if any(pattern in file_path for pattern in [
                '.git/', 'node_modules/', '__pycache__/', '.pyc',
                '.jpg', '.png', '.gif', '.pdf', '.zip', '.tar', '.gz'
            ]):
                continue

            # Get staged content
            content = get_file_content_staged(file_path)
            if not content:
                continue

            # Scan content
            findings = scanner.scan_content(content, file_path=file_path)

            # Filter by confidence threshold
            high_confidence_findings = [
                f for f in findings
                if f.confidence >= confidence_threshold
            ]

            all_findings.extend(high_confidence_findings)

        # Check if we found any high-confidence secrets
        if all_findings:
            print()
            print("=" * 70)
            print("🚨 SECRETS DETECTED IN STAGED FILES")
            print("=" * 70)
            print()
            print(f"Found {len(all_findings)} high-confidence secret(s) in your staged changes.")
            print("Committing secrets is dangerous and should be avoided!")
            print()

            # Group by file
            by_file = {}
            for finding in all_findings:
                file_path = finding.file
                if file_path not in by_file:
                    by_file[file_path] = []
                by_file[file_path].append(finding)

            # Display findings
            for file_path, findings in sorted(by_file.items()):
                print(f"📄 {file_path}:")
                for finding in findings:
                    print(f"   Line {finding.line}: {finding.rule} (confidence: {finding.confidence:.2f})")
                    print(f"   → {finding.remediation}")
                print()

            print("=" * 70)
            print("OPTIONS:")
            print("=" * 70)
            print()
            print("1. Remove secrets from your code:")
            print("   git reset HEAD <file>  # Unstage the file")
            print("   # Edit file to remove secrets")
            print("   git add <file>         # Re-stage")
            print()
            print("2. Use Secrets Sentry to migrate secrets:")
            print("   python -m scripts.scan")
            print("   python -m scripts.fix")
            print()
            print("3. If this is a false positive, bypass with:")
            print("   git commit --no-verify")
            print("   (Use sparingly! Only for genuine false positives)")
            print()
            print("=" * 70)
            print()

            return 1  # Block commit

        # No secrets found, allow commit
        return 0

    except Exception as e:
        # If hook fails, print error but allow commit (fail-open)
        print(f"⚠️  Secrets Sentry pre-commit hook error: {e}", file=sys.stderr)
        print("Allowing commit to proceed (fail-open)", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
