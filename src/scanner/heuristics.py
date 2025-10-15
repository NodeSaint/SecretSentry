"""Heuristic-based detection using filenames and patterns."""

import os
from pathlib import Path
from typing import Optional


# Suspicious filename patterns
SUSPICIOUS_FILENAMES = {
    ".env": 0.95,
    ".env.local": 0.95,
    ".env.production": 0.95,
    ".env.development": 0.95,
    ".env.test": 0.90,
    "config.json": 0.70,
    "config.yaml": 0.70,
    "config.yml": 0.70,
    "credentials.json": 0.95,
    "credentials.yml": 0.95,
    "secrets.json": 0.95,
    "secrets.yaml": 0.95,
    "id_rsa": 0.99,
    "id_dsa": 0.99,
    "id_ecdsa": 0.99,
    "id_ed25519": 0.99,
}

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = {
    ".pem": 0.90,
    ".key": 0.85,
    ".p12": 0.85,
    ".pfx": 0.85,
    ".keystore": 0.85,
}

# Suspicious filename patterns (substring matching)
SUSPICIOUS_PATTERNS = {
    "serviceaccount": 0.90,
    "service_account": 0.90,
    "service-account": 0.90,
    "private": 0.75,
    "secret": 0.75,
    "password": 0.80,
    "credential": 0.85,
    "token": 0.70,
    "apikey": 0.80,
    "api_key": 0.80,
    "api-key": 0.80,
}


class HeuristicDetector:
    """Heuristic-based detection for suspicious files."""

    def __init__(self):
        """Initialize heuristic detector."""
        self.suspicious_files = SUSPICIOUS_FILENAMES
        self.suspicious_extensions = SUSPICIOUS_EXTENSIONS
        self.suspicious_patterns = SUSPICIOUS_PATTERNS

    def check_filename(self, filepath: str) -> Optional[dict]:
        """
        Check if a filename is suspicious.

        Args:
            filepath: Path to file

        Returns:
            Dictionary with finding info or None if not suspicious
        """
        path = Path(filepath)
        filename = path.name
        filename_lower = filename.lower()
        extension = path.suffix.lower()

        # Check exact filename match
        if filename in self.suspicious_files:
            return {
                "file": filepath,
                "rule": "SUSPICIOUS_FILENAME",
                "confidence": self.suspicious_files[filename],
                "reason": f"File '{filename}' typically contains secrets",
                "remediation": (
                    f"File '{filename}' should not be committed. "
                    "Add to .gitignore and use Replit Secrets instead."
                ),
            }

        # Check extension
        if extension in self.suspicious_extensions:
            return {
                "file": filepath,
                "rule": "SUSPICIOUS_EXTENSION",
                "confidence": self.suspicious_extensions[extension],
                "reason": f"Files with '{extension}' extension often contain secrets",
                "remediation": (
                    f"Files with '{extension}' extension should be carefully reviewed. "
                    "Consider using Replit Secrets or secure key management."
                ),
            }

        # Check substring patterns
        for pattern, confidence in self.suspicious_patterns.items():
            if pattern in filename_lower:
                return {
                    "file": filepath,
                    "rule": "SUSPICIOUS_PATTERN",
                    "confidence": confidence,
                    "reason": f"Filename contains '{pattern}' which often indicates secrets",
                    "remediation": (
                        f"File contains '{pattern}' in name. Review contents "
                        "and consider using Replit Secrets for sensitive data."
                    ),
                }

        return None

    def should_skip_file(self, filepath: str, exclude_patterns: list[str] = None) -> bool:
        """
        Check if file should be skipped based on exclude patterns.

        Args:
            filepath: Path to file
            exclude_patterns: List of glob patterns to exclude

        Returns:
            True if file should be skipped
        """
        if exclude_patterns is None:
            exclude_patterns = self.default_exclude_patterns()

        path = Path(filepath)

        # Check each exclude pattern
        for pattern in exclude_patterns:
            # Convert glob pattern to path matching
            if '*' in pattern:
                # Use pathlib's match() which supports ** recursive globbing
                try:
                    # Try matching against full path
                    if path.match(pattern):
                        return True
                    # Also try matching against relative path components
                    # This handles cases like "node_modules/**" matching "/path/to/node_modules/file"
                    path_parts = path.parts
                    for i in range(len(path_parts)):
                        sub_path = Path(*path_parts[i:])
                        if sub_path.match(pattern):
                            return True
                except Exception:
                    # Fallback to simple string matching if pattern is invalid
                    if pattern.replace('**', '').replace('*', '') in str(path):
                        return True
            else:
                # Exact substring matching
                if pattern in str(path):
                    return True

        return False

    @staticmethod
    def default_exclude_patterns() -> list[str]:
        """Get default exclude patterns."""
        return [
            "node_modules/**",
            ".venv/**",
            "venv/**",
            "env/**",
            "dist/**",
            "build/**",
            ".next/**",
            "__pycache__/**",
            "*.pyc",
            "*.pyo",
            "*.pyd",
            ".git/**",
            ".svn/**",
            ".hg/**",
            "*.lock",
            "*.min.js",
            "*.min.css",
            "*.map",
            ".DS_Store",
            "*.egg-info/**",
            ".pytest_cache/**",
            ".coverage",
            "htmlcov/**",
        ]

    def is_binary_file(self, filepath: str) -> bool:
        """
        Check if file is binary (should skip scanning).

        Args:
            filepath: Path to file

        Returns:
            True if file appears to be binary
        """
        try:
            with open(filepath, 'rb') as f:
                # Read first 8KB
                chunk = f.read(8192)

                # Check for null bytes (common in binary files)
                if b'\x00' in chunk:
                    return True

                # Check ratio of non-text characters
                non_text_chars = sum(
                    1 for byte in chunk
                    if byte < 32 and byte not in (9, 10, 13)  # tab, newline, carriage return
                )

                # If more than 30% non-text characters, consider binary
                if len(chunk) > 0 and (non_text_chars / len(chunk)) > 0.3:
                    return True

            return False

        except Exception:
            # If we can't read it, assume it's binary
            return True

    def get_file_warning(self, filepath: str) -> Optional[str]:
        """
        Get a warning message for a suspicious file.

        Args:
            filepath: Path to file

        Returns:
            Warning message or None
        """
        finding = self.check_filename(filepath)
        if finding:
            return (
                f"WARNING: {finding['reason']} "
                f"(confidence: {finding['confidence']:.0%})"
            )
        return None
