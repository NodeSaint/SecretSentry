"""Utilities for redacting secrets in output."""

from typing import Optional


def redact_secret(secret: str, show_chars: int = 4) -> str:
    """
    Redact a secret, showing only the last N characters.

    Args:
        secret: The secret string to redact
        show_chars: Number of characters to show at the end (default 4)

    Returns:
        Redacted string like "***abc123"
    """
    if not secret:
        return "***"

    if len(secret) <= show_chars:
        return "***"

    return "***" + secret[-show_chars:]


def redact_line(line: str, start: int, end: int, show_chars: int = 4) -> str:
    """
    Redact a portion of a line.

    Args:
        line: Original line
        start: Start position of secret
        end: End position of secret
        show_chars: Number of characters to show at the end

    Returns:
        Line with secret redacted
    """
    if start < 0 or end > len(line) or start >= end:
        return line

    secret = line[start:end]
    redacted = redact_secret(secret, show_chars)

    return line[:start] + redacted + line[end:]


def create_snippet(line: str, start: int, end: int, context: int = 20) -> str:
    """
    Create a context snippet around a finding.

    Args:
        line: Full line content
        start: Start position of finding
        end: End position of finding
        context: Number of characters of context on each side

    Returns:
        Snippet with context
    """
    snippet_start = max(0, start - context)
    snippet_end = min(len(line), end + context)

    snippet = line[snippet_start:snippet_end]

    # Add ellipsis if truncated
    if snippet_start > 0:
        snippet = "..." + snippet
    if snippet_end < len(line):
        snippet = snippet + "..."

    return snippet


def redact_finding_snippet(
    line: str,
    start: int,
    end: int,
    context: int = 20,
    show_chars: int = 4
) -> str:
    """
    Create a redacted snippet for a finding.

    Args:
        line: Full line content
        start: Start position of secret
        end: End position of secret
        context: Number of characters of context
        show_chars: Number of secret characters to show

    Returns:
        Redacted snippet with context
    """
    # First create the snippet
    snippet_start = max(0, start - context)
    snippet_end = min(len(line), end + context)

    # Adjust secret positions relative to snippet
    adjusted_start = start - snippet_start
    adjusted_end = end - snippet_start

    # Get snippet
    snippet = line[snippet_start:snippet_end]

    # Redact the secret in the snippet
    if 0 <= adjusted_start < len(snippet) and adjusted_end <= len(snippet):
        secret = snippet[adjusted_start:adjusted_end]
        redacted = redact_secret(secret, show_chars)
        snippet = snippet[:adjusted_start] + redacted + snippet[adjusted_end:]

    # Add ellipsis
    if snippet_start > 0:
        snippet = "..." + snippet
    if snippet_end < len(line):
        snippet = snippet + "..."

    return snippet


def mask_value(value: str, mask_char: str = "*", keep_ratio: float = 0.2) -> str:
    """
    Mask a value, keeping only a portion visible.

    Args:
        value: Value to mask
        mask_char: Character to use for masking
        keep_ratio: Ratio of characters to keep visible (0-1)

    Returns:
        Masked value
    """
    if not value:
        return mask_char * 3

    keep_count = max(1, int(len(value) * keep_ratio))
    mask_count = len(value) - keep_count

    return mask_char * mask_count + value[-keep_count:]


def is_secret_exposed(line: str, patterns: list[str] = None) -> bool:
    """
    Check if a line might expose a secret in plain text.

    Args:
        line: Line to check
        patterns: Optional list of patterns that indicate secrets

    Returns:
        True if line might expose a secret
    """
    if patterns is None:
        patterns = [
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "credentials",
        ]

    line_lower = line.lower()

    # Check for assignment patterns
    for pattern in patterns:
        if pattern in line_lower and ("=" in line or ":" in line):
            return True

    return False
