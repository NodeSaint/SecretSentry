"""Shannon entropy calculation for secret detection."""

import math
from typing import Tuple


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Formula: H(X) = -Σ p(x) * log2(p(x))
    where p(x) is the probability of character x appearing.

    Args:
        data: String to calculate entropy for

    Returns:
        Float value representing the entropy (0-8 for ASCII)
    """
    if not data:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)

    for count in char_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(
    data: str,
    threshold: float = 4.0,
    min_length: int = 20
) -> Tuple[bool, float]:
    """
    Check if a string has high entropy (likely a secret).

    Args:
        data: String to analyze
        threshold: Entropy threshold (default 4.0)
        min_length: Minimum string length to check (default 20)

    Returns:
        Tuple of (is_suspicious, entropy_score)
    """
    if len(data) < min_length:
        return False, 0.0

    entropy = calculate_entropy(data)
    return entropy >= threshold, entropy


def extract_high_entropy_strings(
    text: str,
    threshold: float = 4.0,
    min_length: int = 20,
    max_length: int = 200
) -> list[Tuple[str, float, int, int]]:
    """
    Extract all high-entropy strings from text.

    Args:
        text: Text to scan
        threshold: Entropy threshold
        min_length: Minimum token length
        max_length: Maximum token length

    Returns:
        List of tuples: (token, entropy, start_pos, end_pos)
    """
    findings = []

    # Split on common separators but preserve position
    words = []
    current_word = []
    current_start = 0

    for i, char in enumerate(text):
        if char.isalnum() or char in '_-+=/.':
            if not current_word:
                current_start = i
            current_word.append(char)
        else:
            if current_word:
                word = ''.join(current_word)
                if min_length <= len(word) <= max_length:
                    is_suspicious, entropy = is_high_entropy(
                        word, threshold, min_length
                    )
                    if is_suspicious:
                        findings.append((word, entropy, current_start, i))
                current_word = []

    # Check last word
    if current_word:
        word = ''.join(current_word)
        if min_length <= len(word) <= max_length:
            is_suspicious, entropy = is_high_entropy(word, threshold, min_length)
            if is_suspicious:
                findings.append((word, entropy, current_start, len(text)))

    return findings


class EntropyDetector:
    """Detector for high-entropy secrets."""

    def __init__(self, threshold: float = 4.0, min_length: int = 20):
        """
        Initialize entropy detector.

        Args:
            threshold: Entropy threshold (default 4.0)
            min_length: Minimum string length (default 20)
        """
        self.threshold = threshold
        self.min_length = min_length
        self.allowlist = self._default_allowlist()

    def _default_allowlist(self) -> set[str]:
        """Common high-entropy strings that are not secrets."""
        return {
            # Common base64 encoded strings
            "iVBORw0KGgoAAAANSUhEUgAA",  # PNG header
            "data:image/png;base64",
            # Common hashes
            "0123456789abcdefABCDEF",
            # Example tokens from documentation
            "exampletoken123456789",
            "your_api_key_here",
            "replace_with_your_key",
        }

    def is_allowlisted(self, token: str) -> bool:
        """Check if token is in allowlist."""
        token_lower = token.lower()
        for allowed in self.allowlist:
            if allowed.lower() in token_lower:
                return True
        return False

    def scan(self, content: str, line_number: int = 0) -> list[dict]:
        """
        Scan content for high-entropy secrets.

        Args:
            content: Text content to scan
            line_number: Line number in file (for reporting)

        Returns:
            List of finding dictionaries
        """
        findings = []

        high_entropy_strings = extract_high_entropy_strings(
            content, self.threshold, self.min_length
        )

        for token, entropy, start, end in high_entropy_strings:
            if self.is_allowlisted(token):
                continue

            findings.append({
                "token": token,
                "entropy": entropy,
                "start": start,
                "end": end,
                "line": line_number,
                "confidence": min(entropy / 8.0, 0.95),  # Scale to 0-0.95
                "rule": "HIGH_ENTROPY",
                "remediation": (
                    f"High entropy string detected (entropy: {entropy:.2f}). "
                    "This may be a secret. Consider moving to environment variables."
                )
            })

        return findings
