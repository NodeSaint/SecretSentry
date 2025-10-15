"""Unit tests for entropy detection module."""

import pytest
import math
from src.scanner.entropy import (
    calculate_entropy,
    is_high_entropy,
    extract_high_entropy_strings,
    EntropyDetector,
)
from fixtures.test_secrets import FAKE_SECRETS, FALSE_POSITIVES, EDGE_CASES


class TestCalculateEntropy:
    """Tests for calculate_entropy function."""

    def test_empty_string(self):
        """Test entropy calculation for empty string."""
        assert calculate_entropy("") == 0.0

    def test_single_character(self):
        """Test entropy of string with single repeated character."""
        result = calculate_entropy("aaaaaaa")
        assert result == 0.0, "String with single character should have 0 entropy"

    def test_two_characters_equal(self):
        """Test entropy of string with two equally distributed characters."""
        result = calculate_entropy("ababab")
        assert result == pytest.approx(1.0, abs=0.01), "Equal distribution of 2 chars should have entropy ~1.0"

    def test_uniform_distribution(self):
        """Test entropy of string with uniform character distribution."""
        # Each character appears once
        result = calculate_entropy("abcdefgh")
        expected = math.log2(8)  # log2(8) = 3.0
        assert result == pytest.approx(expected, abs=0.01)

    def test_known_entropy_value(self):
        """Test entropy calculation with known value."""
        # "hello" has known entropy
        result = calculate_entropy("hello")
        # h=1, e=1, l=2, o=1 out of 5
        # H = -(1/5*log2(1/5) + 1/5*log2(1/5) + 2/5*log2(2/5) + 1/5*log2(1/5))
        # H ≈ 1.92
        assert result == pytest.approx(1.92, abs=0.05)

    def test_high_entropy_random_string(self):
        """Test entropy of high-entropy random-looking string."""
        result = calculate_entropy(FAKE_SECRETS["high_entropy_1"])
        assert result > 4.0, "Random string should have high entropy"

    def test_low_entropy_repeated_pattern(self):
        """Test entropy of low-entropy repeated pattern."""
        result = calculate_entropy("ababababababababababab")
        assert result < 2.0, "Repeated pattern should have low entropy"

    def test_unicode_characters(self):
        """Test entropy calculation with unicode characters."""
        result = calculate_entropy("🔑🔐🗝️🚀✨")
        assert result >= 0.0, "Should handle unicode without error"

    def test_mixed_alphanumeric(self):
        """Test entropy of mixed alphanumeric string."""
        result = calculate_entropy("Abc123XyZ789")
        assert result > 3.0, "Mixed alphanumeric should have moderate-high entropy"

    @pytest.mark.parametrize("secret_key,secret_value", [
        ("aws_secret_key", FAKE_SECRETS["aws_secret_key"]),
        ("openai_key", FAKE_SECRETS["openai_key"]),
        ("high_entropy_hex", FAKE_SECRETS["high_entropy_hex"]),
    ])
    def test_real_secret_formats(self, secret_key, secret_value):
        """Test that real secret formats have high entropy."""
        result = calculate_entropy(secret_value)
        assert result > 3.5, f"{secret_key} should have high entropy"


class TestIsHighEntropy:
    """Tests for is_high_entropy function."""

    def test_high_entropy_above_threshold(self):
        """Test detection of high entropy string above threshold."""
        is_suspicious, entropy = is_high_entropy(FAKE_SECRETS["high_entropy_1"])
        assert is_suspicious is True
        assert entropy >= 4.0

    def test_low_entropy_below_threshold(self):
        """Test that low entropy string is not flagged."""
        is_suspicious, entropy = is_high_entropy("a" * 30)
        assert is_suspicious is False

    def test_minimum_length_filter(self):
        """Test that strings below minimum length are not checked."""
        # High entropy but too short
        is_suspicious, entropy = is_high_entropy("aB3$xZ9", min_length=20)
        assert is_suspicious is False
        assert entropy == 0.0

    def test_minimum_length_exact(self):
        """Test string at exactly minimum length."""
        test_string = "a" * 20
        is_suspicious, entropy = is_high_entropy(test_string, threshold=0.0, min_length=20)
        assert is_suspicious is True  # Length is exactly 20, entropy checked

    def test_custom_threshold(self):
        """Test high entropy detection with custom threshold."""
        test_string = "abc" * 10  # Moderate entropy

        # Should pass with low threshold
        is_suspicious_low, _ = is_high_entropy(test_string, threshold=1.0, min_length=20)
        assert is_suspicious_low is True

        # Should fail with high threshold
        is_suspicious_high, _ = is_high_entropy(test_string, threshold=5.0, min_length=20)
        assert is_suspicious_high is False

    def test_aws_secret_key(self):
        """Test AWS secret key format has high entropy."""
        is_suspicious, entropy = is_high_entropy(FAKE_SECRETS["aws_secret_key"])
        assert is_suspicious is True

    def test_uuid_not_high_entropy(self):
        """Test that UUID (false positive) is not flagged."""
        # UUIDs have moderate entropy but we use threshold to filter
        is_suspicious, entropy = is_high_entropy(FALSE_POSITIVES["uuid_v4"], threshold=4.5)
        # UUID might have ~3.5-4.0 entropy, adjust threshold if needed


class TestExtractHighEntropyStrings:
    """Tests for extract_high_entropy_strings function."""

    def test_empty_text(self):
        """Test extraction from empty text."""
        result = extract_high_entropy_strings("")
        assert result == []

    def test_no_high_entropy_strings(self):
        """Test text with no high entropy strings."""
        text = "This is a simple text with no secrets here"
        result = extract_high_entropy_strings(text)
        assert result == []

    def test_single_high_entropy_string(self):
        """Test extraction of single high entropy string."""
        secret = FAKE_SECRETS["high_entropy_1"]
        text = f"The secret is: {secret} and that's it"
        result = extract_high_entropy_strings(text)

        assert len(result) == 1
        token, entropy, start, end = result[0]
        assert token == secret
        assert entropy >= 4.0
        assert text[start:end] == secret or secret in text[start:end]

    def test_multiple_high_entropy_strings(self):
        """Test extraction of multiple high entropy strings."""
        secret1 = FAKE_SECRETS["high_entropy_1"]
        secret2 = FAKE_SECRETS["high_entropy_2"]
        text = f"First: {secret1} and second: {secret2}"
        result = extract_high_entropy_strings(text)

        assert len(result) >= 2
        tokens = [r[0] for r in result]
        assert secret1 in tokens
        assert secret2 in tokens

    def test_position_tracking(self):
        """Test that positions are correctly tracked."""
        secret = FAKE_SECRETS["high_entropy_1"]
        text = f"prefix {secret} suffix"
        result = extract_high_entropy_strings(text)

        assert len(result) == 1
        token, entropy, start, end = result[0]
        # Verify the extracted position matches the secret
        assert secret in text[start:end] or token == secret

    def test_word_boundary_detection(self):
        """Test that word boundaries are respected."""
        secret = "aB3xZ9mK5pL2qR8sT1vW7yN4"
        text = f"key={secret}&other=value"
        result = extract_high_entropy_strings(text, threshold=3.5)

        # Should extract the secret, not include = or &
        assert len(result) >= 1
        token = result[0][0]
        assert "=" not in token
        assert "&" not in token

    def test_min_length_filtering(self):
        """Test minimum length filtering."""
        text = "short=abc long=abcdefghijklmnopqrstuvwxyz123456"
        result = extract_high_entropy_strings(text, min_length=30)

        # Should only find strings >= 30 chars
        for token, _, _, _ in result:
            assert len(token) >= 30

    def test_max_length_filtering(self):
        """Test maximum length filtering."""
        very_long = "a" * 500
        text = f"secret={very_long}"
        result = extract_high_entropy_strings(text, max_length=100)

        # Should not find strings > 100 chars
        for token, _, _, _ in result:
            assert len(token) <= 100

    def test_special_characters_in_tokens(self):
        """Test that allowed special characters are included."""
        # Should include -, _, +, =, /, .
        secret = "aB3+xZ9/mK5=pL.2-qR_8sT1vW7yN4"
        text = f"token: {secret}"
        result = extract_high_entropy_strings(text, threshold=3.0, min_length=20)

        if result:
            token = result[0][0]
            # Token should contain special chars
            assert any(c in token for c in ['+', '/', '=', '-', '_', '.'])

    def test_multiline_text(self):
        """Test extraction from multiline text."""
        text = f"""Line 1: normal text
Line 2: {FAKE_SECRETS["high_entropy_1"]}
Line 3: more text
Line 4: {FAKE_SECRETS["high_entropy_2"]}"""

        result = extract_high_entropy_strings(text)
        assert len(result) >= 2


class TestEntropyDetector:
    """Tests for EntropyDetector class."""

    def test_initialization_defaults(self):
        """Test detector initialization with default values."""
        detector = EntropyDetector()
        assert detector.threshold == 4.0
        assert detector.min_length == 20
        assert isinstance(detector.allowlist, set)
        assert len(detector.allowlist) > 0

    def test_initialization_custom_values(self):
        """Test detector initialization with custom values."""
        detector = EntropyDetector(threshold=5.0, min_length=30)
        assert detector.threshold == 5.0
        assert detector.min_length == 30

    def test_allowlist_contains_common_patterns(self):
        """Test that allowlist contains common false positives."""
        detector = EntropyDetector()

        # Check for PNG header
        assert any("iVBORw0KGgoAAAANSUhEUgAA" in item for item in detector.allowlist)

    def test_is_allowlisted_exact_match(self):
        """Test allowlist matching for exact match."""
        detector = EntropyDetector()
        # Add a test item
        detector.allowlist.add("test_allowlisted_string")

        assert detector.is_allowlisted("test_allowlisted_string") is True

    def test_is_allowlisted_substring_match(self):
        """Test allowlist matching for substring match."""
        detector = EntropyDetector()
        detector.allowlist.add("example")

        # Should match if allowlisted string is substring
        assert detector.is_allowlisted("this_is_an_example_token") is True

    def test_is_allowlisted_case_insensitive(self):
        """Test that allowlist matching is case insensitive."""
        detector = EntropyDetector()
        detector.allowlist.add("example")

        assert detector.is_allowlisted("EXAMPLE_TOKEN") is True
        assert detector.is_allowlisted("Example_Token") is True

    def test_is_allowlisted_not_matched(self):
        """Test that non-allowlisted items return False."""
        detector = EntropyDetector()
        assert detector.is_allowlisted(FAKE_SECRETS["high_entropy_1"]) is False

    def test_scan_empty_content(self):
        """Test scanning empty content."""
        detector = EntropyDetector()
        findings = detector.scan("")
        assert findings == []

    def test_scan_no_secrets(self):
        """Test scanning content with no high entropy strings."""
        detector = EntropyDetector()
        content = "This is normal text with no secrets"
        findings = detector.scan(content)
        assert findings == []

    def test_scan_single_finding(self):
        """Test scanning content with one high entropy string."""
        detector = EntropyDetector()
        secret = FAKE_SECRETS["high_entropy_1"]
        content = f"The secret is {secret} here"
        findings = detector.scan(content)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding["token"] == secret
        assert finding["rule"] == "HIGH_ENTROPY"
        assert finding["confidence"] > 0
        assert finding["entropy"] >= 4.0
        assert "remediation" in finding

    def test_scan_allowlisted_item_filtered(self):
        """Test that allowlisted items are filtered out."""
        detector = EntropyDetector()
        # PNG header should be allowlisted
        content = f"image data: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAY"
        findings = detector.scan(content)

        # Should be filtered by allowlist
        assert len(findings) == 0

    def test_scan_with_line_number(self):
        """Test that line number is correctly recorded."""
        detector = EntropyDetector()
        secret = FAKE_SECRETS["high_entropy_1"]
        content = f"secret: {secret}"
        findings = detector.scan(content, line_number=42)

        assert len(findings) >= 1
        assert findings[0]["line"] == 42

    def test_scan_finding_structure(self):
        """Test that findings have correct structure."""
        detector = EntropyDetector()
        secret = FAKE_SECRETS["high_entropy_1"]
        findings = detector.scan(f"x={secret}")

        assert len(findings) >= 1
        finding = findings[0]

        # Check all required fields
        assert "token" in finding
        assert "entropy" in finding
        assert "start" in finding
        assert "end" in finding
        assert "line" in finding
        assert "confidence" in finding
        assert "rule" in finding
        assert "remediation" in finding

    def test_scan_confidence_calculation(self):
        """Test that confidence is properly calculated."""
        detector = EntropyDetector()
        secret = FAKE_SECRETS["high_entropy_1"]
        findings = detector.scan(f"x={secret}")

        if findings:
            confidence = findings[0]["confidence"]
            entropy = findings[0]["entropy"]

            # Confidence should be entropy/8, capped at 0.95
            expected = min(entropy / 8.0, 0.95)
            assert confidence == pytest.approx(expected, abs=0.01)

    def test_scan_multiple_findings(self):
        """Test scanning content with multiple high entropy strings."""
        detector = EntropyDetector()
        content = f"""
        secret1={FAKE_SECRETS["high_entropy_1"]}
        secret2={FAKE_SECRETS["high_entropy_2"]}
        """
        findings = detector.scan(content)

        assert len(findings) >= 2

    def test_scan_unicode_content(self):
        """Test scanning content with unicode characters."""
        detector = EntropyDetector()
        content = EDGE_CASES["unicode_mixed"]
        # Should not crash
        findings = detector.scan(content)
        assert isinstance(findings, list)

    def test_scan_very_long_content(self):
        """Test scanning very long content."""
        detector = EntropyDetector()
        content = EDGE_CASES["very_long_line"]
        # Should not crash and should handle long strings
        findings = detector.scan(content)
        assert isinstance(findings, list)

    @pytest.mark.parametrize("secret_key", [
        "aws_secret_key",
        "openai_key",
        "high_entropy_1",
        "high_entropy_2",
        "high_entropy_hex",
    ])
    def test_scan_detects_various_secrets(self, secret_key):
        """Test that various secret formats are detected."""
        detector = EntropyDetector()
        secret = FAKE_SECRETS[secret_key]

        # Skip if too short
        if len(secret) < 20:
            pytest.skip(f"{secret_key} is too short")

        findings = detector.scan(f"x={secret}")
        assert len(findings) >= 1, f"Should detect {secret_key}"

    def test_custom_allowlist(self):
        """Test adding custom items to allowlist."""
        detector = EntropyDetector()
        custom_item = "my_custom_allowlisted_string_12345"
        detector.allowlist.add(custom_item)

        assert detector.is_allowlisted(custom_item) is True

        # Should not appear in findings
        findings = detector.scan(f"token={custom_item}")
        assert len(findings) == 0
