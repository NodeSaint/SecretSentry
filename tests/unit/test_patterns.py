"""Unit tests for pattern-based secret detection."""

import pytest
import re
from src.scanner.patterns import PatternDetector, PATTERNS
from fixtures.test_secrets import FAKE_SECRETS, FALSE_POSITIVES


class TestPatternDetector:
    """Tests for PatternDetector class."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = PatternDetector()
        assert len(detector.compiled_patterns) == len(PATTERNS)

        # Check that patterns are compiled
        for name, config in detector.compiled_patterns.items():
            assert "regex" in config
            assert isinstance(config["regex"], re.Pattern)
            assert "confidence" in config
            assert "remediation" in config

    def test_list_patterns(self):
        """Test getting list of all pattern names."""
        detector = PatternDetector()
        pattern_list = detector.list_patterns()

        assert isinstance(pattern_list, list)
        assert len(pattern_list) > 20  # We have 20+ patterns
        assert "AWS_ACCESS_KEY" in pattern_list
        assert "OPENAI_API_KEY" in pattern_list

    def test_get_pattern_info_valid(self):
        """Test getting info for valid pattern."""
        detector = PatternDetector()
        info = detector.get_pattern_info("AWS_ACCESS_KEY")

        assert info is not None
        assert info["name"] == "AWS_ACCESS_KEY"
        assert "pattern" in info
        assert "confidence" in info
        assert "remediation" in info

    def test_get_pattern_info_invalid(self):
        """Test getting info for invalid pattern returns None."""
        detector = PatternDetector()
        info = detector.get_pattern_info("NONEXISTENT_PATTERN")
        assert info is None


class TestScanLine:
    """Tests for scan_line method."""

    def test_scan_empty_line(self):
        """Test scanning empty line."""
        detector = PatternDetector()
        findings = detector.scan_line("", 1)
        assert findings == []

    def test_scan_line_no_secrets(self):
        """Test scanning line with no secrets."""
        detector = PatternDetector()
        findings = detector.scan_line("This is a normal line of code", 1)
        assert findings == []

    def test_scan_line_line_number(self):
        """Test that line number is correctly recorded."""
        detector = PatternDetector()
        line = f"key = {FAKE_SECRETS['aws_access_key']}"
        findings = detector.scan_line(line, 42)

        assert len(findings) >= 1
        assert findings[0]["line"] == 42

    def test_scan_line_finding_structure(self):
        """Test that finding has correct structure."""
        detector = PatternDetector()
        line = f"key = {FAKE_SECRETS['aws_access_key']}"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        finding = findings[0]

        assert "token" in finding
        assert "line" in finding
        assert "start" in finding
        assert "end" in finding
        assert "rule" in finding
        assert "confidence" in finding
        assert "remediation" in finding

    def test_scan_line_multiple_secrets(self):
        """Test line with multiple different secrets."""
        detector = PatternDetector()
        line = f"aws={FAKE_SECRETS['aws_access_key']} stripe={FAKE_SECRETS['stripe_live_key']}"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 2
        rules = [f["rule"] for f in findings]
        assert "AWS_ACCESS_KEY" in rules
        assert "STRIPE_API_KEY" in rules


class TestAWSPatterns:
    """Tests for AWS secret patterns."""

    def test_aws_access_key_valid(self):
        """Test detection of valid AWS access key."""
        detector = PatternDetector()
        line = f"AWS_ACCESS_KEY_ID = {FAKE_SECRETS['aws_access_key']}"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "AWS_ACCESS_KEY"
        assert findings[0]["token"] == FAKE_SECRETS['aws_access_key']
        assert findings[0]["confidence"] == 0.95

    def test_aws_access_key_alternative(self):
        """Test detection of alternative AWS access key format."""
        detector = PatternDetector()
        line = f"key = {FAKE_SECRETS['aws_access_key_2']}"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "AWS_ACCESS_KEY"

    def test_aws_secret_key_valid(self):
        """Test detection of AWS secret key."""
        detector = PatternDetector()
        line = f'aws_secret = "{FAKE_SECRETS["aws_secret_key"]}"'
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found_aws = any(f["rule"] == "AWS_SECRET_KEY" for f in findings)
        assert found_aws

    def test_aws_access_key_boundaries(self):
        """Test AWS access key pattern boundaries."""
        detector = PatternDetector()

        # Should match
        assert detector.scan_line("AKIATESTTESTTEST1234", 1)

        # Should not match (wrong prefix)
        assert not detector.scan_line("XKIATESTTESTTEST1234", 1)

        # Should not match (too short)
        assert not detector.scan_line("AKIATEST", 1)


class TestOpenAIPatterns:
    """Tests for OpenAI API key patterns."""

    def test_openai_key_valid(self):
        """Test detection of valid OpenAI key."""
        detector = PatternDetector()
        line = f"OPENAI_API_KEY = '{FAKE_SECRETS['openai_key']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "OPENAI_API_KEY" for f in findings)
        assert found

    def test_openai_key_in_code(self):
        """Test OpenAI key detection in various code contexts."""
        detector = PatternDetector()

        contexts = [
            f'openai.api_key = "{FAKE_SECRETS["openai_key"]}"',
            f"api_key={FAKE_SECRETS['openai_key']}",
            f"const key = `{FAKE_SECRETS['openai_key']}`",
        ]

        for context in contexts:
            findings = detector.scan_line(context, 1)
            assert len(findings) >= 1, f"Should detect in context: {context}"

    def test_openai_key_prefix_required(self):
        """Test that OpenAI key must start with sk-."""
        detector = PatternDetector()

        # Should match
        assert detector.scan_line(FAKE_SECRETS['openai_key'], 1)

        # Should not match (wrong prefix)
        wrong_prefix = "pk-" + "x" * 48
        assert not any(
            f["rule"] == "OPENAI_API_KEY"
            for f in detector.scan_line(wrong_prefix, 1)
        )


class TestSlackPatterns:
    """Tests for Slack token and webhook patterns."""

    def test_slack_bot_token(self):
        """Test detection of Slack bot token."""
        detector = PatternDetector()
        line = f"SLACK_BOT_TOKEN = '{FAKE_SECRETS['slack_bot_token']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "SLACK_TOKEN"

    def test_slack_app_token(self):
        """Test detection of Slack app token."""
        detector = PatternDetector()
        line = FAKE_SECRETS['slack_app_token']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "SLACK_TOKEN"

    def test_slack_webhook_url(self):
        """Test detection of Slack webhook URL."""
        detector = PatternDetector()
        line = f"webhook = '{FAKE_SECRETS['slack_webhook']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "SLACK_WEBHOOK" for f in findings)
        assert found

    def test_slack_token_variants(self):
        """Test various Slack token prefixes."""
        detector = PatternDetector()

        variants = [
            "xoxb-test-token-here",
            "xoxa-2-test-token",
            "xoxp-user-token-12345",
            "xoxr-refresh-token",
            "xoxs-socket-token",
        ]

        for variant in variants:
            findings = detector.scan_line(variant, 1)
            assert any(f["rule"] == "SLACK_TOKEN" for f in findings), f"Should detect: {variant}"


class TestDiscordPatterns:
    """Tests for Discord token and webhook patterns."""

    def test_discord_token_format_1(self):
        """Test Discord token format starting with M."""
        detector = PatternDetector()
        line = FAKE_SECRETS['discord_token']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "DISCORD_TOKEN"

    def test_discord_token_format_2(self):
        """Test Discord token format starting with N."""
        detector = PatternDetector()
        line = FAKE_SECRETS['discord_token_2']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "DISCORD_TOKEN"

    def test_discord_webhook_new_format(self):
        """Test Discord webhook URL (discord.com)."""
        detector = PatternDetector()
        line = FAKE_SECRETS['discord_webhook']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "DISCORD_WEBHOOK" for f in findings)
        assert found

    def test_discord_webhook_old_format(self):
        """Test Discord webhook URL (discordapp.com)."""
        detector = PatternDetector()
        line = FAKE_SECRETS['discord_webhook_old']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "DISCORD_WEBHOOK" for f in findings)
        assert found


class TestGitHubPatterns:
    """Tests for GitHub token patterns."""

    def test_github_pat(self):
        """Test GitHub Personal Access Token."""
        detector = PatternDetector()
        line = f"GITHUB_TOKEN = '{FAKE_SECRETS['github_pat']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "GITHUB_PAT"
        assert findings[0]["confidence"] == 0.95

    def test_github_oauth(self):
        """Test GitHub OAuth token."""
        detector = PatternDetector()
        line = FAKE_SECRETS['github_oauth']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "GITHUB_OAUTH"

    def test_github_pat_length(self):
        """Test that GitHub PAT has correct length."""
        detector = PatternDetector()

        # Correct length (40 chars after prefix)
        valid = "ghp_" + "a" * 36
        assert detector.scan_line(valid, 1)

        # Wrong length
        invalid = "ghp_" + "a" * 20
        findings = detector.scan_line(invalid, 1)
        assert not any(f["rule"] == "GITHUB_PAT" for f in findings)


class TestJWTPatterns:
    """Tests for JWT token patterns."""

    def test_jwt_token_valid(self):
        """Test detection of valid JWT token."""
        detector = PatternDetector()
        line = f"token = '{FAKE_SECRETS['jwt_token']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "JWT_TOKEN" for f in findings)
        assert found

    def test_jwt_unsigned(self):
        """Test detection of unsigned JWT token."""
        detector = PatternDetector()
        line = FAKE_SECRETS['jwt_token_unsigned']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "JWT_TOKEN" for f in findings)
        assert found

    def test_jwt_confidence(self):
        """Test JWT token confidence level."""
        detector = PatternDetector()
        findings = detector.scan_line(FAKE_SECRETS['jwt_token'], 1)

        jwt_finding = next((f for f in findings if f["rule"] == "JWT_TOKEN"), None)
        assert jwt_finding is not None
        assert jwt_finding["confidence"] == 0.75  # JWTs are lower confidence


class TestPrivateKeyPatterns:
    """Tests for private key patterns."""

    def test_rsa_private_key(self):
        """Test detection of RSA private key."""
        detector = PatternDetector()
        line = "-----BEGIN RSA PRIVATE KEY-----"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "PRIVATE_KEY"
        assert findings[0]["confidence"] == 0.99

    def test_ec_private_key(self):
        """Test detection of EC private key."""
        detector = PatternDetector()
        line = "-----BEGIN EC PRIVATE KEY-----"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "PRIVATE_KEY"

    def test_openssh_private_key(self):
        """Test detection of OpenSSH private key."""
        detector = PatternDetector()
        line = "-----BEGIN OPENSSH PRIVATE KEY-----"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "PRIVATE_KEY"

    def test_dsa_private_key(self):
        """Test detection of DSA private key."""
        detector = PatternDetector()
        line = "-----BEGIN DSA PRIVATE KEY-----"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "PRIVATE_KEY"


class TestFirebasePatterns:
    """Tests for Firebase API key patterns."""

    def test_firebase_key_valid(self):
        """Test detection of Firebase API key."""
        detector = PatternDetector()
        line = f"FIREBASE_API_KEY = '{FAKE_SECRETS['firebase_key']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        # Could be FIREBASE_API_KEY or GOOGLE_API_KEY (both match AIza prefix)
        found = any(
            f["rule"] in ["FIREBASE_API_KEY", "GOOGLE_API_KEY"]
            for f in findings
        )
        assert found

    def test_firebase_key_prefix(self):
        """Test that Firebase key must start with AIza."""
        detector = PatternDetector()

        # Should match
        assert detector.scan_line(FAKE_SECRETS['firebase_key'], 1)

        # Should not match
        wrong_prefix = "BIza" + "x" * 35
        findings = detector.scan_line(wrong_prefix, 1)
        assert not any(
            f["rule"] == "FIREBASE_API_KEY"
            for f in findings
        )


class TestStripePatterns:
    """Tests for Stripe API key patterns."""

    def test_stripe_live_key(self):
        """Test detection of Stripe live API key."""
        detector = PatternDetector()
        line = f"STRIPE_SECRET = '{FAKE_SECRETS['stripe_live_key']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "STRIPE_API_KEY"
        assert findings[0]["confidence"] == 0.95

    def test_stripe_live_key_long(self):
        """Test Stripe key with longer format."""
        detector = PatternDetector()
        line = FAKE_SECRETS['stripe_live_key_long']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "STRIPE_API_KEY"

    def test_stripe_restricted_key(self):
        """Test detection of Stripe restricted key."""
        detector = PatternDetector()
        line = FAKE_SECRETS['stripe_restricted_key']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "STRIPE_RESTRICTED_KEY"

    def test_stripe_test_key_not_detected(self):
        """Test that Stripe test keys are not detected (only live keys)."""
        detector = PatternDetector()
        test_key = "sk_test_" + "1" * 24
        findings = detector.scan_line(test_key, 1)

        # Should not match STRIPE_API_KEY (which is sk_live_)
        stripe_findings = [f for f in findings if f["rule"] == "STRIPE_API_KEY"]
        assert len(stripe_findings) == 0


class TestTwilioPatterns:
    """Tests for Twilio API patterns."""

    def test_twilio_api_key(self):
        """Test detection of Twilio API key."""
        detector = PatternDetector()
        line = f"TWILIO_API_KEY = '{FAKE_SECRETS['twilio_api_key']}'"
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "TWILIO_API_KEY"

    def test_twilio_account_sid(self):
        """Test detection of Twilio Account SID."""
        detector = PatternDetector()
        line = FAKE_SECRETS['twilio_account_sid']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "TWILIO_ACCOUNT_SID"

    def test_twilio_key_format(self):
        """Test Twilio key format specifics."""
        detector = PatternDetector()

        # Must start with SK and be 34 chars total
        valid = "SK" + "1234567890abcdef" * 2
        assert detector.scan_line(valid, 1)


class TestGenericPatterns:
    """Tests for generic secret patterns."""

    def test_generic_api_key_pattern(self):
        """Test generic API key pattern."""
        detector = PatternDetector()

        test_cases = [
            'api_key="abcdef1234567890"',
            'apikey="abcdef1234567890"',
            "API_KEY=abcdef1234567890xyz",
            'api-secret="secret1234567890"',
        ]

        for test_case in test_cases:
            findings = detector.scan_line(test_case, 1)
            found = any(
                f["rule"] in ["GENERIC_API_KEY", "GENERIC_SECRET"]
                for f in findings
            )
            assert found, f"Should detect: {test_case}"

    def test_generic_secret_pattern(self):
        """Test generic secret pattern."""
        detector = PatternDetector()

        test_cases = [
            'secret="MySecret123"',
            'password="Pass1234"',
            'passwd="TestPass"',
            'pwd="MyPwd123"',
        ]

        for test_case in test_cases:
            findings = detector.scan_line(test_case, 1)
            found = any(f["rule"] == "GENERIC_SECRET" for f in findings)
            assert found, f"Should detect: {test_case}"

    def test_generic_base64_pattern(self):
        """Test generic base64 encoded secret pattern."""
        detector = PatternDetector()

        test_cases = [
            'token="dGhpc2lzYWZha2ViYXNlNjRlbmNvZGVkc2VjcmV0MTIzNDU2Nzg5MA=="',
            'secret="QmFzZTY0RW5jb2RlZFNlY3JldEtleQ=="',
            'key="YW5vdGhlcmJhc2U2NGVuY29kZWRzdHJpbmdoZXJl"',
        ]

        for test_case in test_cases:
            findings = detector.scan_line(test_case, 1)
            found = any(f["rule"] == "GENERIC_BASE64" for f in findings)
            assert found, f"Should detect: {test_case}"


class TestDatabaseURLPatterns:
    """Tests for database connection string patterns."""

    def test_postgres_url(self):
        """Test PostgreSQL connection string detection."""
        detector = PatternDetector()
        line = FAKE_SECRETS['postgres_url']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        assert findings[0]["rule"] == "DATABASE_URL"
        assert findings[0]["confidence"] == 0.90

    def test_mysql_url(self):
        """Test MySQL connection string detection."""
        detector = PatternDetector()
        line = FAKE_SECRETS['mysql_url']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "DATABASE_URL" for f in findings)
        assert found

    def test_mongodb_url(self):
        """Test MongoDB connection string detection."""
        detector = PatternDetector()
        line = FAKE_SECRETS['mongodb_url']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "DATABASE_URL" for f in findings)
        assert found

    def test_redis_url(self):
        """Test Redis connection string detection."""
        detector = PatternDetector()
        line = FAKE_SECRETS['redis_url']
        findings = detector.scan_line(line, 1)

        assert len(findings) >= 1
        found = any(f["rule"] == "DATABASE_URL" for f in findings)
        assert found


class TestScanMultiline:
    """Tests for scan method (multi-line content)."""

    def test_scan_empty_content(self):
        """Test scanning empty content."""
        detector = PatternDetector()
        findings = detector.scan("")
        assert findings == []

    def test_scan_single_line(self):
        """Test scanning single line content."""
        detector = PatternDetector()
        content = f"key = {FAKE_SECRETS['aws_access_key']}"
        findings = detector.scan(content)

        assert len(findings) >= 1
        assert findings[0]["line"] == 1

    def test_scan_multiline_content(self):
        """Test scanning multi-line content."""
        detector = PatternDetector()
        content = f"""Line 1
Line 2: {FAKE_SECRETS['aws_access_key']}
Line 3
Line 4: {FAKE_SECRETS['github_pat']}
Line 5"""

        findings = detector.scan(content)

        assert len(findings) >= 2

        # Check line numbers
        lines = [f["line"] for f in findings]
        assert 2 in lines  # AWS key on line 2
        assert 4 in lines  # GitHub PAT on line 4

    def test_scan_with_start_line(self):
        """Test scanning with custom start line number."""
        detector = PatternDetector()
        content = f"key = {FAKE_SECRETS['aws_access_key']}"
        findings = detector.scan(content, start_line=100)

        assert len(findings) >= 1
        assert findings[0]["line"] == 100

    def test_scan_multiple_secrets_per_line(self):
        """Test scanning line with multiple secrets."""
        detector = PatternDetector()
        content = f"aws={FAKE_SECRETS['aws_access_key']} github={FAKE_SECRETS['github_pat']}"
        findings = detector.scan(content)

        assert len(findings) >= 2


class TestFalsePositives:
    """Tests to ensure false positives are not detected."""

    def test_uuid_not_detected(self):
        """Test that UUIDs are not detected as secrets."""
        detector = PatternDetector()

        uuids = [
            FALSE_POSITIVES['uuid_v4'],
            FALSE_POSITIVES['uuid_v1'],
        ]

        for uuid in uuids:
            findings = detector.scan_line(uuid, 1)
            # UUIDs should not match any secret pattern
            assert len(findings) == 0, f"UUID should not be detected: {uuid}"

    def test_hash_not_detected(self):
        """Test that hashes are not detected as secrets."""
        detector = PatternDetector()

        hashes = [
            FALSE_POSITIVES['sha256'],
            FALSE_POSITIVES['md5'],
            FALSE_POSITIVES['sha1'],
        ]

        for hash_val in hashes:
            findings = detector.scan_line(hash_val, 1)
            # Hashes should not match any secret pattern
            assert len(findings) == 0, f"Hash should not be detected: {hash_val}"

    def test_placeholder_not_detected(self):
        """Test that common placeholders are not detected."""
        detector = PatternDetector()

        placeholders = [
            FALSE_POSITIVES['placeholder_1'],
            FALSE_POSITIVES['placeholder_2'],
            FALSE_POSITIVES['placeholder_3'],
        ]

        for placeholder in placeholders:
            findings = detector.scan_line(placeholder, 1)
            # Placeholders should not match high-confidence patterns
            high_conf = [f for f in findings if f["confidence"] > 0.8]
            assert len(high_conf) == 0, f"Placeholder should not be high confidence: {placeholder}"


class TestCaptureGroups:
    """Tests for capture group extraction."""

    def test_capture_group_extraction(self):
        """Test that capture groups are properly extracted."""
        detector = PatternDetector()

        # GENERIC_API_KEY has capture groups
        line = 'api_key="abc123def456ghi789"'
        findings = detector.scan_line(line, 1)

        if findings:
            # The token should be just the key value, not the whole pattern
            token = findings[0]["token"]
            assert token == "abc123def456ghi789"
            assert "api_key" not in token


class TestConfidenceLevels:
    """Tests for confidence level assignments."""

    @pytest.mark.parametrize("pattern_name,expected_conf", [
        ("AWS_ACCESS_KEY", 0.95),
        ("OPENAI_API_KEY", 0.95),
        ("PRIVATE_KEY", 0.99),
        ("JWT_TOKEN", 0.75),
        ("GENERIC_API_KEY", 0.70),
        ("GENERIC_SECRET", 0.65),
        ("GENERIC_BASE64", 0.60),
    ])
    def test_confidence_levels(self, pattern_name, expected_conf):
        """Test that patterns have correct confidence levels."""
        assert PATTERNS[pattern_name]["confidence"] == expected_conf
