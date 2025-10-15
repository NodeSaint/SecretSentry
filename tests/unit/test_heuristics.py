"""Unit tests for heuristic-based detection."""

import pytest
import os
import tempfile
from pathlib import Path
from src.scanner.heuristics import HeuristicDetector
from fixtures.test_secrets import SUSPICIOUS_FILENAMES, CLEAN_FILENAMES, EXCLUDED_PATTERNS


class TestHeuristicDetector:
    """Tests for HeuristicDetector class."""

    def test_initialization(self):
        """Test detector initialization."""
        detector = HeuristicDetector()

        assert detector.suspicious_files is not None
        assert detector.suspicious_extensions is not None
        assert detector.suspicious_patterns is not None
        assert len(detector.suspicious_files) > 0


class TestCheckFilename:
    """Tests for check_filename method."""

    def test_check_filename_returns_none_for_clean(self):
        """Test that clean filenames return None."""
        detector = HeuristicDetector()

        for filename in CLEAN_FILENAMES:
            result = detector.check_filename(filename)
            assert result is None, f"Clean filename should not be flagged: {filename}"

    def test_check_env_file(self):
        """Test detection of .env file."""
        detector = HeuristicDetector()
        result = detector.check_filename(".env")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_FILENAME"
        assert result["confidence"] == 0.95
        assert ".env" in result["reason"]
        assert "remediation" in result

    def test_check_env_variants(self):
        """Test detection of .env file variants."""
        detector = HeuristicDetector()

        env_files = [".env.local", ".env.production", ".env.development", ".env.test"]

        for env_file in env_files:
            result = detector.check_filename(env_file)
            assert result is not None, f"Should detect: {env_file}"
            assert result["rule"] == "SUSPICIOUS_FILENAME"

    def test_check_credentials_file(self):
        """Test detection of credentials files."""
        detector = HeuristicDetector()

        cred_files = ["credentials.json", "credentials.yml", "secrets.json", "secrets.yaml"]

        for filename in cred_files:
            result = detector.check_filename(filename)
            assert result is not None, f"Should detect: {filename}"
            assert result["confidence"] >= 0.90

    def test_check_ssh_keys(self):
        """Test detection of SSH private keys."""
        detector = HeuristicDetector()

        ssh_keys = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"]

        for key in ssh_keys:
            result = detector.check_filename(key)
            assert result is not None, f"Should detect: {key}"
            assert result["confidence"] == 0.99

    def test_check_pem_extension(self):
        """Test detection of .pem files."""
        detector = HeuristicDetector()
        result = detector.check_filename("certificate.pem")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_EXTENSION"
        assert ".pem" in result["reason"]

    def test_check_key_extension(self):
        """Test detection of .key files."""
        detector = HeuristicDetector()
        result = detector.check_filename("private.key")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_EXTENSION"

    def test_check_certificate_extensions(self):
        """Test detection of certificate file extensions."""
        detector = HeuristicDetector()

        cert_files = ["cert.p12", "cert.pfx", "app.keystore"]

        for filename in cert_files:
            result = detector.check_filename(filename)
            assert result is not None, f"Should detect: {filename}"
            assert result["rule"] == "SUSPICIOUS_EXTENSION"

    def test_check_serviceaccount_pattern(self):
        """Test detection of service account files."""
        detector = HeuristicDetector()

        patterns = [
            "serviceaccount.json",
            "service_account.json",
            "service-account.json",
            "my-serviceaccount.json",
        ]

        for pattern in patterns:
            result = detector.check_filename(pattern)
            assert result is not None, f"Should detect: {pattern}"
            assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_secret_pattern(self):
        """Test detection of files with 'secret' in name."""
        detector = HeuristicDetector()

        secret_files = ["secret.txt", "mysecret.json", "app_secret.yaml"]

        for filename in secret_files:
            result = detector.check_filename(filename)
            assert result is not None, f"Should detect: {filename}"
            assert result["rule"] == "SUSPICIOUS_PATTERN"
            assert "secret" in result["reason"].lower()

    def test_check_password_pattern(self):
        """Test detection of files with 'password' in name."""
        detector = HeuristicDetector()

        password_files = ["password.txt", "passwords.json", "db_password.conf"]

        for filename in password_files:
            result = detector.check_filename(filename)
            assert result is not None, f"Should detect: {filename}"
            assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_apikey_patterns(self):
        """Test detection of files with API key related names."""
        detector = HeuristicDetector()

        api_files = ["apikey.txt", "api_key.json", "api-key.yaml"]

        for filename in api_files:
            result = detector.check_filename(filename)
            assert result is not None, f"Should detect: {filename}"
            assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_credential_pattern(self):
        """Test detection of files with 'credential' in name."""
        detector = HeuristicDetector()
        result = detector.check_filename("aws_credentials")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_token_pattern(self):
        """Test detection of files with 'token' in name."""
        detector = HeuristicDetector()
        result = detector.check_filename("access_token.json")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_private_pattern(self):
        """Test detection of files with 'private' in name."""
        detector = HeuristicDetector()
        result = detector.check_filename("private_config.json")

        assert result is not None
        assert result["rule"] == "SUSPICIOUS_PATTERN"

    def test_check_with_path(self):
        """Test filename checking with full path."""
        detector = HeuristicDetector()
        result = detector.check_filename("/home/user/config/.env")

        assert result is not None
        assert ".env" in result["file"]

    def test_check_case_insensitive(self):
        """Test that pattern matching is case insensitive."""
        detector = HeuristicDetector()

        # Should detect regardless of case
        result1 = detector.check_filename("SECRET.txt")
        result2 = detector.check_filename("Secret.txt")
        result3 = detector.check_filename("secret.txt")

        assert result1 is not None
        assert result2 is not None
        assert result3 is not None

    def test_check_confidence_levels(self):
        """Test that different files have appropriate confidence levels."""
        detector = HeuristicDetector()

        # High confidence
        high_conf = detector.check_filename("id_rsa")
        assert high_conf["confidence"] == 0.99

        # Medium-high confidence
        med_conf = detector.check_filename("credentials.json")
        assert med_conf["confidence"] == 0.95

        # Medium confidence
        token_conf = detector.check_filename("token.txt")
        assert token_conf["confidence"] >= 0.70

    def test_priority_exact_over_pattern(self):
        """Test that exact filename match takes priority over pattern match."""
        detector = HeuristicDetector()

        # .env is both an exact match and contains suspicious patterns
        result = detector.check_filename(".env")

        # Should be flagged as exact match, not pattern
        assert result["rule"] == "SUSPICIOUS_FILENAME"


class TestShouldSkipFile:
    """Tests for should_skip_file method."""

    def test_should_skip_default_patterns(self):
        """Test skipping with default exclude patterns."""
        detector = HeuristicDetector()

        skip_files = [
            "node_modules/package.json",
            ".venv/lib/python3.9/site.py",
            "dist/bundle.js",
            "__pycache__/test.pyc",
            ".git/config",
            "package-lock.json",
            "bundle.min.js",
            "styles.min.css",
            "app.js.map",
        ]

        for filepath in skip_files:
            assert detector.should_skip_file(filepath) is True, f"Should skip: {filepath}"

    def test_should_not_skip_normal_files(self):
        """Test that normal files are not skipped."""
        detector = HeuristicDetector()

        normal_files = [
            "src/main.py",
            "app/index.js",
            "config.py",
            "README.md",
        ]

        for filepath in normal_files:
            assert detector.should_skip_file(filepath) is False, f"Should not skip: {filepath}"

    def test_should_skip_custom_patterns(self):
        """Test skipping with custom exclude patterns."""
        detector = HeuristicDetector()

        custom_patterns = ["*.test.js", "tmp/**", "backup/"]

        assert detector.should_skip_file("app.test.js", custom_patterns) is True
        assert detector.should_skip_file("tmp/file.txt", custom_patterns) is True
        assert detector.should_skip_file("backup/data.json", custom_patterns) is True
        assert detector.should_skip_file("src/app.js", custom_patterns) is False

    def test_should_skip_glob_patterns(self):
        """Test glob pattern matching."""
        detector = HeuristicDetector()

        patterns = ["*.pyc", "test_*.py"]

        assert detector.should_skip_file("module.pyc", patterns) is True
        assert detector.should_skip_file("test_example.py", patterns) is True
        assert detector.should_skip_file("example.py", patterns) is False

    def test_should_skip_directory_patterns(self):
        """Test directory pattern matching."""
        detector = HeuristicDetector()

        patterns = ["node_modules/**", ".venv/**"]

        assert detector.should_skip_file("node_modules/pkg/index.js", patterns) is True
        assert detector.should_skip_file(".venv/lib/site.py", patterns) is True
        assert detector.should_skip_file("src/node_modules.py", patterns) is False

    def test_should_skip_substring_patterns(self):
        """Test substring matching for non-glob patterns."""
        detector = HeuristicDetector()

        patterns = ["test", "backup"]

        assert detector.should_skip_file("path/test/file.py", patterns) is True
        assert detector.should_skip_file("backup.json", patterns) is True
        assert detector.should_skip_file("src/app.py", patterns) is False

    def test_default_exclude_patterns_content(self):
        """Test that default exclude patterns contain expected patterns."""
        patterns = HeuristicDetector.default_exclude_patterns()

        assert "node_modules/**" in patterns
        assert ".venv/**" in patterns
        assert ".git/**" in patterns
        assert "*.pyc" in patterns
        assert "*.min.js" in patterns

    def test_empty_exclude_patterns(self):
        """Test behavior with empty exclude patterns."""
        detector = HeuristicDetector()

        # Should not skip anything with empty patterns
        assert detector.should_skip_file("node_modules/file.js", []) is False


class TestIsBinaryFile:
    """Tests for is_binary_file method."""

    def test_text_file_not_binary(self):
        """Test that text files are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a text file\nWith multiple lines\n")
            f.write("And normal text content\n")
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_binary_file_detected(self):
        """Test that binary files are detected."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            # Write binary data with null bytes
            f.write(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
            f.write(b'\x00' * 100)
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is True
        finally:
            os.unlink(temp_path)

    def test_file_with_null_bytes(self):
        """Test that files with null bytes are detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'Some text\x00more text')
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is True
        finally:
            os.unlink(temp_path)

    def test_file_with_many_non_text_chars(self):
        """Test that files with many non-text characters are detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Write mostly non-text bytes (> 30%)
            binary_data = bytes(range(1, 32)) * 50  # Control characters
            f.write(binary_data)
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is True
        finally:
            os.unlink(temp_path)

    def test_empty_file_not_binary(self):
        """Test that empty files are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_python_file_not_binary(self):
        """Test that Python files are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write("#!/usr/bin/env python3\n")
            f.write("def main():\n")
            f.write("    print('Hello, world!')\n")
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_json_file_not_binary(self):
        """Test that JSON files are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('{"key": "value", "number": 123}')
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_unicode_file_not_binary(self):
        """Test that files with unicode are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as f:
            f.write("Unicode content: 你好世界 🌍 مرحبا\n")
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_nonexistent_file_is_binary(self):
        """Test that nonexistent files are treated as binary (safe default)."""
        detector = HeuristicDetector()
        assert detector.is_binary_file("/nonexistent/file.txt") is True

    def test_large_text_file_not_binary(self):
        """Test that large text files are not detected as binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # Write more than 8KB of text
            f.write("Normal text line\n" * 1000)
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)

    def test_file_with_tabs_and_newlines_not_binary(self):
        """Test that files with tabs and newlines are not binary."""
        detector = HeuristicDetector()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Column1\tColumn2\tColumn3\n")
            f.write("Value1\tValue2\tValue3\r\n")
            temp_path = f.name

        try:
            assert detector.is_binary_file(temp_path) is False
        finally:
            os.unlink(temp_path)


class TestGetFileWarning:
    """Tests for get_file_warning method."""

    def test_get_warning_for_suspicious_file(self):
        """Test getting warning for suspicious file."""
        detector = HeuristicDetector()
        warning = detector.get_file_warning(".env")

        assert warning is not None
        assert "WARNING" in warning
        assert ".env" in warning or "typically contains secrets" in warning
        assert "%" in warning  # Confidence percentage

    def test_get_warning_for_clean_file(self):
        """Test that clean files return None warning."""
        detector = HeuristicDetector()
        warning = detector.get_file_warning("main.py")

        assert warning is None

    def test_get_warning_for_private_key(self):
        """Test getting warning for private key file."""
        detector = HeuristicDetector()
        warning = detector.get_file_warning("id_rsa")

        assert warning is not None
        assert "WARNING" in warning
        assert "99%" in warning  # High confidence

    def test_get_warning_for_credentials(self):
        """Test getting warning for credentials file."""
        detector = HeuristicDetector()
        warning = detector.get_file_warning("credentials.json")

        assert warning is not None
        assert "95%" in warning

    def test_get_warning_confidence_format(self):
        """Test that warning includes properly formatted confidence."""
        detector = HeuristicDetector()
        warning = detector.get_file_warning(".env")

        # Should include percentage with % sign
        assert "%" in warning
        # Should be a whole number percentage
        import re
        match = re.search(r'(\d+)%', warning)
        assert match is not None


class TestHeuristicIntegration:
    """Integration tests combining multiple heuristic checks."""

    def test_suspicious_file_in_excluded_directory(self):
        """Test that files in excluded directories are skipped even if suspicious."""
        detector = HeuristicDetector()

        filepath = "node_modules/.env"

        # Should be skipped due to exclusion
        assert detector.should_skip_file(filepath) is True

        # But would be suspicious if not excluded
        assert detector.check_filename(".env") is not None

    def test_multiple_suspicious_indicators(self):
        """Test file with multiple suspicious indicators."""
        detector = HeuristicDetector()

        # File with suspicious name AND extension
        result = detector.check_filename("secret.key")

        # Should be detected (may match either pattern or extension first)
        assert result is not None

    def test_realistic_project_structure(self):
        """Test realistic project file structure."""
        detector = HeuristicDetector()

        project_files = {
            "src/main.py": (False, None),  # Skip, suspicious
            "src/config.py": (False, None),
            ".env": (False, "SUSPICIOUS_FILENAME"),
            ".env.example": (False, None),  # Not in suspicious list
            "node_modules/package.json": (True, None),
            ".git/config": (True, None),
            "dist/bundle.js": (True, None),
            "credentials.json": (False, "SUSPICIOUS_FILENAME"),
            "README.md": (False, None),
        }

        for filepath, (should_skip, expected_rule) in project_files.items():
            skip = detector.should_skip_file(filepath)
            assert skip == should_skip, f"Unexpected skip status for {filepath}"

            if not should_skip and expected_rule:
                finding = detector.check_filename(filepath)
                if expected_rule:
                    assert finding is not None, f"Should detect {filepath}"
                    assert finding["rule"] == expected_rule

    def test_edge_case_filenames(self):
        """Test edge case filenames."""
        detector = HeuristicDetector()

        edge_cases = [
            ".env.backup",  # Not exact match
            "test_secret.py",  # Contains 'secret' pattern
            "SECRET.TXT",  # Uppercase
            "my-api-key.json",  # Contains 'api-key' with hyphens
        ]

        for filename in edge_cases:
            result = detector.check_filename(filename)
            # Most should be detected via pattern matching
            if "secret" in filename.lower() or "api" in filename.lower():
                assert result is not None, f"Should detect pattern in: {filename}"
