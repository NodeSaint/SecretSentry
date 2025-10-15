"""Unit tests for main scanner orchestrator."""

import pytest
import tempfile
import os
from pathlib import Path
from src.scanner.scanner import Scanner, Finding
from fixtures.test_secrets import FAKE_SECRETS, TEST_FILES, CLEAN_FILENAMES


class TestFinding:
    """Tests for Finding class."""

    def test_finding_initialization(self):
        """Test Finding initialization."""
        finding = Finding(
            file="test.py",
            line=10,
            column=5,
            token="secret123",
            rule="TEST_RULE",
            confidence=0.85,
            remediation="Test remediation"
        )

        assert finding.file == "test.py"
        assert finding.line == 10
        assert finding.column == 5
        assert finding.token == "secret123"
        assert finding.rule == "TEST_RULE"
        assert finding.confidence == 0.85
        assert finding.remediation == "Test remediation"
        assert finding.snippet is not None
        assert finding.found_at is not None

    def test_finding_with_custom_snippet(self):
        """Test Finding with custom snippet."""
        custom_snippet = "custom snippet here"
        finding = Finding(
            file="test.py",
            line=1,
            column=0,
            token="secret",
            rule="TEST",
            confidence=0.5,
            remediation="Fix it",
            snippet=custom_snippet
        )

        assert finding.snippet == custom_snippet

    def test_finding_to_dict(self):
        """Test Finding conversion to dictionary."""
        finding = Finding(
            file="test.py",
            line=10,
            column=5,
            token="secret123",
            rule="TEST_RULE",
            confidence=0.85,
            remediation="Test remediation"
        )

        result = finding.to_dict()

        assert isinstance(result, dict)
        assert result["file"] == "test.py"
        assert result["line"] == 10
        assert result["column"] == 5
        assert result["snippet"] is not None
        assert result["rule"] == "TEST_RULE"
        assert result["confidence"] == 0.85
        assert result["remediation"] == "Test remediation"
        assert "found_at" in result

    def test_finding_repr(self):
        """Test Finding string representation."""
        finding = Finding(
            file="test.py",
            line=10,
            column=5,
            token="secret123",
            rule="TEST_RULE",
            confidence=0.85,
            remediation="Test"
        )

        repr_str = repr(finding)

        assert "Finding" in repr_str
        assert "test.py" in repr_str
        assert "10" in repr_str
        assert "TEST_RULE" in repr_str
        assert "0.85" in repr_str


class TestScannerInitialization:
    """Tests for Scanner initialization."""

    def test_scanner_default_initialization(self):
        """Test Scanner with default parameters."""
        scanner = Scanner()

        assert scanner.entropy_detector is not None
        assert scanner.pattern_detector is not None
        assert scanner.heuristic_detector is not None
        assert scanner.exclude_patterns is not None
        assert len(scanner.exclude_patterns) > 0

    def test_scanner_custom_parameters(self):
        """Test Scanner with custom parameters."""
        custom_patterns = ["*.test.js", "tmp/**"]
        scanner = Scanner(
            entropy_threshold=5.0,
            min_token_length=30,
            exclude_patterns=custom_patterns
        )

        assert scanner.entropy_detector.threshold == 5.0
        assert scanner.entropy_detector.min_length == 30
        assert scanner.exclude_patterns == custom_patterns

    def test_scanner_detectors_initialized(self):
        """Test that all detectors are properly initialized."""
        scanner = Scanner()

        # Check entropy detector
        assert hasattr(scanner.entropy_detector, 'scan')
        assert hasattr(scanner.entropy_detector, 'threshold')

        # Check pattern detector
        assert hasattr(scanner.pattern_detector, 'scan')
        assert len(scanner.pattern_detector.compiled_patterns) > 0

        # Check heuristic detector
        assert hasattr(scanner.heuristic_detector, 'check_filename')
        assert hasattr(scanner.heuristic_detector, 'is_binary_file')


class TestScanFile:
    """Tests for scan_file method."""

    def test_scan_file_with_secrets(self):
        """Test scanning file containing secrets."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write(TEST_FILES['python_with_secrets'])
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            assert len(findings) > 0
            assert all(isinstance(f, Finding) for f in findings)

            # Should detect AWS keys
            rules = [f.rule for f in findings]
            assert "AWS_ACCESS_KEY" in rules

        finally:
            os.unlink(temp_path)

    def test_scan_file_clean(self):
        """Test scanning file with no secrets."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write(TEST_FILES['clean_file'])
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Clean file should have no findings (or very few low confidence)
            high_conf_findings = [f for f in findings if f.confidence > 0.7]
            assert len(high_conf_findings) == 0

        finally:
            os.unlink(temp_path)

    def test_scan_file_suspicious_filename(self):
        """Test scanning file with suspicious filename."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.env', prefix='test_'
        ) as f:
            f.write("# Empty env file\n")
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Should have finding for suspicious filename
            filename_findings = [
                f for f in findings
                if f.rule in ["SUSPICIOUS_FILENAME", "SUSPICIOUS_EXTENSION", "SUSPICIOUS_PATTERN"]
            ]
            assert len(filename_findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_file_binary_skipped(self):
        """Test that binary files are skipped."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b'\x00\x01\x02\x03\x04\x05')
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)
            assert findings == []

        finally:
            os.unlink(temp_path)

    def test_scan_file_excluded_pattern(self):
        """Test that files matching exclude patterns are skipped."""
        scanner = Scanner(exclude_patterns=["*.test.py"])

        with tempfile.NamedTemporaryFile(
            mode='w', delete=False, suffix='.test.py'
        ) as f:
            f.write(f"secret = {FAKE_SECRETS['aws_access_key']}")
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)
            assert findings == []

        finally:
            os.unlink(temp_path)

    def test_scan_file_nonexistent(self):
        """Test scanning nonexistent file."""
        scanner = Scanner()
        findings = scanner.scan_file("/nonexistent/file.txt")
        assert findings == []

    def test_scan_file_pattern_detection(self):
        """Test that pattern detector finds secrets."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.js') as f:
            f.write(TEST_FILES['javascript_with_secrets'])
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Should detect OpenAI and Stripe keys
            rules = [f.rule for f in findings]
            assert "OPENAI_API_KEY" in rules
            assert "STRIPE_API_KEY" in rules

        finally:
            os.unlink(temp_path)

    def test_scan_file_entropy_detection(self):
        """Test that entropy detector finds high entropy strings."""
        scanner = Scanner(entropy_threshold=4.0, min_token_length=20)

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # Write high entropy string that doesn't match patterns
            high_entropy = FAKE_SECRETS['high_entropy_1']
            f.write(f"data = '{high_entropy}'\n")
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Should detect high entropy
            entropy_findings = [f for f in findings if f.rule == "HIGH_ENTROPY"]
            assert len(entropy_findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_file_duplicate_detection(self):
        """Test that duplicates are filtered (pattern + entropy match same secret)."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # OpenAI key should match both pattern and entropy
            f.write(f"key = {FAKE_SECRETS['openai_key']}\n")
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Count findings for the same token on same line
            key_findings = [
                f for f in findings
                if FAKE_SECRETS['openai_key'] in f.token
            ]

            # Should not have duplicate findings for the same secret
            lines = [f.line for f in key_findings]
            assert len(lines) == len(set(lines)), "Should not have duplicates on same line"

        finally:
            os.unlink(temp_path)

    def test_scan_file_multiline_secrets(self):
        """Test scanning file with multi-line secrets."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(FAKE_SECRETS['rsa_private_key'])
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)

            # Should detect private key
            key_findings = [f for f in findings if f.rule == "PRIVATE_KEY"]
            assert len(key_findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_file_unicode_content(self):
        """Test scanning file with unicode content."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(
            mode='w', delete=False, encoding='utf-8'
        ) as f:
            f.write("# Comment with unicode: 你好\n")
            f.write(f"secret = {FAKE_SECRETS['aws_access_key']}\n")
            temp_path = f.name

        try:
            findings = scanner.scan_file(temp_path)
            # Should still detect the secret
            assert len(findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_file_various_formats(self):
        """Test scanning various file formats."""
        scanner = Scanner()

        test_cases = [
            ('config.json', TEST_FILES['json_config']),
            ('config.yaml', TEST_FILES['yaml_config']),
            ('.env', TEST_FILES['env_file']),
        ]

        for filename, content in test_cases:
            with tempfile.NamedTemporaryFile(
                mode='w', delete=False, suffix=filename
            ) as f:
                f.write(content)
                temp_path = f.name

            try:
                findings = scanner.scan_file(temp_path)
                assert len(findings) > 0, f"Should find secrets in {filename}"

            finally:
                os.unlink(temp_path)


class TestScanDirectory:
    """Tests for scan_directory method."""

    def test_scan_directory_empty(self):
        """Test scanning empty directory."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            findings = scanner.scan_directory(temp_dir)
            assert findings == []

    def test_scan_directory_with_files(self):
        """Test scanning directory with multiple files."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            file1 = Path(temp_dir) / "file1.py"
            file1.write_text(f"key = {FAKE_SECRETS['aws_access_key']}\n")

            file2 = Path(temp_dir) / "file2.js"
            file2.write_text(f"const key = '{FAKE_SECRETS['github_pat']}';\n")

            findings = scanner.scan_directory(temp_dir)

            assert len(findings) > 0
            files = [f.file for f in findings]
            assert any("file1.py" in f for f in files)
            assert any("file2.js" in f for f in files)

    def test_scan_directory_nested(self):
        """Test scanning nested directory structure."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create nested structure
            subdir = Path(temp_dir) / "subdir"
            subdir.mkdir()

            file1 = Path(temp_dir) / "root.py"
            file1.write_text(f"key1 = {FAKE_SECRETS['aws_access_key']}\n")

            file2 = subdir / "nested.py"
            file2.write_text(f"key2 = {FAKE_SECRETS['github_pat']}\n")

            findings = scanner.scan_directory(temp_dir)

            assert len(findings) > 0
            files = [f.file for f in findings]
            assert any("root.py" in f for f in files)
            assert any("nested.py" in f for f in files)

    def test_scan_directory_excludes_patterns(self):
        """Test that excluded directories are skipped."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create node_modules (should be excluded)
            node_modules = Path(temp_dir) / "node_modules"
            node_modules.mkdir()

            excluded_file = node_modules / "package.json"
            excluded_file.write_text(f"secret: {FAKE_SECRETS['aws_access_key']}")

            # Create normal file
            normal_file = Path(temp_dir) / "app.py"
            normal_file.write_text("print('hello')")

            findings = scanner.scan_directory(temp_dir)

            # Should not scan node_modules
            files = [f.file for f in findings]
            assert not any("node_modules" in f for f in files)

    def test_scan_directory_mixed_content(self):
        """Test scanning directory with mix of clean and secret files."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Clean file
            clean = Path(temp_dir) / "clean.py"
            clean.write_text(TEST_FILES['clean_file'])

            # File with secrets
            secret = Path(temp_dir) / "secrets.py"
            secret.write_text(TEST_FILES['python_with_secrets'])

            findings = scanner.scan_directory(temp_dir)

            # Should only find secrets in secrets.py
            files_with_findings = set(f.file for f in findings)
            assert any("secrets.py" in f for f in files_with_findings)

    def test_scan_directory_handles_errors(self):
        """Test that scanner continues on errors."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a normal file
            normal = Path(temp_dir) / "normal.py"
            normal.write_text(f"key = {FAKE_SECRETS['aws_access_key']}")

            # Scan should complete despite any issues
            findings = scanner.scan_directory(temp_dir)
            assert len(findings) > 0


class TestScanFiles:
    """Tests for scan_files method."""

    def test_scan_files_single(self):
        """Test scanning single file from list."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(f"key = {FAKE_SECRETS['aws_access_key']}")
            temp_path = f.name

        try:
            findings = scanner.scan_files([temp_path])
            assert len(findings) > 0

        finally:
            os.unlink(temp_path)

    def test_scan_files_multiple(self):
        """Test scanning multiple files from list."""
        scanner = Scanner()

        temp_files = []
        try:
            for i in range(3):
                f = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py')
                f.write(f"key{i} = {FAKE_SECRETS['aws_access_key']}")
                f.close()
                temp_files.append(f.name)

            findings = scanner.scan_files(temp_files)

            # Should find secrets in all files
            assert len(findings) > 0
            files = set(f.file for f in findings)
            assert len(files) >= 3

        finally:
            for path in temp_files:
                os.unlink(path)

    def test_scan_files_empty_list(self):
        """Test scanning empty file list."""
        scanner = Scanner()
        findings = scanner.scan_files([])
        assert findings == []

    def test_scan_files_nonexistent(self):
        """Test scanning list with nonexistent file."""
        scanner = Scanner()
        findings = scanner.scan_files(["/nonexistent/file.txt"])
        assert findings == []

    def test_scan_files_mixed(self):
        """Test scanning list with mix of valid and invalid files."""
        scanner = Scanner()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(f"key = {FAKE_SECRETS['aws_access_key']}")
            valid_path = f.name

        try:
            filepaths = [valid_path, "/nonexistent/file.txt"]
            findings = scanner.scan_files(filepaths)

            # Should still get findings from valid file
            assert len(findings) > 0

        finally:
            os.unlink(valid_path)


class TestGetSummary:
    """Tests for get_summary method."""

    def test_get_summary_empty(self):
        """Test summary with no findings."""
        scanner = Scanner()
        summary = scanner.get_summary([])

        assert summary["total"] == 0
        assert summary["by_rule"] == {}
        assert summary["by_confidence"]["high"] == 0
        assert summary["by_confidence"]["medium"] == 0
        assert summary["by_confidence"]["low"] == 0
        assert summary["files_affected"] == 0

    def test_get_summary_single_finding(self):
        """Test summary with single finding."""
        scanner = Scanner()

        finding = Finding(
            file="test.py",
            line=1,
            column=0,
            token="secret",
            rule="TEST_RULE",
            confidence=0.9,
            remediation="Fix it"
        )

        summary = scanner.get_summary([finding])

        assert summary["total"] == 1
        assert summary["by_rule"]["TEST_RULE"] == 1
        assert summary["by_confidence"]["high"] == 1
        assert summary["files_affected"] == 1

    def test_get_summary_multiple_findings(self):
        """Test summary with multiple findings."""
        scanner = Scanner()

        findings = [
            Finding("file1.py", 1, 0, "s1", "RULE1", 0.95, "Fix"),
            Finding("file1.py", 2, 0, "s2", "RULE2", 0.75, "Fix"),
            Finding("file2.py", 1, 0, "s3", "RULE1", 0.55, "Fix"),
            Finding("file2.py", 2, 0, "s4", "RULE3", 0.30, "Fix"),
        ]

        summary = scanner.get_summary(findings)

        assert summary["total"] == 4
        assert summary["by_rule"]["RULE1"] == 2
        assert summary["by_rule"]["RULE2"] == 1
        assert summary["by_rule"]["RULE3"] == 1
        assert summary["files_affected"] == 2

    def test_get_summary_confidence_levels(self):
        """Test summary confidence level categorization."""
        scanner = Scanner()

        findings = [
            Finding("f1", 1, 0, "s1", "R1", 0.95, "Fix"),  # High
            Finding("f2", 1, 0, "s2", "R2", 0.80, "Fix"),  # High
            Finding("f3", 1, 0, "s3", "R3", 0.75, "Fix"),  # Medium
            Finding("f4", 1, 0, "s4", "R4", 0.50, "Fix"),  # Medium
            Finding("f5", 1, 0, "s5", "R5", 0.30, "Fix"),  # Low
        ]

        summary = scanner.get_summary(findings)

        assert summary["by_confidence"]["high"] == 2
        assert summary["by_confidence"]["medium"] == 2
        assert summary["by_confidence"]["low"] == 1

    def test_get_summary_unique_files(self):
        """Test that summary counts unique files correctly."""
        scanner = Scanner()

        findings = [
            Finding("file1.py", 1, 0, "s1", "R1", 0.9, "Fix"),
            Finding("file1.py", 2, 0, "s2", "R1", 0.9, "Fix"),
            Finding("file1.py", 3, 0, "s3", "R1", 0.9, "Fix"),
            Finding("file2.py", 1, 0, "s4", "R1", 0.9, "Fix"),
        ]

        summary = scanner.get_summary(findings)

        assert summary["total"] == 4
        assert summary["files_affected"] == 2


class TestScannerIntegration:
    """Integration tests for scanner."""

    def test_scan_realistic_project(self):
        """Test scanning realistic project structure."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create realistic structure
            src_dir = Path(temp_dir) / "src"
            src_dir.mkdir()

            # Clean source file
            (src_dir / "main.py").write_text(TEST_FILES['clean_file'])

            # Config with secrets (bad)
            (Path(temp_dir) / "config.py").write_text(
                TEST_FILES['python_with_secrets']
            )

            # .env file (suspicious)
            (Path(temp_dir) / ".env").write_text(TEST_FILES['env_file'])

            # node_modules (should be excluded)
            node_modules = Path(temp_dir) / "node_modules"
            node_modules.mkdir()
            (node_modules / "package.json").write_text(
                f"secret: {FAKE_SECRETS['aws_access_key']}"
            )

            findings = scanner.scan_directory(temp_dir)

            # Should find secrets in config.py and .env
            files = [f.file for f in findings]
            assert any("config.py" in f for f in files)
            assert any(".env" in f for f in files)

            # Should not scan node_modules
            assert not any("node_modules" in f for f in files)

    def test_scan_end_to_end(self):
        """Test complete scan workflow."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file with multiple types of secrets
            test_file = Path(temp_dir) / "secrets.py"
            test_file.write_text(f"""
# Configuration file
AWS_KEY = "{FAKE_SECRETS['aws_access_key']}"
GITHUB_TOKEN = "{FAKE_SECRETS['github_pat']}"
OPENAI_KEY = "{FAKE_SECRETS['openai_key']}"
            """)

            # Scan
            findings = scanner.scan_file(str(test_file))

            # Get summary
            summary = scanner.get_summary(findings)

            # Verify results
            assert len(findings) > 0
            assert summary["total"] > 0
            assert summary["files_affected"] == 1

            # Check that different rule types were detected
            rules = set(f.rule for f in findings)
            assert len(rules) > 1  # Multiple different secret types
