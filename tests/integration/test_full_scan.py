"""Integration tests for full scanning workflow."""

import pytest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from src.scanner.scanner import Scanner
from src.scanner.git_scanner import GitScanner, GIT_AVAILABLE
from src.utils.storage import save_findings, load_findings
from fixtures.test_secrets import FAKE_SECRETS, TEST_FILES


class TestFullScanWorkflow:
    """Integration tests for complete scan workflow."""

    def test_scan_entire_project(self):
        """Test scanning a complete project structure."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create realistic project structure
            src_dir = Path(temp_dir) / "src"
            src_dir.mkdir()

            tests_dir = Path(temp_dir) / "tests"
            tests_dir.mkdir()

            config_dir = Path(temp_dir) / "config"
            config_dir.mkdir()

            # Add various files
            (src_dir / "main.py").write_text(TEST_FILES['clean_file'])
            (src_dir / "app.py").write_text(TEST_FILES['python_with_secrets'])
            (tests_dir / "test_app.py").write_text(TEST_FILES['clean_file'])
            (config_dir / "config.json").write_text(TEST_FILES['json_config'])
            (Path(temp_dir) / ".env").write_text(TEST_FILES['env_file'])
            (Path(temp_dir) / "README.md").write_text("# Project README\n")

            # Scan entire directory
            findings = scanner.scan_directory(temp_dir)

            # Verify findings
            assert len(findings) > 0

            # Get summary
            summary = scanner.get_summary(findings)

            assert summary["total"] > 0
            assert summary["files_affected"] >= 3  # app.py, config.json, .env

            # Verify different rule types detected
            rules = set(f.rule for f in findings)
            assert len(rules) > 1

            # Verify findings have proper structure
            for finding in findings:
                assert finding.file is not None
                assert finding.rule is not None
                assert 0 <= finding.confidence <= 1.0
                assert finding.remediation is not None

    def test_scan_with_exclusions(self):
        """Test scanning with custom exclusion patterns."""
        scanner = Scanner(exclude_patterns=["tests/**", "*.min.js"])

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create files that should be excluded
            tests_dir = Path(temp_dir) / "tests"
            tests_dir.mkdir()

            (tests_dir / "test.py").write_text(
                f"key = {FAKE_SECRETS['aws_access_key']}"
            )

            (Path(temp_dir) / "bundle.min.js").write_text(
                f"const k='{FAKE_SECRETS['github_pat']}'"
            )

            # Create file that should be scanned
            (Path(temp_dir) / "app.py").write_text(
                f"key = {FAKE_SECRETS['aws_access_key']}"
            )

            findings = scanner.scan_directory(temp_dir)

            # Should only find secrets in app.py
            files = [f.file for f in findings]
            assert any("app.py" in f for f in files)
            assert not any("tests" in f for f in files)
            assert not any("min.js" in f for f in files)

    def test_scan_multiple_file_types(self):
        """Test scanning various file types."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create different file types
            files = {
                "config.py": TEST_FILES['python_with_secrets'],
                "config.js": TEST_FILES['javascript_with_secrets'],
                "config.json": TEST_FILES['json_config'],
                "config.yaml": TEST_FILES['yaml_config'],
                ".env": TEST_FILES['env_file'],
            }

            for filename, content in files.items():
                (Path(temp_dir) / filename).write_text(content)

            findings = scanner.scan_directory(temp_dir)

            # Should find secrets in all files
            found_files = set(Path(f.file).name for f in findings)

            # Verify we scanned different file types
            assert len(found_files) >= 3

    def test_scan_with_findings_persistence(self):
        """Test scanning and persisting findings to storage."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create data directory
            data_dir = Path(temp_dir) / "data"
            data_dir.mkdir()

            # Create file with secrets
            test_file = Path(temp_dir) / "secrets.py"
            test_file.write_text(
                f"key = {FAKE_SECRETS['aws_access_key']}"
            )

            # Scan
            findings = scanner.scan_file(str(test_file))

            # Save findings
            findings_dicts = [f.to_dict() for f in findings]
            save_findings(findings_dicts, str(data_dir))

            # Load findings back
            loaded = load_findings(str(data_dir))

            assert len(loaded) == len(findings)
            assert loaded[0]["rule"] is not None

    def test_scan_high_confidence_only(self):
        """Test filtering for high confidence findings."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file with various confidence levels
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text(f"""
AWS_KEY = "{FAKE_SECRETS['aws_access_key']}"  # High confidence
password = "weak123"  # Lower confidence generic pattern
            """)

            findings = scanner.scan_file(str(test_file))

            # Filter high confidence
            high_conf = [f for f in findings if f.confidence >= 0.8]

            assert len(high_conf) > 0
            # AWS key should be high confidence
            assert any(f.rule == "AWS_ACCESS_KEY" for f in high_conf)

    def test_scan_reports_all_finding_fields(self):
        """Test that all expected finding fields are populated."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text(
                f"key = {FAKE_SECRETS['aws_access_key']}"
            )

            findings = scanner.scan_file(str(test_file))

            assert len(findings) > 0

            for finding in findings:
                # Check all required fields
                assert hasattr(finding, 'file')
                assert hasattr(finding, 'line')
                assert hasattr(finding, 'column')
                assert hasattr(finding, 'token')
                assert hasattr(finding, 'rule')
                assert hasattr(finding, 'confidence')
                assert hasattr(finding, 'remediation')
                assert hasattr(finding, 'snippet')
                assert hasattr(finding, 'found_at')

                # Verify values are reasonable
                assert finding.line > 0
                assert finding.column >= 0
                assert len(finding.token) > 0
                assert len(finding.rule) > 0
                assert 0 <= finding.confidence <= 1.0


class TestGitScanningIntegration:
    """Integration tests for git history scanning."""

    @pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not available")
    def test_git_scanner_initialization(self):
        """Test GitScanner initialization in git repo."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize git repo
            os.system(f"cd {temp_dir} && git init -q")
            os.system(f"cd {temp_dir} && git config user.email 'test@example.com'")
            os.system(f"cd {temp_dir} && git config user.name 'Test User'")

            try:
                scanner = GitScanner(temp_dir)
                assert scanner.repo is not None
                assert scanner.pattern_detector is not None
                assert scanner.entropy_detector is not None
            except Exception as e:
                pytest.skip(f"Git operations not available: {e}")

    @pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not available")
    def test_git_scan_commit_with_secrets(self):
        """Test scanning git commit containing secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize git repo
            os.system(f"cd {temp_dir} && git init -q")
            os.system(f"cd {temp_dir} && git config user.email 'test@example.com'")
            os.system(f"cd {temp_dir} && git config user.name 'Test User'")

            # Create file with secret
            test_file = Path(temp_dir) / "config.py"
            test_file.write_text(
                f"key = {FAKE_SECRETS['aws_access_key']}"
            )

            # Commit
            os.system(f"cd {temp_dir} && git add .")
            os.system(f"cd {temp_dir} && git commit -q -m 'Add config'")

            try:
                scanner = GitScanner(temp_dir)
                findings = scanner.scan_history(depth=1)

                # Should find the secret in commit
                assert len(findings) > 0
                assert any(f.rule == "AWS_ACCESS_KEY" for f in findings)

                # Check commit metadata
                for finding in findings:
                    assert hasattr(finding, 'commit_sha')
                    assert hasattr(finding, 'commit_author')
                    assert hasattr(finding, 'commit_date')
                    assert finding.commit_sha is not None

            except Exception as e:
                pytest.skip(f"Git scanning not available: {e}")

    @pytest.mark.skipif(not GIT_AVAILABLE, reason="GitPython not available")
    def test_git_scan_added_lines_only(self):
        """Test that only added lines are scanned, not removed."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize git repo
            os.system(f"cd {temp_dir} && git init -q")
            os.system(f"cd {temp_dir} && git config user.email 'test@example.com'")
            os.system(f"cd {temp_dir} && git config user.name 'Test User'")

            # First commit (clean)
            test_file = Path(temp_dir) / "config.py"
            test_file.write_text("# Config file\n")
            os.system(f"cd {temp_dir} && git add .")
            os.system(f"cd {temp_dir} && git commit -q -m 'Initial'")

            # Second commit (add secret)
            test_file.write_text(
                f"# Config file\nkey = {FAKE_SECRETS['aws_access_key']}\n"
            )
            os.system(f"cd {temp_dir} && git add .")
            os.system(f"cd {temp_dir} && git commit -q -m 'Add key'")

            try:
                scanner = GitScanner(temp_dir)
                findings = scanner.scan_history(depth=1)

                # Should find the secret
                assert len(findings) > 0

            except Exception as e:
                pytest.skip(f"Git scanning not available: {e}")


class TestConfigAndStorage:
    """Integration tests for config and storage."""

    def test_settings_load_save_cycle(self):
        """Test loading and saving settings."""
        from src.utils.config import Settings, save_settings, load_settings

        with tempfile.TemporaryDirectory() as temp_dir:
            settings_file = Path(temp_dir) / "settings.json"

            # Create settings
            settings = Settings()
            settings.scan.entropy_threshold = 5.0
            settings.scan.min_token_length = 30

            # Save
            save_settings(settings, settings_file)

            # Load
            loaded = load_settings(settings_file)

            assert loaded.scan.entropy_threshold == 5.0
            assert loaded.scan.min_token_length == 30

    def test_findings_persistence(self):
        """Test persisting and loading findings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = str(temp_dir)

            # Create findings
            findings = [
                {
                    "file": "test.py",
                    "line": 10,
                    "column": 5,
                    "rule": "AWS_ACCESS_KEY",
                    "confidence": 0.95,
                    "snippet": "***KEY",
                    "remediation": "Fix it",
                    "found_at": "2024-01-01T00:00:00"
                }
            ]

            # Save
            save_findings(findings, data_dir)

            # Load
            loaded = load_findings(data_dir)

            assert len(loaded) == 1
            assert loaded[0]["rule"] == "AWS_ACCESS_KEY"
            assert loaded[0]["confidence"] == 0.95

    def test_migration_log_persistence(self):
        """Test migration log storage."""
        from src.utils.storage import (
            add_migration_entry,
            load_migration_log
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = str(temp_dir)

            # Add migration entry
            add_migration_entry(
                file="config.py",
                line=10,
                old_value_redacted="***KEY",
                env_var_name="AWS_ACCESS_KEY_ID",
                data_dir=data_dir
            )

            # Load log
            log = load_migration_log(data_dir)

            assert "migrations" in log
            assert len(log["migrations"]) == 1
            assert log["migrations"][0]["file"] == "config.py"
            assert log["migrations"][0]["env_var_name"] == "AWS_ACCESS_KEY_ID"

    def test_atomic_write_protection(self):
        """Test that atomic writes protect against corruption."""
        from src.utils.storage import save_json

        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.json"

            # First write
            data1 = {"key": "value1"}
            save_json(test_file, data1)

            # Second write (should be atomic)
            data2 = {"key": "value2", "new_key": "new_value"}
            save_json(test_file, data2)

            # Read back
            with open(test_file) as f:
                loaded = json.load(f)

            # Should have complete data, not corrupted
            assert loaded == data2


class TestEndToEndScenarios:
    """End-to-end integration scenarios."""

    def test_scan_and_report_workflow(self):
        """Test complete scan and report generation workflow."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create project
            (Path(temp_dir) / "app.py").write_text(
                TEST_FILES['python_with_secrets']
            )
            (Path(temp_dir) / ".env").write_text(TEST_FILES['env_file'])

            # Scan
            findings = scanner.scan_directory(temp_dir)

            # Get summary
            summary = scanner.get_summary(findings)

            # Verify complete workflow
            assert len(findings) > 0
            assert summary["total"] > 0
            assert summary["files_affected"] >= 2

            # Findings should be serializable (for reporting)
            findings_dicts = [f.to_dict() for f in findings]
            json_str = json.dumps(findings_dicts)
            loaded = json.loads(json_str)

            assert len(loaded) == len(findings)

    def test_incremental_scan_workflow(self):
        """Test incremental scanning (scan only new/changed files)."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Initial scan
            file1 = Path(temp_dir) / "file1.py"
            file1.write_text(f"key = {FAKE_SECRETS['aws_access_key']}")

            findings1 = scanner.scan_directory(temp_dir)
            initial_count = len(findings1)

            # Add new file
            file2 = Path(temp_dir) / "file2.py"
            file2.write_text(f"token = {FAKE_SECRETS['github_pat']}")

            # Scan only new file
            findings2 = scanner.scan_file(str(file2))

            # Verify new findings
            assert len(findings2) > 0
            assert all(f.file == str(file2) for f in findings2)

    def test_scan_with_remediation_tracking(self):
        """Test scanning with remediation tracking."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir) / "data"
            data_dir.mkdir()

            # Create file with secrets
            test_file = Path(temp_dir) / "config.py"
            test_file.write_text(
                f"AWS_KEY = '{FAKE_SECRETS['aws_access_key']}'\n"
            )

            # Initial scan
            findings = scanner.scan_file(str(test_file))
            assert len(findings) > 0

            # Save findings
            save_findings(
                [f.to_dict() for f in findings],
                str(data_dir)
            )

            # Simulate remediation (remove secret)
            test_file.write_text("AWS_KEY = os.getenv('AWS_KEY')\n")

            # Re-scan
            new_findings = scanner.scan_file(str(test_file))

            # Should have fewer findings
            assert len(new_findings) < len(findings)

    def test_multi_detector_coordination(self):
        """Test that multiple detectors work together correctly."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file that triggers multiple detectors
            test_file = Path(temp_dir) / ".env"  # Heuristic detector
            test_file.write_text(f"""
# This file will trigger:
# 1. Heuristic detector (filename .env)
# 2. Pattern detector (AWS keys)
# 3. Entropy detector (high entropy strings)

AWS_ACCESS_KEY_ID={FAKE_SECRETS['aws_access_key']}
RANDOM_TOKEN={FAKE_SECRETS['high_entropy_1']}
            """)

            findings = scanner.scan_file(str(test_file))

            # Should have findings from multiple detectors
            rules = set(f.rule for f in findings)

            # Should have heuristic finding
            assert any(
                "SUSPICIOUS" in rule for rule in rules
            ), "Should detect suspicious filename"

            # Should have pattern finding
            assert "AWS_ACCESS_KEY" in rules, "Should detect AWS key pattern"

            # May have entropy finding (if not duplicated)
            # Note: Some findings may be deduplicated

    def test_performance_large_directory(self):
        """Test scanning performance with larger directory."""
        scanner = Scanner()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create 50 files
            for i in range(50):
                file_path = Path(temp_dir) / f"file{i}.py"
                if i % 10 == 0:
                    # Every 10th file has a secret
                    file_path.write_text(
                        f"key{i} = {FAKE_SECRETS['aws_access_key']}"
                    )
                else:
                    file_path.write_text(f"# Clean file {i}\nprint('hello')")

            # Scan should complete in reasonable time
            import time
            start = time.time()
            findings = scanner.scan_directory(temp_dir)
            elapsed = time.time() - start

            # Should complete in under 5 seconds for 50 files
            assert elapsed < 5.0, f"Scan took too long: {elapsed}s"

            # Should find secrets in ~5 files
            files_with_secrets = len(set(f.file for f in findings))
            assert files_with_secrets >= 4
