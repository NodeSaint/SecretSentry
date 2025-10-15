"""Main scanner orchestrator that combines all detection methods."""

import os
from pathlib import Path
from typing import Optional
from datetime import datetime

from .entropy import EntropyDetector
from .patterns import PatternDetector
from .heuristics import HeuristicDetector
from ..utils.redaction import redact_finding_snippet


class Finding:
    """Represents a secret finding."""

    def __init__(
        self,
        file: str,
        line: int,
        column: int,
        token: str,
        rule: str,
        confidence: float,
        remediation: str,
        snippet: Optional[str] = None,
    ):
        """Initialize a finding."""
        self.file = file
        self.line = line
        self.column = column
        self.token = token
        self.rule = rule
        self.confidence = confidence
        self.remediation = remediation
        self.snippet = snippet or redact_finding_snippet(token, 0, len(token))
        self.found_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "rule": self.rule,
            "confidence": self.confidence,
            "remediation": self.remediation,
            "found_at": self.found_at,
        }

    def __repr__(self) -> str:
        return (
            f"Finding(file='{self.file}', line={self.line}, "
            f"rule='{self.rule}', confidence={self.confidence:.2f})"
        )


class Scanner:
    """Main scanner that orchestrates all detection methods."""

    def __init__(
        self,
        entropy_threshold: float = 4.0,
        min_token_length: int = 20,
        exclude_patterns: Optional[list[str]] = None,
    ):
        """
        Initialize scanner with detectors.

        Args:
            entropy_threshold: Threshold for entropy detection
            min_token_length: Minimum token length for entropy check
            exclude_patterns: Patterns to exclude from scanning
        """
        self.entropy_detector = EntropyDetector(entropy_threshold, min_token_length)
        self.pattern_detector = PatternDetector()
        self.heuristic_detector = HeuristicDetector()
        self.exclude_patterns = exclude_patterns or self.heuristic_detector.default_exclude_patterns()

    def scan_file(self, filepath: str) -> list[Finding]:
        """
        Scan a single file for secrets.

        Args:
            filepath: Path to file to scan

        Returns:
            List of Finding objects
        """
        findings = []

        # Check if file should be skipped
        if self.heuristic_detector.should_skip_file(filepath, self.exclude_patterns):
            return findings

        # Check if file is binary
        if self.heuristic_detector.is_binary_file(filepath):
            return findings

        # Check filename heuristics
        filename_finding = self.heuristic_detector.check_filename(filepath)
        if filename_finding:
            findings.append(
                Finding(
                    file=filepath,
                    line=0,
                    column=0,
                    token="",
                    rule=filename_finding["rule"],
                    confidence=filename_finding["confidence"],
                    remediation=filename_finding["remediation"],
                    snippet=filename_finding["reason"],
                )
            )

        # Read file content
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            # Skip files we can't read
            return findings

        # Scan with pattern detector
        pattern_findings = self.pattern_detector.scan(content)
        for pf in pattern_findings:
            # Get the actual line content for snippet
            lines = content.split('\n')
            line_idx = pf['line'] - 1
            if 0 <= line_idx < len(lines):
                line_content = lines[line_idx]
                snippet = redact_finding_snippet(
                    line_content,
                    pf['start'],
                    pf['end'],
                    context=30
                )
            else:
                snippet = redact_finding_snippet(pf['token'], 0, len(pf['token']))

            findings.append(
                Finding(
                    file=filepath,
                    line=pf['line'],
                    column=pf['start'],
                    token=pf['token'],
                    rule=pf['rule'],
                    confidence=pf['confidence'],
                    remediation=pf['remediation'],
                    snippet=snippet,
                )
            )

        # Scan with entropy detector (line by line to get accurate positions)
        lines = content.split('\n')
        for line_num, line_content in enumerate(lines, start=1):
            entropy_findings = self.entropy_detector.scan(line_content, line_num)
            for ef in entropy_findings:
                # Check if this overlaps with a pattern finding (avoid duplicates)
                is_duplicate = any(
                    f.line == line_num and
                    f.token == ef['token']
                    for f in findings
                )

                if not is_duplicate:
                    snippet = redact_finding_snippet(
                        line_content,
                        ef['start'],
                        ef['end'],
                        context=30
                    )

                    findings.append(
                        Finding(
                            file=filepath,
                            line=line_num,
                            column=ef['start'],
                            token=ef['token'],
                            rule=ef['rule'],
                            confidence=ef['confidence'],
                            remediation=ef['remediation'],
                            snippet=snippet,
                        )
                    )

        return findings

    def scan_directory(self, directory: str = ".") -> list[Finding]:
        """
        Scan a directory recursively for secrets.

        Args:
            directory: Directory path to scan (default current directory)

        Returns:
            List of Finding objects
        """
        all_findings = []
        dir_path = Path(directory).resolve()

        # Walk through directory
        for root, dirs, files in os.walk(dir_path):
            # Filter out excluded directories
            dirs[:] = [
                d for d in dirs
                if not self.heuristic_detector.should_skip_file(
                    os.path.join(root, d), self.exclude_patterns
                )
            ]

            for file in files:
                filepath = os.path.join(root, file)
                try:
                    findings = self.scan_file(filepath)
                    all_findings.extend(findings)
                except Exception as e:
                    # Log error but continue scanning
                    print(f"Error scanning {filepath}: {e}")
                    continue

        return all_findings

    def scan_files(self, filepaths: list[str]) -> list[Finding]:
        """
        Scan a list of files for secrets.

        Args:
            filepaths: List of file paths to scan

        Returns:
            List of Finding objects
        """
        all_findings = []

        for filepath in filepaths:
            try:
                findings = self.scan_file(filepath)
                all_findings.extend(findings)
            except Exception as e:
                print(f"Error scanning {filepath}: {e}")
                continue

        return all_findings

    def get_summary(self, findings: list[Finding]) -> dict:
        """
        Get summary statistics for findings.

        Args:
            findings: List of findings

        Returns:
            Dictionary with summary stats
        """
        if not findings:
            return {
                "total": 0,
                "by_rule": {},
                "by_confidence": {"high": 0, "medium": 0, "low": 0},
                "files_affected": 0,
            }

        # Count by rule
        by_rule = {}
        for finding in findings:
            by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1

        # Count by confidence level
        high_conf = sum(1 for f in findings if f.confidence >= 0.8)
        medium_conf = sum(1 for f in findings if 0.5 <= f.confidence < 0.8)
        low_conf = sum(1 for f in findings if f.confidence < 0.5)

        # Count unique files
        unique_files = len(set(f.file for f in findings))

        return {
            "total": len(findings),
            "by_rule": by_rule,
            "by_confidence": {
                "high": high_conf,
                "medium": medium_conf,
                "low": low_conf,
            },
            "files_affected": unique_files,
        }
