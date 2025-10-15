"""Git history scanner for detecting secrets in commit history."""

import os
from typing import Optional, List
from datetime import datetime

try:
    from git import Repo, InvalidGitRepositoryError, GitCommandError
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False
    Repo = None
    InvalidGitRepositoryError = Exception
    GitCommandError = Exception

from .scanner import Finding
from .entropy import EntropyDetector
from .patterns import PatternDetector
from ..utils.redaction import redact_finding_snippet


class CommitFinding(Finding):
    """Finding from git commit history."""

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
        commit_sha: Optional[str] = None,
        commit_author: Optional[str] = None,
        commit_date: Optional[str] = None,
        commit_message: Optional[str] = None,
    ):
        """Initialize commit finding with git metadata."""
        super().__init__(
            file, line, column, token, rule, confidence, remediation, snippet
        )
        self.commit_sha = commit_sha
        self.commit_author = commit_author
        self.commit_date = commit_date
        self.commit_message = commit_message

    def to_dict(self) -> dict:
        """Convert to dictionary with git metadata."""
        data = super().to_dict()
        data.update({
            "commit_sha": self.commit_sha,
            "commit_author": self.commit_author,
            "commit_date": self.commit_date,
            "commit_message": self.commit_message,
        })
        return data


class GitScanner:
    """Scanner for git commit history."""

    def __init__(
        self,
        repo_path: str = ".",
        entropy_threshold: float = 4.0,
        min_token_length: int = 20,
    ):
        """
        Initialize git scanner.

        Args:
            repo_path: Path to git repository (default current directory)
            entropy_threshold: Entropy threshold for detection
            min_token_length: Minimum token length for entropy check

        Raises:
            RuntimeError: If GitPython is not installed
            InvalidGitRepositoryError: If path is not a git repository
        """
        if not GIT_AVAILABLE:
            raise RuntimeError(
                "GitPython is required for history scanning. "
                "Install with: pip install GitPython"
            )

        self.repo_path = repo_path
        try:
            self.repo = Repo(repo_path)
        except InvalidGitRepositoryError:
            raise InvalidGitRepositoryError(
                f"'{repo_path}' is not a git repository. "
                "Initialize with: git init"
            )

        self.entropy_detector = EntropyDetector(entropy_threshold, min_token_length)
        self.pattern_detector = PatternDetector()

    def scan_commit(self, commit) -> List[CommitFinding]:
        """
        Scan a single commit for secrets.

        Args:
            commit: GitPython commit object

        Returns:
            List of CommitFinding objects
        """
        findings = []

        # Get commit metadata
        commit_sha = commit.hexsha[:8]  # Short SHA
        commit_author = f"{commit.author.name} <{commit.author.email}>"
        commit_date = datetime.fromtimestamp(commit.committed_date).isoformat()
        commit_message = commit.message.strip().split('\n')[0]  # First line only

        # Get diff for this commit
        try:
            # Compare with parent (or empty tree for first commit)
            if commit.parents:
                parent = commit.parents[0]
                diffs = parent.diff(commit, create_patch=True)
            else:
                # First commit - compare with empty tree
                diffs = commit.diff(None, create_patch=True)

            for diff in diffs:
                # Skip deleted files
                if diff.deleted_file:
                    continue

                # Get the file path
                filepath = diff.b_path if diff.b_path else diff.a_path

                # Get the diff content (added lines only)
                if diff.diff:
                    diff_text = diff.diff.decode('utf-8', errors='ignore')

                    # Parse diff to extract added lines
                    added_lines = self._extract_added_lines(diff_text)

                    for line_num, line_content in added_lines:
                        # Scan with pattern detector
                        pattern_findings = self.pattern_detector.scan_line(
                            line_content, line_num
                        )

                        for pf in pattern_findings:
                            snippet = redact_finding_snippet(
                                line_content,
                                pf['start'],
                                pf['end'],
                                context=30
                            )

                            findings.append(
                                CommitFinding(
                                    file=filepath,
                                    line=line_num,
                                    column=pf['start'],
                                    token=pf['token'],
                                    rule=pf['rule'],
                                    confidence=pf['confidence'],
                                    remediation=pf['remediation'],
                                    snippet=snippet,
                                    commit_sha=commit_sha,
                                    commit_author=commit_author,
                                    commit_date=commit_date,
                                    commit_message=commit_message,
                                )
                            )

                        # Scan with entropy detector
                        entropy_findings = self.entropy_detector.scan(
                            line_content, line_num
                        )

                        for ef in entropy_findings:
                            # Avoid duplicates with pattern findings
                            is_duplicate = any(
                                f.line == line_num and f.token == ef['token']
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
                                    CommitFinding(
                                        file=filepath,
                                        line=line_num,
                                        column=ef['start'],
                                        token=ef['token'],
                                        rule=ef['rule'],
                                        confidence=ef['confidence'],
                                        remediation=ef['remediation'],
                                        snippet=snippet,
                                        commit_sha=commit_sha,
                                        commit_author=commit_author,
                                        commit_date=commit_date,
                                        commit_message=commit_message,
                                    )
                                )

        except Exception as e:
            print(f"Error scanning commit {commit_sha}: {e}")

        return findings

    def _extract_added_lines(self, diff_text: str) -> List[tuple[int, str]]:
        """
        Extract added lines from git diff output.

        Args:
            diff_text: Git diff output

        Returns:
            List of (line_number, content) tuples for added lines
        """
        added_lines = []
        current_line = 0

        for line in diff_text.split('\n'):
            # Track line numbers from diff headers
            if line.startswith('@@'):
                # Parse line number from @@ -1,2 +3,4 @@
                try:
                    parts = line.split('+')[1].split('@@')[0].strip()
                    current_line = int(parts.split(',')[0])
                except (IndexError, ValueError):
                    current_line = 0
                continue

            # Skip diff headers
            if line.startswith('---') or line.startswith('+++'):
                continue
            if line.startswith('diff --git'):
                continue

            # Added line
            if line.startswith('+') and not line.startswith('+++'):
                content = line[1:]  # Remove the '+' prefix
                added_lines.append((current_line, content))
                current_line += 1
            # Context or removed line
            elif not line.startswith('-'):
                current_line += 1

        return added_lines

    def scan_history(
        self,
        depth: int = 100,
        branch: Optional[str] = None
    ) -> List[CommitFinding]:
        """
        Scan git commit history for secrets.

        Args:
            depth: Number of commits to scan (default 100)
            branch: Branch name to scan (default current branch)

        Returns:
            List of CommitFinding objects
        """
        all_findings = []

        try:
            # Get commits
            if branch:
                commits = list(self.repo.iter_commits(branch, max_count=depth))
            else:
                commits = list(self.repo.iter_commits(max_count=depth))

            print(f"Scanning {len(commits)} commits...")

            for i, commit in enumerate(commits, 1):
                if i % 10 == 0:
                    print(f"Progress: {i}/{len(commits)} commits scanned...")

                findings = self.scan_commit(commit)
                all_findings.extend(findings)

            print(f"Completed: {len(commits)} commits scanned.")

        except GitCommandError as e:
            print(f"Git command error: {e}")
        except Exception as e:
            print(f"Error scanning history: {e}")

        return all_findings

    def scan_range(
        self,
        start_ref: str,
        end_ref: str = "HEAD"
    ) -> List[CommitFinding]:
        """
        Scan a range of commits.

        Args:
            start_ref: Starting commit reference
            end_ref: Ending commit reference (default HEAD)

        Returns:
            List of CommitFinding objects
        """
        all_findings = []

        try:
            commits = list(self.repo.iter_commits(f"{start_ref}..{end_ref}"))
            print(f"Scanning {len(commits)} commits in range {start_ref}..{end_ref}...")

            for commit in commits:
                findings = self.scan_commit(commit)
                all_findings.extend(findings)

        except GitCommandError as e:
            print(f"Git command error: {e}")
        except Exception as e:
            print(f"Error scanning range: {e}")

        return all_findings

    def is_git_repo(self) -> bool:
        """Check if current directory is a git repository."""
        return self.repo is not None

    def get_current_branch(self) -> Optional[str]:
        """Get name of current branch."""
        try:
            return self.repo.active_branch.name
        except Exception:
            return None

    def get_commit_count(self, branch: Optional[str] = None) -> int:
        """Get total number of commits in branch."""
        try:
            if branch:
                return sum(1 for _ in self.repo.iter_commits(branch))
            else:
                return sum(1 for _ in self.repo.iter_commits())
        except Exception:
            return 0
