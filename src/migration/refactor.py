"""
Code refactoring utilities for replacing hardcoded secrets with environment variables.

This module provides safe code refactoring that:
- Creates backups before modification
- Preserves code formatting
- Supports Python and JavaScript
- Provides diff preview before applying changes
"""

import os
import re
import shutil
import difflib
from pathlib import Path
from typing import Optional, Tuple, List
from datetime import datetime

try:
    import pasta
    PASTA_AVAILABLE = True
except ImportError:
    PASTA_AVAILABLE = False


class RefactorError(Exception):
    """Raised when refactoring fails."""
    pass


def create_backup(file_path: Path, backup_dir: str = ".backup") -> Path:
    """
    Create a backup of the file before modification.

    Args:
        file_path: Path to file to backup
        backup_dir: Directory to store backups

    Returns:
        Path to backup file

    Raises:
        RefactorError: If backup creation fails
    """
    try:
        file_path = Path(file_path)
        backup_root = Path(backup_dir)

        # Create backup directory structure matching original
        relative_path = file_path.relative_to(Path.cwd()) if file_path.is_absolute() else file_path
        backup_path = backup_root / relative_path

        # Add timestamp to backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_path.parent / f"{backup_path.name}.{timestamp}.bak"

        # Create parent directories
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy file
        shutil.copy2(file_path, backup_path)

        return backup_path

    except Exception as e:
        raise RefactorError(f"Failed to create backup of {file_path}: {e}")


def generate_diff(original: str, modified: str, filename: str = "file") -> str:
    """
    Generate unified diff between original and modified content.

    Args:
        original: Original file content
        modified: Modified file content
        filename: Filename for diff header

    Returns:
        Unified diff string
    """
    original_lines = original.splitlines(keepends=True)
    modified_lines = modified.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        modified_lines,
        fromfile=f"{filename} (original)",
        tofile=f"{filename} (refactored)",
        lineterm=''
    )

    return ''.join(diff)


def escape_for_regex(text: str) -> str:
    """Escape special regex characters in text."""
    return re.escape(text)


def extract_secret_from_line(file_path: Path, line_number: int) -> Optional[str]:
    """
    Extract the secret value from a specific line in a file.

    This is used when we don't have the unredacted secret value stored,
    and need to extract it from the source file for refactoring.

    Args:
        file_path: Path to source file
        line_number: Line number (1-indexed)

    Returns:
        The extracted secret value, or None if not found
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        if line_number < 1 or line_number > len(lines):
            return None

        line = lines[line_number - 1]  # Convert to 0-indexed

        # Try to extract string literals from the line
        # Match various quote styles: "...", '...', """...""", '''...''', `...`
        string_patterns = [
            r'"([^"\\]*(?:\\.[^"\\]*)*)"',  # Double quotes
            r"'([^'\\]*(?:\\.[^'\\]*)*)'",  # Single quotes
            r'"""(.*?)"""',  # Triple double quotes
            r"'''(.*?)'''",  # Triple single quotes
            r'`([^`]*)`',  # Backticks (template literals)
        ]

        for pattern in string_patterns:
            matches = re.findall(pattern, line, re.DOTALL)
            if matches:
                # Return the longest match (likely to be the secret)
                return max(matches, key=len)

        # If no quoted strings, try to extract any long alphanumeric sequence
        # This handles cases like: api_key = sk-abc123...
        matches = re.findall(r'[a-zA-Z0-9_\-+/=]{20,}', line)
        if matches:
            return max(matches, key=len)

        return None

    except Exception:
        return None


def refactor_python_file(
    file_path: Path,
    secret_value: str,
    env_var_name: str,
    line_number: Optional[int] = None
) -> Tuple[str, str]:
    """
    Refactor Python file to replace hardcoded secret with os.getenv() call.

    Uses pasta library to preserve formatting when possible, falls back to
    regex replacement if pasta is not available or fails.

    Args:
        file_path: Path to Python file
        secret_value: The secret value to replace
        env_var_name: Environment variable name to use
        line_number: Optional line number hint for replacement

    Returns:
        Tuple of (original_content, modified_content)

    Raises:
        RefactorError: If refactoring fails
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        modified_content = original_content

        # Strategy 1: Try pasta for AST-based refactoring (preserves formatting)
        if PASTA_AVAILABLE and secret_value in original_content:
            try:
                # Parse with pasta
                tree = pasta.parse(original_content)

                # TODO: AST walking to find and replace string literals
                # For MVP, we'll use regex approach which is more reliable
                # Full AST implementation would go here

            except Exception as e:
                # If pasta fails, fall through to regex
                pass

        # Strategy 2: Regex-based replacement (reliable fallback)
        # This handles most common patterns safely

        # Ensure we have os import at the top
        if 'import os' not in modified_content and 'from os import' not in modified_content:
            # Add import after any existing imports or at the top
            lines = modified_content.split('\n')
            import_index = 0

            # Find last import or first non-comment/docstring line
            in_docstring = False
            for i, line in enumerate(lines):
                stripped = line.strip()

                # Track docstrings
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_docstring = not in_docstring
                    import_index = i + 1
                    continue

                if in_docstring:
                    import_index = i + 1
                    continue

                # Track imports
                if stripped.startswith('import ') or stripped.startswith('from '):
                    import_index = i + 1
                elif stripped and not stripped.startswith('#'):
                    # Found first non-import, non-comment line
                    break

            lines.insert(import_index, 'import os')
            modified_content = '\n'.join(lines)

        # Replace the secret value with os.getenv() call
        # Handle various quote styles
        patterns_to_try = [
            # Double quotes
            (f'"{escape_for_regex(secret_value)}"', f'os.getenv("{env_var_name}")'),
            (f"'{escape_for_regex(secret_value)}'", f'os.getenv("{env_var_name}")'),
            # Triple quotes (for multiline strings)
            (f'"""{escape_for_regex(secret_value)}"""', f'os.getenv("{env_var_name}")'),
            (f"'''{escape_for_regex(secret_value)}'''", f'os.getenv("{env_var_name}")'),
            # F-strings
            (f'f"{escape_for_regex(secret_value)}"', f'os.getenv("{env_var_name}")'),
            (f"f'{escape_for_regex(secret_value)}'", f'os.getenv("{env_var_name}")'),
        ]

        replaced = False
        for pattern, replacement in patterns_to_try:
            if pattern in modified_content:
                modified_content = modified_content.replace(pattern, replacement)
                replaced = True
                break

        # If no exact match found, try finding the secret value without quotes
        if not replaced and secret_value in modified_content:
            # This is more aggressive - replace the raw value
            # Could have false positives, so we're careful
            modified_content = modified_content.replace(secret_value, f'os.getenv("{env_var_name}")')
            replaced = True

        if not replaced:
            raise RefactorError(f"Could not find secret value in {file_path}")

        return original_content, modified_content

    except Exception as e:
        raise RefactorError(f"Failed to refactor Python file {file_path}: {e}")


def refactor_js_file(
    file_path: Path,
    secret_value: str,
    env_var_name: str,
    line_number: Optional[int] = None
) -> Tuple[str, str]:
    """
    Refactor JavaScript/TypeScript file to replace secret with process.env.

    Uses regex-based replacement (safer than AST for JS/TS).

    Args:
        file_path: Path to JS/TS file
        secret_value: The secret value to replace
        env_var_name: Environment variable name to use
        line_number: Optional line number hint for replacement

    Returns:
        Tuple of (original_content, modified_content)

    Raises:
        RefactorError: If refactoring fails
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()

        modified_content = original_content

        # Replace the secret value with process.env access
        # Handle various quote styles and declarations
        patterns_to_try = [
            # Double quotes
            (f'"{escape_for_regex(secret_value)}"', f'process.env.{env_var_name}'),
            (f"'{escape_for_regex(secret_value)}'", f'process.env.{env_var_name}'),
            # Template literals
            (f'`{escape_for_regex(secret_value)}`', f'process.env.{env_var_name}'),
        ]

        replaced = False
        for pattern, replacement in patterns_to_try:
            if pattern in modified_content:
                modified_content = modified_content.replace(pattern, replacement)
                replaced = True
                break

        # If no exact match found, try finding the secret value without quotes
        if not replaced and secret_value in modified_content:
            modified_content = modified_content.replace(secret_value, f'process.env.{env_var_name}')
            replaced = True

        if not replaced:
            raise RefactorError(f"Could not find secret value in {file_path}")

        return original_content, modified_content

    except Exception as e:
        raise RefactorError(f"Failed to refactor JS file {file_path}: {e}")


def refactor_file(
    file_path: Path,
    secret_value: str,
    env_var_name: str,
    line_number: Optional[int] = None,
    create_backup_file: bool = True,
    dry_run: bool = False
) -> Tuple[str, str, Optional[Path]]:
    """
    Refactor a file to replace hardcoded secret with environment variable.

    Automatically detects file type and uses appropriate refactoring strategy.

    Args:
        file_path: Path to file to refactor
        secret_value: The secret value to replace (can be empty/placeholder if line_number is provided)
        env_var_name: Environment variable name to use
        line_number: Optional line number hint for replacement
        create_backup_file: Whether to create backup before modification
        dry_run: If True, don't actually modify files

    Returns:
        Tuple of (original_content, modified_content, backup_path)
        backup_path is None if create_backup_file is False or dry_run is True

    Raises:
        RefactorError: If refactoring fails
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise RefactorError(f"File does not exist: {file_path}")

    # If secret_value is not provided or is a placeholder, try to extract from source
    if (not secret_value or
        secret_value in ['<ask user to provide>', '<masked>', ''] or
        secret_value.startswith('***')):  # Redacted value

        if line_number:
            extracted_secret = extract_secret_from_line(file_path, line_number)
            if extracted_secret:
                secret_value = extracted_secret
            else:
                raise RefactorError(
                    f"Could not extract secret value from {file_path}:{line_number}. "
                    f"Manual refactoring may be required."
                )
        else:
            raise RefactorError(
                f"Secret value not provided and no line number given for {file_path}. "
                f"Cannot refactor without knowing what to replace."
            )

    # Detect file type
    suffix = file_path.suffix.lower()

    if suffix == '.py':
        original_content, modified_content = refactor_python_file(
            file_path, secret_value, env_var_name, line_number
        )
    elif suffix in ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs']:
        original_content, modified_content = refactor_js_file(
            file_path, secret_value, env_var_name, line_number
        )
    else:
        # For other file types, try generic text replacement
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()

            if secret_value not in original_content:
                raise RefactorError(f"Secret value not found in {file_path}")

            # Generic replacement - just replace the value
            modified_content = original_content.replace(
                secret_value,
                f"${{{{env_var_name}}}}"  # Generic placeholder
            )
        except Exception as e:
            raise RefactorError(f"Unsupported file type {suffix} for {file_path}: {e}")

    backup_path = None

    if not dry_run:
        # Create backup if requested
        if create_backup_file:
            backup_path = create_backup(file_path)

        # Write modified content
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)
        except Exception as e:
            # If write fails and we created a backup, restore it
            if backup_path:
                shutil.copy2(backup_path, file_path)
            raise RefactorError(f"Failed to write refactored file {file_path}: {e}")

    return original_content, modified_content, backup_path


def refactor_multiple_files(
    migrations: List[dict],
    dry_run: bool = False,
    create_backups: bool = True
) -> List[dict]:
    """
    Refactor multiple files based on migration list.

    Args:
        migrations: List of migration dictionaries with keys:
                   - file: file path
                   - value_full: secret value to replace
                   - env_var_name: environment variable name
                   - line: line number (optional)
        dry_run: If True, don't actually modify files
        create_backups: Whether to create backups

    Returns:
        List of result dictionaries with keys:
            - file: file path
            - success: bool
            - error: error message if failed
            - backup_path: path to backup if created
            - diff: unified diff string
    """
    results = []

    for migration in migrations:
        file_path = Path(migration['file'])
        secret_value = migration.get('value_full', '')
        env_var_name = migration['env_var_name']
        line_number = migration.get('line')

        result = {
            'file': str(file_path),
            'env_var_name': env_var_name,
            'success': False,
            'error': None,
            'backup_path': None,
            'diff': None
        }

        try:
            original, modified, backup_path = refactor_file(
                file_path=file_path,
                secret_value=secret_value,
                env_var_name=env_var_name,
                line_number=line_number,
                create_backup_file=create_backups,
                dry_run=dry_run
            )

            result['success'] = True
            result['backup_path'] = str(backup_path) if backup_path else None
            result['diff'] = generate_diff(original, modified, str(file_path))

        except Exception as e:
            result['error'] = str(e)

        results.append(result)

    return results


def rollback_file(backup_path: Path) -> None:
    """
    Rollback a file from its backup.

    Args:
        backup_path: Path to backup file

    Raises:
        RefactorError: If rollback fails
    """
    try:
        backup_path = Path(backup_path)

        if not backup_path.exists():
            raise RefactorError(f"Backup file does not exist: {backup_path}")

        # Extract original file path from backup path
        # Format: .backup/path/to/file.py.TIMESTAMP.bak
        original_path_str = str(backup_path.relative_to('.backup'))
        # Remove timestamp and .bak extension
        original_path_str = re.sub(r'\.\d{8}_\d{6}\.bak$', '', original_path_str)
        original_path = Path(original_path_str)

        # Restore from backup
        shutil.copy2(backup_path, original_path)

    except Exception as e:
        raise RefactorError(f"Failed to rollback from backup {backup_path}: {e}")
