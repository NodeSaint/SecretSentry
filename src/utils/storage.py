"""JSON storage utilities with atomic writes."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional
from datetime import datetime


def load_json(filepath: Path) -> dict:
    """
    Load JSON data from file.

    Args:
        filepath: Path to JSON file

    Returns:
        Dictionary containing JSON data

    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If JSON is invalid
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json(filepath: Path, data: Any, indent: int = 2) -> None:
    """
    Save JSON data to file atomically.

    Uses atomic write pattern: write to temp file, then rename.
    This ensures the file is never left in a partially written state.

    Args:
        filepath: Path to JSON file
        data: Data to save (must be JSON serializable)
        indent: JSON indentation level (default 2)

    Raises:
        TypeError: If data is not JSON serializable
    """
    filepath = Path(filepath)

    # Ensure parent directory exists
    filepath.parent.mkdir(parents=True, exist_ok=True)

    # Write to temporary file first
    temp_fd, temp_path = tempfile.mkstemp(
        dir=filepath.parent,
        prefix=f".{filepath.name}.",
        suffix=".tmp"
    )

    try:
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # Atomic rename
        os.replace(temp_path, filepath)

    except Exception:
        # Clean up temp file on error
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def append_json_list(filepath: Path, item: dict) -> None:
    """
    Append an item to a JSON array file.

    Args:
        filepath: Path to JSON file containing an array
        item: Dictionary item to append

    Raises:
        ValueError: If file exists but doesn't contain an array
    """
    if filepath.exists():
        data = load_json(filepath)
        if not isinstance(data, list):
            raise ValueError(f"{filepath} does not contain a JSON array")
        data.append(item)
    else:
        data = [item]

    save_json(filepath, data)


def load_findings(data_dir: str = "data") -> list[dict]:
    """
    Load findings from findings.json.

    Args:
        data_dir: Data directory path

    Returns:
        List of finding dictionaries
    """
    findings_file = Path(data_dir) / "findings.json"

    if not findings_file.exists():
        return []

    data = load_json(findings_file)
    if not isinstance(data, list):
        return []

    return data


def save_findings(findings: list[dict], data_dir: str = "data") -> None:
    """
    Save findings to findings.json.

    Args:
        findings: List of finding dictionaries
        data_dir: Data directory path
    """
    findings_file = Path(data_dir) / "findings.json"
    save_json(findings_file, findings)


def load_migration_log(data_dir: str = "data") -> dict:
    """
    Load migration log.

    Args:
        data_dir: Data directory path

    Returns:
        Dictionary mapping old secret locations to new env var names
    """
    log_file = Path(data_dir) / "migration_log.json"

    if not log_file.exists():
        return {
            "migrations": [],
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }

    return load_json(log_file)


def save_migration_log(log_data: dict, data_dir: str = "data") -> None:
    """
    Save migration log.

    Args:
        log_data: Migration log dictionary
        data_dir: Data directory path
    """
    log_file = Path(data_dir) / "migration_log.json"
    log_data["last_updated"] = datetime.now().isoformat()
    save_json(log_file, log_data)


def add_migration_entry(
    file: str,
    line: int,
    old_value_redacted: str,
    env_var_name: str,
    data_dir: str = "data"
) -> None:
    """
    Add an entry to the migration log.

    Args:
        file: File path where secret was found
        line: Line number
        old_value_redacted: Redacted old value
        env_var_name: New environment variable name
        data_dir: Data directory path
    """
    log = load_migration_log(data_dir)

    entry = {
        "file": file,
        "line": line,
        "old_value_redacted": old_value_redacted,
        "env_var_name": env_var_name,
        "migrated_at": datetime.now().isoformat()
    }

    log["migrations"].append(entry)
    save_migration_log(log, data_dir)


def load_override_log(data_dir: str = "data") -> list[dict]:
    """
    Load pre-commit hook override log.

    Args:
        data_dir: Data directory path

    Returns:
        List of override entries
    """
    log_file = Path(data_dir) / "override_log.json"

    if not log_file.exists():
        return []

    data = load_json(log_file)
    if not isinstance(data, list):
        return []

    return data


def log_override(reason: str, findings_count: int, data_dir: str = "data") -> None:
    """
    Log a pre-commit hook override.

    Args:
        reason: Reason for override
        findings_count: Number of findings that were bypassed
        data_dir: Data directory path
    """
    log = load_override_log(data_dir)

    entry = {
        "timestamp": datetime.now().isoformat(),
        "reason": reason,
        "findings_bypassed": findings_count,
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    }

    log.append(entry)

    log_file = Path(data_dir) / "override_log.json"
    save_json(log_file, log)


def file_exists(filepath: Path) -> bool:
    """Check if file exists."""
    return Path(filepath).exists()


def ensure_dir(dirpath: Path) -> None:
    """Ensure directory exists."""
    Path(dirpath).mkdir(parents=True, exist_ok=True)


def get_file_size(filepath: Path) -> int:
    """Get file size in bytes."""
    return Path(filepath).stat().st_size


def get_file_modified_time(filepath: Path) -> datetime:
    """Get file last modified time."""
    timestamp = Path(filepath).stat().st_mtime
    return datetime.fromtimestamp(timestamp)
