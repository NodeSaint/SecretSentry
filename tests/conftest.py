"""Pytest configuration and shared fixtures."""

import pytest
import tempfile
import os
from pathlib import Path
from fixtures.test_secrets import FAKE_SECRETS, TEST_FILES


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_file():
    """Create a temporary file for tests."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        yield f.name
    # Cleanup
    try:
        os.unlink(f.name)
    except OSError:
        pass


@pytest.fixture
def project_structure(temp_dir):
    """Create a realistic project structure in temp directory."""
    base = Path(temp_dir)

    # Create directories
    (base / "src").mkdir()
    (base / "tests").mkdir()
    (base / "config").mkdir()
    (base / "node_modules").mkdir()

    # Create files
    files = {
        "src/main.py": TEST_FILES['clean_file'],
        "src/app.py": TEST_FILES['python_with_secrets'],
        "tests/test_app.py": TEST_FILES['clean_file'],
        "config/config.json": TEST_FILES['json_config'],
        ".env": TEST_FILES['env_file'],
        "README.md": "# Test Project\n",
        "node_modules/package.json": '{"name": "test"}',
    }

    for filepath, content in files.items():
        full_path = base / filepath
        full_path.write_text(content)

    return base


@pytest.fixture
def file_with_secret(temp_dir):
    """Create a file containing a secret."""
    filepath = Path(temp_dir) / "secret.py"
    filepath.write_text(f"API_KEY = '{FAKE_SECRETS['aws_access_key']}'")
    return filepath


@pytest.fixture
def file_clean(temp_dir):
    """Create a clean file with no secrets."""
    filepath = Path(temp_dir) / "clean.py"
    filepath.write_text(TEST_FILES['clean_file'])
    return filepath


@pytest.fixture
def multiple_files_with_secrets(temp_dir):
    """Create multiple files with different secrets."""
    base = Path(temp_dir)

    files = {
        "aws_config.py": f"AWS_KEY = '{FAKE_SECRETS['aws_access_key']}'",
        "github_config.py": f"GITHUB_TOKEN = '{FAKE_SECRETS['github_pat']}'",
        "openai_config.py": f"OPENAI_KEY = '{FAKE_SECRETS['openai_key']}'",
    }

    created_files = []
    for filename, content in files.items():
        filepath = base / filename
        filepath.write_text(content)
        created_files.append(filepath)

    return created_files


@pytest.fixture
def env_file(temp_dir):
    """Create a .env file with secrets."""
    filepath = Path(temp_dir) / ".env"
    filepath.write_text(TEST_FILES['env_file'])
    return filepath


@pytest.fixture
def json_config(temp_dir):
    """Create a JSON config file with secrets."""
    filepath = Path(temp_dir) / "config.json"
    filepath.write_text(TEST_FILES['json_config'])
    return filepath


@pytest.fixture
def yaml_config(temp_dir):
    """Create a YAML config file with secrets."""
    filepath = Path(temp_dir) / "config.yaml"
    filepath.write_text(TEST_FILES['yaml_config'])
    return filepath


@pytest.fixture
def binary_file(temp_dir):
    """Create a binary file."""
    filepath = Path(temp_dir) / "binary.bin"
    with open(filepath, 'wb') as f:
        f.write(b'\x00\x01\x02\x03\x04\x05')
    return filepath


@pytest.fixture
def data_directory(temp_dir):
    """Create a data directory for storage tests."""
    data_dir = Path(temp_dir) / "data"
    data_dir.mkdir()
    return data_dir


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers",
        "git: marks tests that require git operations"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add integration marker to integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)

        # Add git marker to git-related tests
        if "git" in item.name.lower():
            item.add_marker(pytest.mark.git)
