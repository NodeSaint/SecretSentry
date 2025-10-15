"""Default configuration values for Secrets Sentry."""

# Default exclude patterns for file scanning
DEFAULT_EXCLUDE_PATTERNS = [
    "node_modules/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "dist/**",
    "build/**",
    ".next/**",
    "__pycache__/**",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".git/**",
    ".svn/**",
    ".hg/**",
    "*.lock",
    "*.min.js",
    "*.min.css",
    "*.map",
    ".DS_Store",
    "*.egg-info/**",
    ".pytest_cache/**",
    ".coverage",
    "htmlcov/**",
    "reports/**",
    "data/**",
]

# Default entropy detection settings
DEFAULT_ENTROPY_THRESHOLD = 4.0
DEFAULT_MIN_TOKEN_LENGTH = 20

# Default git history scanning settings
DEFAULT_HISTORY_DEPTH = 100

# Default confidence threshold for reporting
DEFAULT_CONFIDENCE_THRESHOLD = 0.7

# Default data directory
DEFAULT_DATA_DIR = "data"

# Default reports directory
DEFAULT_REPORTS_DIR = "reports"

# Supported file extensions for scanning
SUPPORTED_EXTENSIONS = [
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".txt",
    ".md",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".config",
]

# Binary file extensions to always skip
BINARY_EXTENSIONS = [
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".wasm",
    ".pyc",
    ".pyo",
    ".pyd",
    ".class",
    ".o",
    ".a",
]