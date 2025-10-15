"""Test fixtures containing realistic FAKE secrets for testing.

IMPORTANT: All secrets in this file are FAKE and meant only for testing.
Do NOT use these in production or commit real secrets.
"""

# Valid format examples for pattern detection
FAKE_SECRETS = {
    # AWS Keys
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "aws_access_key_2": "AKIATESTTESTTESTTEST",
    "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",

    # OpenAI
    "openai_key": "sk-" + "x" * 48,
    "openai_key_valid": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",

    # Slack
    "slack_bot_token": "xoxb-FAKE_SLACK_BOT_TOKEN_FOR_TESTING_ONLY",
    "slack_app_token": "xoxp-FAKE_SLACK_APP_TOKEN_FOR_TESTING_ONLY",
    "slack_webhook": "https://hooks.slack.com/services/FAKE/WEBHOOK/PLACEHOLDER",

    # Discord
    "discord_token": "FAKE.DISCORD.TOKEN_FOR_TESTING_ONLY",
    "discord_token_2": "ANOTHER.FAKE.DISCORD_TOKEN_FOR_TESTING",
    "discord_webhook": "https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
    "discord_webhook_old": "https://discordapp.com/api/webhooks/987654321098765432/ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0123456789",

    # GitHub
    "github_pat": "ghp_" + "a" * 36,
    "github_oauth": "gho_" + "b" * 36,
    "github_pat_realistic": "ghp_1234567890abcdefghijklmnopqrstuv1234",

    # JWT
    "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "jwt_token_unsigned": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.",

    # Private Keys (multi-line)
    "rsa_private_key": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx7PnVWcUAAAAFAKEKEYexamplekeydonotuseAAAA
examplekeyexamplekeyexamplekeyexamplekeyexamplekeyAAAAAA
-----END RSA PRIVATE KEY-----""",

    "ec_private_key": """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIGLEKEYexampleeckeydontuse1234567890ABCDEFGHIJ
-----END EC PRIVATE KEY-----""",

    "openssh_private_key": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----""",

    # Firebase
    "firebase_key": "AIzaSyDEXAMPLEKEY1234567890abcdefghijkl",
    "firebase_key_2": "AIzaSyC_1234567890-ABCDEFGHIJKLMNOPQRS",

    # Stripe
    "stripe_live_key": "sk_live_FAKE_STRIPE_KEY_FOR_TESTING",
    "stripe_live_key_long": "sk_live_ANOTHER_FAKE_STRIPE_KEY_PLACEHOLDER",
    "stripe_restricted_key": "rk_live_FAKE_RESTRICTED_KEY",

    # Twilio
    "twilio_api_key": "SK_FAKE_TWILIO_API_KEY_FOR_TESTING",
    "twilio_account_sid": "AC_FAKE_TWILIO_ACCOUNT_SID_TEST",
    "twilio_api_realistic": "SK_FAKE_TWILIO_KEY_PLACEHOLDER",

    # Google API
    "google_api_key": "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI",
    "google_api_key_2": "AIzaSyB1234567890-abcdefghijklmnopqrst",

    # Database URLs
    "postgres_url": "postgresql://admin:SuperSecret123@db.example.com:5432/mydb",
    "mysql_url": "mysql://root:MyPassword456@localhost:3306/database",
    "mongodb_url": "mongodb://dbuser:dbpass123@mongo.example.com:27017/myapp",
    "redis_url": "redis://:secretpassword@redis.example.com:6379/0",

    # Generic secrets
    "generic_api_key": "api_key=abcdef1234567890abcdef1234567890",
    "generic_api_key_2": 'apikey="1234567890abcdefghijklmnopqrstuvwxyz"',
    "generic_secret": 'secret="MyVerySecretPassword123!"',
    "generic_password": 'password="P@ssw0rd123456"',

    # Base64 encoded
    "base64_token": 'token="dGhpc2lzYWZha2ViYXNlNjRlbmNvZGVkc2VjcmV0MTIzNDU2Nzg5MA=="',
    "base64_secret": 'secret="QmFzZTY0RW5jb2RlZFNlY3JldEtleUZvclRlc3RpbmdQdXJwb3Nlc09ubHk="',

    # High entropy strings
    "high_entropy_1": "g8jF3nK9pL2mQ5rT1vW7xY4zA6bC8dE0fH2iJ5kM9nP3qR7sU1vX4yZ",
    "high_entropy_2": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8",
    "high_entropy_hex": "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
}

# False positives - should NOT be detected as secrets
FALSE_POSITIVES = {
    # UUIDs
    "uuid_v4": "550e8400-e29b-41d4-a716-446655440000",
    "uuid_v1": "f47ac10b-58cc-4372-a567-0e02b2c3d479",

    # Hashes (not secrets)
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",

    # Timestamps
    "unix_timestamp": "1234567890123456",
    "unix_timestamp_ms": "1609459200000",

    # Version numbers
    "semver": "1.2.3-alpha.1+build.123",
    "version_long": "2.10.4.20230615.1",

    # Placeholders
    "placeholder_1": "your_api_key_here",
    "placeholder_2": "replace_with_your_token",
    "placeholder_3": "INSERT_YOUR_SECRET_HERE",
    "placeholder_4": "xxxxxxxxxxxxxxxxxxxx",

    # Example values from docs
    "example_1": "example_key_123",
    "example_2": "sample_token_456",
    "example_3": "test_secret_789",

    # Common non-secret long strings
    "lorem_ipsum": "LoremIpsumDolorSitAmetConsecteturAdipiscingElitSedDoEiusmod",
    "alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",

    # Image data headers
    "png_header": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA",
    "jpeg_header": "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJ",
}

# Edge cases for testing
EDGE_CASES = {
    # Very short strings (below min_length)
    "short_string": "abc123",
    "empty_string": "",

    # Very long strings
    "long_string": "a" * 500,
    "long_secret": "sk-" + "x" * 500,

    # Unicode and special characters
    "unicode_emoji": "api_key=🔑🔐🗝️🚀✨💻🌟🎉",
    "unicode_mixed": "secret_密码_パスワード_1234567890",
    "unicode_cyrillic": "пароль_секрет_ключ_1234567890",
    "unicode_chinese": "密钥_API密钥_1234567890abcdefghij",
    "unicode_arabic": "مفتاح_سري_1234567890abcdefghij",
    "special_chars": "p@$$w0rd!#$%^&*()_+-=[]{}|;:',.<>?/",

    # Escaped strings
    "escaped_newline": "api_key=test\\nvalue\\n1234567890",
    "escaped_quotes": 'secret=\\"test\\\\"value\\\\"123\\"',
    "escaped_backslash": "key=path\\\\to\\\\secret\\\\1234567890",

    # Multi-line formats
    "yaml_multiline": """
api_key: "sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789"
secret: "MySecretValue123"
""",

    "json_multiline": """{
  "apiKey": "AKIAIOSFODNN7EXAMPLE",
  "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}""",

    "toml_multiline": """[secrets]
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789"
database_url = "postgresql://user:pass@host:5432/db"
""",

    # Concatenated strings
    "concatenated": '"sk-" + "1234567890abcdefghijklmnopqrstuvwxyz0123456789"',
    "concatenated_env": "API_KEY=" + "test" + "1234567890abcdef",

    # Environment variable patterns
    "env_export": 'export API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789"',
    "env_dotenv": 'API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789',
    "env_quoted": "API_KEY='sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789'",

    # Comments with secrets
    "python_comment": "# API_KEY = sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789",
    "js_comment": "// const API_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789';",
    "hash_comment": "# secret=MySecretPassword123",

    # Mixed case
    "mixed_case": "Api_Key=aBcDeF1234567890GhIjKlMnOpQrStUvWxYz",

    # Binary-like data (should be skipped)
    "binary_like": "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",

    # Very long line (>10k chars)
    "very_long_line": "api_key=" + ("x" * 10000) + "1234567890",
}

# Test file contents for integration tests
TEST_FILES = {
    # Python file with secrets
    "python_with_secrets": """
#!/usr/bin/env python3
import os

# AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# OpenAI API key
OPENAI_API_KEY = "sk-" + "x" * 48

# Database connection
DATABASE_URL = "postgresql://admin:SuperSecret123@db.example.com:5432/mydb"

def connect_to_api():
    # This should not be detected (placeholder)
    api_key = "your_api_key_here"
    return api_key
""",

    # JavaScript file with secrets
    "javascript_with_secrets": """
const express = require('express');

// API Keys
const OPENAI_KEY = 'sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789';
const STRIPE_KEY = 'sk_live_FAKE_STRIPE_KEY_PLACEHOLDER';

// Slack webhook
const SLACK_WEBHOOK = 'https://hooks.slack.com/services/FAKE/PLACEHOLDER/XXXX';

// This is OK (example)
const EXAMPLE_KEY = 'example_key_123';
""",

    # .env file
    "env_file": """
# Production secrets
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789

# Database
DATABASE_URL=postgresql://admin:SuperSecret123@db.example.com:5432/mydb

# Webhooks
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/FAKE/PLACEHOLDER/XXXX
""",

    # YAML config
    "yaml_config": """
api:
  openai:
    key: sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789
  stripe:
    secret_key: sk_live_FAKE_STRIPE_KEY_PLACEHOLDER

database:
  url: postgresql://admin:SuperSecret123@db.example.com:5432/mydb

webhooks:
  slack: https://hooks.slack.com/services/FAKE/PLACEHOLDER/XXXX
""",

    # JSON config
    "json_config": """{
  "aws": {
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  },
  "openai": {
    "apiKey": "sk-1234567890abcdefghijklmnopqrstuvwxyz0123456789"
  }
}""",

    # File with no secrets
    "clean_file": """
import os

def get_api_key():
    # Properly using environment variables
    return os.getenv('API_KEY')

def main():
    api_key = get_api_key()
    if not api_key:
        raise ValueError("API_KEY not set")
    print("API key loaded from environment")
""",
}

# Suspicious filenames for heuristic detection
SUSPICIOUS_FILENAMES = [
    ".env",
    ".env.local",
    ".env.production",
    "credentials.json",
    "secrets.yaml",
    "id_rsa",
    "id_dsa",
    "private.key",
    "serviceaccount.json",
    "service_account.json",
    "api-key.txt",
    "password.txt",
    "token.json",
]

# Clean filenames (should not trigger heuristics)
CLEAN_FILENAMES = [
    "main.py",
    "app.js",
    "index.html",
    "README.md",
    "package.json",
    "requirements.txt",
    "Dockerfile",
    "config.example.json",
    ".gitignore",
]

# Patterns that should be excluded
EXCLUDED_PATTERNS = [
    "node_modules/package.json",
    ".venv/lib/python3.9/site.py",
    "dist/bundle.js",
    "build/output.min.js",
    "__pycache__/module.pyc",
    ".git/config",
    "*.lock",
    "*.min.js",
    "*.min.css",
]
