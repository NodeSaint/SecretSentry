"""Regex pattern-based secret detection."""

import re
from typing import Optional


# Secret pattern definitions
PATTERNS = {
    "AWS_ACCESS_KEY": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "confidence": 0.95,
        "remediation": "AWS Access Key detected. Move to Replit Secrets as AWS_ACCESS_KEY_ID.",
    },
    "AWS_SECRET_KEY": {
        "pattern": r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]",
        "confidence": 0.85,
        "remediation": "AWS Secret Key detected. Move to Replit Secrets as AWS_SECRET_ACCESS_KEY.",
    },
    "OPENAI_API_KEY": {
        "pattern": r"sk-[a-zA-Z0-9]{48}",
        "confidence": 0.95,
        "remediation": "OpenAI API Key detected. Move to Replit Secrets as OPENAI_API_KEY.",
    },
    "SLACK_TOKEN": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z-]+",
        "confidence": 0.90,
        "remediation": "Slack Token detected. Move to Replit Secrets as SLACK_TOKEN.",
    },
    "SLACK_WEBHOOK": {
        "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "confidence": 0.95,
        "remediation": "Slack Webhook URL detected. Move to Replit Secrets as SLACK_WEBHOOK_URL.",
    },
    "DISCORD_TOKEN": {
        "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
        "confidence": 0.90,
        "remediation": "Discord Token detected. Move to Replit Secrets as DISCORD_TOKEN.",
    },
    "DISCORD_WEBHOOK": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
        "confidence": 0.95,
        "remediation": "Discord Webhook URL detected. Move to Replit Secrets as DISCORD_WEBHOOK_URL.",
    },
    "GITHUB_PAT": {
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "confidence": 0.95,
        "remediation": "GitHub Personal Access Token detected. Move to Replit Secrets as GITHUB_TOKEN.",
    },
    "GITHUB_OAUTH": {
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "confidence": 0.95,
        "remediation": "GitHub OAuth Token detected. Move to Replit Secrets as GITHUB_OAUTH_TOKEN.",
    },
    "JWT_TOKEN": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "confidence": 0.75,
        "remediation": "JWT Token detected. If this is a secret token, move to Replit Secrets.",
    },
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----",
        "confidence": 0.99,
        "remediation": "Private Key detected. Never commit private keys! Move to Replit Secrets or use secure key management.",
    },
    "FIREBASE_API_KEY": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "confidence": 0.90,
        "remediation": "Firebase API Key detected. Move to Replit Secrets as FIREBASE_API_KEY.",
    },
    "STRIPE_API_KEY": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "confidence": 0.95,
        "remediation": "Stripe Live API Key detected. Move to Replit Secrets as STRIPE_API_KEY.",
    },
    "STRIPE_RESTRICTED_KEY": {
        "pattern": r"rk_live_[0-9a-zA-Z]{24,}",
        "confidence": 0.95,
        "remediation": "Stripe Restricted Key detected. Move to Replit Secrets as STRIPE_RESTRICTED_KEY.",
    },
    "TWILIO_API_KEY": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "confidence": 0.85,
        "remediation": "Twilio API Key detected. Move to Replit Secrets as TWILIO_API_KEY.",
    },
    "TWILIO_ACCOUNT_SID": {
        "pattern": r"AC[0-9a-fA-F]{32}",
        "confidence": 0.85,
        "remediation": "Twilio Account SID detected. Move to Replit Secrets as TWILIO_ACCOUNT_SID.",
    },
    "GOOGLE_API_KEY": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "confidence": 0.85,
        "remediation": "Google API Key detected. Move to Replit Secrets as GOOGLE_API_KEY.",
    },
    "GENERIC_API_KEY": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret|apisecret)['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z-_]{16,})['\"]?",
        "confidence": 0.70,
        "remediation": "Generic API Key pattern detected. Consider moving to Replit Secrets.",
    },
    "GENERIC_SECRET": {
        "pattern": r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]",
        "confidence": 0.65,
        "remediation": "Generic secret pattern detected. Consider moving to Replit Secrets.",
    },
    "DATABASE_URL": {
        "pattern": r"(?i)(postgres|postgresql|mysql|mongodb|redis)://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+",
        "confidence": 0.90,
        "remediation": "Database connection string with credentials detected. Move to Replit Secrets as DATABASE_URL.",
    },
    "GENERIC_BASE64": {
        "pattern": r"(?i)(token|secret|key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{30,}={0,2})['\"]?",
        "confidence": 0.60,
        "remediation": "Base64-encoded secret detected. Consider moving to Replit Secrets.",
    },

    # ==================== ADDITIONAL PATTERNS (Agent-researched) ====================

    # AWS Expanded
    "AWS_SESSION_TOKEN": {
        "pattern": r"(?i)(aws.?session.?token|aws.?token).{0,20}['\"]([A-Za-z0-9/+=]{100,})['\"]",
        "confidence": 0.85,
        "remediation": "AWS Session Token detected. Move to Replit Secrets as AWS_SESSION_TOKEN.",
    },

    # Azure
    "AZURE_CLIENT_SECRET": {
        "pattern": r"[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}",
        "confidence": 0.95,
        "remediation": "Azure AD Client Secret detected. Move to Replit Secrets as AZURE_CLIENT_SECRET.",
    },

    # GCP
    "GCP_OAUTH_TOKEN": {
        "pattern": r"ya29\.[0-9A-Za-z\-_]+",
        "confidence": 0.90,
        "remediation": "GCP OAuth Access Token detected. Move to Replit Secrets as GCP_OAUTH_TOKEN.",
    },

    # DigitalOcean
    "DIGITALOCEAN_PAT": {
        "pattern": r"dop_v1_[a-f0-9]{64}",
        "confidence": 0.95,
        "remediation": "DigitalOcean Personal Access Token detected. Move to Replit Secrets as DO_API_TOKEN.",
    },

    # Anthropic (Claude AI)
    "ANTHROPIC_API_KEY": {
        "pattern": r"sk-ant-api03-[a-zA-Z0-9_\-]{93}AA",
        "confidence": 0.98,
        "remediation": "Anthropic Claude API Key detected. Move to Replit Secrets as ANTHROPIC_API_KEY.",
    },

    # Hugging Face
    "HUGGINGFACE_TOKEN": {
        "pattern": r"hf_[a-zA-Z]{34}",
        "confidence": 0.95,
        "remediation": "Hugging Face Access Token detected. Move to Replit Secrets as HUGGINGFACE_TOKEN.",
    },

    # Cohere
    "COHERE_API_KEY": {
        "pattern": r"(?i)cohere.{0,20}['\"]([a-zA-Z0-9]{40})['\"]",
        "confidence": 0.85,
        "remediation": "Cohere API Key detected. Move to Replit Secrets as COHERE_API_KEY.",
    },

    # Replicate
    "REPLICATE_API_TOKEN": {
        "pattern": r"r8_[a-zA-Z0-9]{40}",
        "confidence": 0.95,
        "remediation": "Replicate API Token detected. Move to Replit Secrets as REPLICATE_API_TOKEN.",
    },

    # Supabase
    "SUPABASE_SERVICE_KEY": {
        "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
        "confidence": 0.70,
        "remediation": "Supabase Service Role Key (JWT) detected. Never expose this key! Move to Replit Secrets.",
    },

    # Vercel
    "VERCEL_TOKEN": {
        "pattern": r"(?i)(?:vercel|now).{0,20}['\"]([a-zA-Z0-9]{24})['\"]",
        "confidence": 0.85,
        "remediation": "Vercel Access Token detected. Move to Replit Secrets as VERCEL_TOKEN.",
    },

    # PlanetScale
    "PLANETSCALE_TOKEN": {
        "pattern": r"pscale_tkn_[a-zA-Z0-9_\-\.]{43}",
        "confidence": 0.95,
        "remediation": "PlanetScale API Token detected. Move to Replit Secrets as PLANETSCALE_TOKEN.",
    },

    # Square
    "SQUARE_ACCESS_TOKEN": {
        "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",
        "confidence": 0.95,
        "remediation": "Square Access Token detected. Move to Replit Secrets as SQUARE_ACCESS_TOKEN.",
    },

    # SendGrid
    "SENDGRID_API_KEY": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "confidence": 0.95,
        "remediation": "SendGrid API Key detected. Move to Replit Secrets as SENDGRID_API_KEY.",
    },

    # NPM
    "NPM_TOKEN": {
        "pattern": r"npm_[a-zA-Z0-9]{36}",
        "confidence": 0.95,
        "remediation": "NPM Access Token detected. Move to Replit Secrets as NPM_TOKEN.",
    },

    # PyPI
    "PYPI_TOKEN": {
        "pattern": r"pypi-AgEIcH[a-zA-Z0-9_-]{50,}",
        "confidence": 0.95,
        "remediation": "PyPI Upload Token detected. Move to Replit Secrets as PYPI_TOKEN.",
    },

    # Docker Hub
    "DOCKER_HUB_TOKEN": {
        "pattern": r"dckr_pat_[a-zA-Z0-9_-]{36,}",
        "confidence": 0.95,
        "remediation": "Docker Hub Personal Access Token detected. Move to Replit Secrets as DOCKER_HUB_TOKEN.",
    },

    # Terraform Cloud
    "TERRAFORM_CLOUD_TOKEN": {
        "pattern": r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{60,}",
        "confidence": 0.95,
        "remediation": "Terraform Cloud API Token detected. Move to Replit Secrets as TFE_TOKEN.",
    },

    # New Relic
    "NEW_RELIC_API_KEY": {
        "pattern": r"NRAK-[A-Z0-9]{27}",
        "confidence": 0.95,
        "remediation": "New Relic User API Key detected. Move to Replit Secrets as NEW_RELIC_API_KEY.",
    },

    # Sentry
    "SENTRY_DSN": {
        "pattern": r"https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/\d+",
        "confidence": 0.95,
        "remediation": "Sentry DSN detected. While DSNs are safe to expose, consider moving to Replit Secrets.",
    },

    # GitHub Fine-Grained PAT
    "GITHUB_FINE_GRAINED_PAT": {
        "pattern": r"github_pat_[0-9a-zA-Z_]{82}",
        "confidence": 0.95,
        "remediation": "GitHub Fine-Grained Personal Access Token detected. Move to Replit Secrets as GITHUB_TOKEN.",
    },

    # GitLab
    "GITLAB_PAT": {
        "pattern": r"glpat-[0-9a-zA-Z_-]{20}",
        "confidence": 0.95,
        "remediation": "GitLab Personal Access Token detected. Move to Replit Secrets as GITLAB_TOKEN.",
    },
}


class PatternDetector:
    """Pattern-based secret detector using regex."""

    def __init__(self):
        """Initialize pattern detector with compiled regex patterns."""
        self.compiled_patterns = {}
        for name, config in PATTERNS.items():
            self.compiled_patterns[name] = {
                "regex": re.compile(config["pattern"]),
                "confidence": config["confidence"],
                "remediation": config["remediation"],
            }

    def scan_line(self, line: str, line_number: int) -> list[dict]:
        """
        Scan a single line for secret patterns.

        Args:
            line: Line content to scan
            line_number: Line number in file

        Returns:
            List of finding dictionaries
        """
        findings = []

        for rule_name, pattern_config in self.compiled_patterns.items():
            regex = pattern_config["regex"]
            matches = regex.finditer(line)

            for match in matches:
                # Extract the matched secret
                secret = match.group(0)

                # For patterns with capture groups, use the last group
                if match.groups():
                    secret = match.group(match.lastindex)

                findings.append({
                    "token": secret,
                    "line": line_number,
                    "start": match.start(),
                    "end": match.end(),
                    "rule": rule_name,
                    "confidence": pattern_config["confidence"],
                    "remediation": pattern_config["remediation"],
                })

        return findings

    def scan(self, content: str, start_line: int = 1) -> list[dict]:
        """
        Scan multi-line content for secret patterns.

        Args:
            content: Text content to scan
            start_line: Starting line number (default 1)

        Returns:
            List of finding dictionaries
        """
        findings = []
        lines = content.split('\n')

        for i, line in enumerate(lines):
            line_number = start_line + i
            line_findings = self.scan_line(line, line_number)
            findings.extend(line_findings)

        return findings

    def get_pattern_info(self, rule_name: str) -> Optional[dict]:
        """
        Get information about a specific pattern.

        Args:
            rule_name: Name of the pattern rule

        Returns:
            Dictionary with pattern info or None if not found
        """
        if rule_name not in PATTERNS:
            return None

        return {
            "name": rule_name,
            "pattern": PATTERNS[rule_name]["pattern"],
            "confidence": PATTERNS[rule_name]["confidence"],
            "remediation": PATTERNS[rule_name]["remediation"],
        }

    def list_patterns(self) -> list[str]:
        """Get list of all available pattern names."""
        return list(PATTERNS.keys())
