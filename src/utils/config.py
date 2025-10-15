"""Configuration management using Pydantic."""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings

from .defaults import (
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_MIN_TOKEN_LENGTH,
    DEFAULT_HISTORY_DEPTH,
    DEFAULT_CONFIDENCE_THRESHOLD,
    DEFAULT_EXCLUDE_PATTERNS,
    DEFAULT_DATA_DIR,
    DEFAULT_REPORTS_DIR,
)


class WebhookConfig(BaseModel):
    """Webhook configuration."""

    slack: Optional[str] = Field(default=None, description="Slack webhook URL")
    discord: Optional[str] = Field(default=None, description="Discord webhook URL")

    @field_validator("slack", "discord")
    @classmethod
    def validate_webhook_url(cls, v: Optional[str]) -> Optional[str]:
        """Validate webhook URL format."""
        if v is None:
            return v
        if not v.startswith("https://"):
            raise ValueError("Webhook URL must start with https://")
        return v


class NotificationConfig(BaseModel):
    """Notification configuration."""

    enabled: bool = Field(default=True, description="Enable/disable notifications")
    channels: list[str] = Field(
        default_factory=lambda: ["slack", "discord"],
        description="Enabled notification channels"
    )

    @field_validator("channels")
    @classmethod
    def validate_channels(cls, v: list[str]) -> list[str]:
        """Validate channel names."""
        valid_channels = {"slack", "discord", "email"}
        for channel in v:
            if channel not in valid_channels:
                raise ValueError(
                    f"Invalid channel '{channel}'. "
                    f"Must be one of: {', '.join(valid_channels)}"
                )
        return v


class ScanConfig(BaseModel):
    """Scanning configuration."""

    entropy_threshold: float = Field(
        default=DEFAULT_ENTROPY_THRESHOLD,
        ge=0.0,
        le=8.0,
        description="Shannon entropy threshold for detection"
    )
    min_token_length: int = Field(
        default=DEFAULT_MIN_TOKEN_LENGTH,
        ge=1,
        description="Minimum token length for entropy checking"
    )
    confidence_threshold: float = Field(
        default=DEFAULT_CONFIDENCE_THRESHOLD,
        ge=0.0,
        le=1.0,
        description="Minimum confidence level for reporting findings"
    )
    history_depth: int = Field(
        default=DEFAULT_HISTORY_DEPTH,
        ge=1,
        description="Number of commits to scan in history"
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: DEFAULT_EXCLUDE_PATTERNS.copy(),
        description="File patterns to exclude from scanning"
    )


class Settings(BaseModel):
    """Main application settings."""

    # Scanning configuration
    scan: ScanConfig = Field(default_factory=ScanConfig)

    # Webhooks configuration
    webhooks: WebhookConfig = Field(default_factory=WebhookConfig)

    # Notifications configuration
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    # Paths
    data_dir: str = Field(default=DEFAULT_DATA_DIR, description="Data directory path")
    reports_dir: str = Field(default=DEFAULT_REPORTS_DIR, description="Reports directory path")

    # GitHub integration (optional)
    github_token: Optional[str] = Field(
        default=None,
        description="GitHub Personal Access Token for PR creation"
    )
    github_owner: Optional[str] = Field(
        default=None,
        description="GitHub repository owner"
    )
    github_repo: Optional[str] = Field(
        default=None,
        description="GitHub repository name"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "scan": {
                    "entropy_threshold": 4.0,
                    "min_token_length": 20,
                    "confidence_threshold": 0.7,
                    "history_depth": 100,
                    "exclude_patterns": ["node_modules/**", ".venv/**"]
                },
                "webhooks": {
                    "slack": "https://hooks.slack.com/services/xxx",
                    "discord": "https://discord.com/api/webhooks/xxx"
                },
                "notifications": {
                    "enabled": True,
                    "channels": ["slack"]
                }
            }
        }
    }

    def ensure_directories(self) -> None:
        """Ensure data and reports directories exist."""
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)

    @property
    def settings_file(self) -> Path:
        """Get path to settings file."""
        return Path(self.data_dir) / "settings.json"

    @property
    def findings_file(self) -> Path:
        """Get path to findings file."""
        return Path(self.data_dir) / "findings.json"

    @property
    def migration_log_file(self) -> Path:
        """Get path to migration log file."""
        return Path(self.data_dir) / "migration_log.json"

    @property
    def override_log_file(self) -> Path:
        """Get path to override log file."""
        return Path(self.data_dir) / "override_log.json"


class AppConfig(BaseSettings):
    """Application-level configuration from environment variables."""

    # Environment
    env: str = Field(default="development", description="Environment name")
    debug: bool = Field(default=False, description="Debug mode")

    # Server configuration
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")

    # Replit-specific
    replit_db_url: Optional[str] = Field(
        default=None,
        alias="REPLIT_DB_URL",
        description="Replit database URL"
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


def load_settings(settings_file: Optional[Path] = None) -> Settings:
    """
    Load settings from file or create default settings.

    Args:
        settings_file: Path to settings file (default: data/settings.json)

    Returns:
        Settings object
    """
    from .storage import load_json, save_json

    if settings_file is None:
        settings_file = Path(DEFAULT_DATA_DIR) / "settings.json"

    # Ensure parent directory exists
    settings_file.parent.mkdir(parents=True, exist_ok=True)

    if settings_file.exists():
        # Load existing settings
        data = load_json(settings_file)
        settings = Settings(**data)
    else:
        # Create default settings
        settings = Settings()
        settings.ensure_directories()
        # Save default settings
        save_json(settings_file, settings.model_dump())

    return settings


def save_settings(settings: Settings, settings_file: Optional[Path] = None) -> None:
    """
    Save settings to file.

    Args:
        settings: Settings object to save
        settings_file: Path to settings file (default: data/settings.json)
    """
    from .storage import save_json

    if settings_file is None:
        settings_file = Path(DEFAULT_DATA_DIR) / "settings.json"

    # Ensure directories exist
    settings.ensure_directories()

    # Save settings
    save_json(settings_file, settings.model_dump())
