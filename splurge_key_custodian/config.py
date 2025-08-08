"""Configuration management for the Splurge Key Custodian File system."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class KeyCustodianConfig:
    """Configuration for KeyCustodian instances."""

    # Security settings
    max_login_attempts: int = 5
    lockout_duration: int = 300  # seconds
    failed_attempt_delay: int = 1  # seconds
    min_password_length: int = 32
    min_iterations: int = 500000
    default_iterations: int = 1000000

    # Performance settings
    enable_caching: bool = True
    cache_size_limit: int = 1000
    cache_ttl: int = 3600  # seconds

    # File settings
    atomic_write_enabled: bool = True
    backup_enabled: bool = True
    secure_permissions: bool = True

    # Validation settings
    max_input_length: int = 1000
    allowed_control_chars: set[str] = None

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.allowed_control_chars is None:
            self.allowed_control_chars = {'\t', '\n', '\r'}

        # Validate security settings
        if self.max_login_attempts < 1:
            raise ValueError("max_login_attempts must be at least 1")
        if self.lockout_duration < 1:
            raise ValueError("lockout_duration must be at least 1 second")
        if self.min_password_length < 8:
            raise ValueError("min_password_length must be at least 8")
        if self.min_iterations < 100000:
            raise ValueError("min_iterations must be at least 100,000")
        if self.default_iterations < self.min_iterations:
            raise ValueError("default_iterations must be at least min_iterations")

        # Validate performance settings
        if self.cache_size_limit < 1:
            raise ValueError("cache_size_limit must be at least 1")
        if self.cache_ttl < 0:
            raise ValueError("cache_ttl must be non-negative")

        # Validate file settings
        if self.max_input_length < 1:
            raise ValueError("max_input_length must be at least 1")


# Default configuration instance
DEFAULT_CONFIG = KeyCustodianConfig()
