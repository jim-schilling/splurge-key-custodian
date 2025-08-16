"""Validation utilities for the key custodian package."""

from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import ValidationError


def validate_master_password_complexity(password: str) -> None:
    """Validate master password complexity requirements.

    Enforces minimum length, maximum length, and character class requirements.
    This function provides consistent password validation across the codebase.

    Args:
        password: Master password to validate

    Raises:
        ValidationError: If password doesn't meet complexity requirements
    """
    if len(password) < Constants.MIN_PASSWORD_LENGTH():
        raise ValidationError(
            f"Master password must be at least {Constants.MIN_PASSWORD_LENGTH()} characters long"
        )
    
    if len(password) > Constants.MAX_PASSWORD_LENGTH():
        raise ValidationError(
            f"Master password must be less than {Constants.MAX_PASSWORD_LENGTH()} characters long"
        )
    
    if not any(c in Constants.ALLOWABLE_ALPHA_UPPER() for c in password):
        raise ValidationError(
            "Master password must contain at least one uppercase letter"
        )
    
    if not any(c in Constants.ALLOWABLE_ALPHA_LOWER() for c in password):
        raise ValidationError(
            "Master password must contain at least one lowercase letter"
        )
    
    if not any(c in Constants.ALLOWABLE_DIGITS() for c in password):
        raise ValidationError(
            "Master password must contain at least one numeric character"
        )
    
    if not any(c in Constants.ALLOWABLE_SPECIAL() for c in password):
        raise ValidationError(
            "Master password must contain at least one special character"
        )


def validate_credential_name(name: str) -> None:
    """Validate credential name requirements.

    Enforces basic requirements for credential names.

    Args:
        name: Credential name to validate

    Raises:
        ValidationError: If name doesn't meet requirements
    """
    if name is None:
        raise ValidationError("Credential name cannot be None")

    if name == "":
        raise ValidationError("Credential name cannot be empty")

    if name.strip() == "":
        raise ValidationError("Credential name cannot contain only whitespace")

    # Check for reasonable length limits
    if len(name) > 1000:  # Arbitrary reasonable limit
        raise ValidationError("Credential name is too long (maximum 1000 characters)")

    # Check for null bytes or other problematic characters
    if '\x00' in name:
        raise ValidationError("Credential name cannot contain null bytes")
