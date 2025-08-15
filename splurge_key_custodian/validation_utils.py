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
    
    if not any(c in CryptoUtils.B58_ALPHA_UPPER() for c in password):
        raise ValidationError(
            "Master password must contain at least one uppercase letter"
        )
    
    if not any(c in CryptoUtils.B58_ALPHA_LOWER() for c in password):
        raise ValidationError(
            "Master password must contain at least one lowercase letter"
        )
    
    if not any(c in CryptoUtils.B58_DIGIT() for c in password):
        raise ValidationError(
            "Master password must contain at least one numeric character"
        )
    
    if not any(c in CryptoUtils.ALLOWABLE_SPECIAL() for c in password):
        raise ValidationError(
            "Master password must contain at least one special character"
        )
