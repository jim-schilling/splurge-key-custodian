"""Custom exceptions for the Splurge Key Custodian File system."""


class KeyCustodianError(Exception):
    """Base exception for all Key Custodian errors."""


class KeyNotFoundError(KeyCustodianError):
    """Raised when a requested key is not found."""


class KeyRotationError(KeyCustodianError):
    """Raised when key rotation fails."""


class RotationBackupError(KeyCustodianError):
    """Raised when rotation backup operations fail."""


class RotationRollbackError(KeyCustodianError):
    """Raised when rotation rollback operations fail."""


class RotationHistoryError(KeyCustodianError):
    """Raised when rotation history operations fail."""


class FileOperationError(KeyCustodianError):
    """Raised when file operations fail."""


class EncryptionError(KeyCustodianError):
    """Raised when encryption/decryption operations fail."""


class ValidationError(KeyCustodianError):
    """Raised when data validation fails."""


class MasterKeyError(KeyCustodianError):
    """Raised when master key operations fail."""
