"""Splurge Key Custodian File - A secure file-based key management system.

This package provides a secure file-based key management system that stores
cryptographic keys in JSON files with atomic key rotation capabilities.
"""

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.exceptions import (
    EncryptionError,
    FileOperationError,
    KeyCustodianError,
    KeyNotFoundError,
    KeyRotationError,
    MasterKeyError,
    ValidationError,
)
from splurge_key_custodian.key_custodian import KeyCustodian

try:
    from importlib.metadata import version
    __version__ = version("splurge-key-custodian")
except ImportError:
    # Fallback for environments without importlib.metadata
    __version__ = "unknown"

__all__ = [
    "Base58",
    "EncryptionError",
    "FileOperationError",
    "KeyCustodian",
    "KeyCustodianError",
    "KeyNotFoundError",
    "KeyRotationError",
    "MasterKeyError",
    "ValidationError",
]
