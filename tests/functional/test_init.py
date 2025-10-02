"""Tests for the __init__.py module."""

from unittest.mock import Mock, patch

import pytest
from splurge_key_custodian import (
    Base58,
    EncryptionError,
    FileOperationError,
    KeyCustodian,
    KeyCustodianError,
    KeyNotFoundError,
    KeyRotationError,
    MasterKeyError,
    ValidationError,
    __version__,
)


class TestInit:
    """Test cases for the __init__.py module."""

    def test_imports(self):
        """Test that all expected classes and functions can be imported."""
        # Test that KeyCustodian can be imported
        assert KeyCustodian is not None

        # Test that all exceptions can be imported
        assert KeyCustodianError is not None
        assert KeyNotFoundError is not None
        assert KeyRotationError is not None
        assert FileOperationError is not None
        assert EncryptionError is not None
        assert ValidationError is not None
        assert MasterKeyError is not None

        # Test that Base58 can be imported
        assert Base58 is not None

        # Test that __version__ is available
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_version_importlib_metadata(self):
        """Test version retrieval using importlib.metadata."""
        with patch("importlib.metadata.version") as mock_version:
            mock_version.return_value = "1.2.3"

            # Re-import to test the importlib.metadata path
            import importlib
            import sys

            if "splurge_key_custodian" in sys.modules:
                del sys.modules["splurge_key_custodian"]

            from splurge_key_custodian import __version__ as version

            assert version == "1.2.3"
            mock_version.assert_called_once_with("splurge-key-custodian")

    def test_version_fallback_when_importlib_metadata_unavailable(self):
        """Test version retrieval fallback when importlib.metadata is not available."""
        with patch(
            "importlib.metadata.version",
            side_effect=ImportError("No module named 'importlib.metadata'"),
        ):
            # Re-import to test the fallback path
            import importlib
            import sys

            if "splurge_key_custodian" in sys.modules:
                del sys.modules["splurge_key_custodian"]

            from splurge_key_custodian import __version__ as version

            assert version == "unknown"

    def test_all_list(self):
        """Test that __all__ contains all expected exports."""
        from splurge_key_custodian import __all__

        expected_exports = [
            "KeyCustodian",
            "KeyCustodianError",
            "KeyNotFoundError",
            "KeyRotationError",
            "FileOperationError",
            "EncryptionError",
            "ValidationError",
            "MasterKeyError",
            "Base58",
        ]

        for export in expected_exports:
            assert export in __all__

        # Check that __all__ doesn't contain unexpected items
        assert len(__all__) == len(expected_exports)
