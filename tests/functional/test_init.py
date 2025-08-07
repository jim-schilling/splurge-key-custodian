"""Tests for the __init__.py module."""

import unittest
from unittest.mock import patch, Mock

from splurge_key_custodian import (
    KeyCustodian,
    KeyCustodianError,
    KeyNotFoundError,
    KeyRotationError,
    FileOperationError,
    EncryptionError,
    ValidationError,
    MasterKeyError,
    Base58,
    __version__,
)


class TestInit(unittest.TestCase):
    """Test cases for the __init__.py module."""

    def test_imports(self):
        """Test that all expected classes and functions can be imported."""
        # Test that KeyCustodian can be imported
        self.assertIsNotNone(KeyCustodian)
        
        # Test that all exceptions can be imported
        self.assertIsNotNone(KeyCustodianError)
        self.assertIsNotNone(KeyNotFoundError)
        self.assertIsNotNone(KeyRotationError)
        self.assertIsNotNone(FileOperationError)
        self.assertIsNotNone(EncryptionError)
        self.assertIsNotNone(ValidationError)
        self.assertIsNotNone(MasterKeyError)
        
        # Test that Base58 can be imported
        self.assertIsNotNone(Base58)
        
        # Test that __version__ is available
        self.assertIsNotNone(__version__)
        self.assertIsInstance(__version__, str)

    def test_version_importlib_metadata(self):
        """Test version retrieval using importlib.metadata."""
        with patch('importlib.metadata.version') as mock_version:
            mock_version.return_value = "1.2.3"
            
            # Re-import to test the importlib.metadata path
            import importlib
            import sys
            if 'splurge_key_custodian' in sys.modules:
                del sys.modules['splurge_key_custodian']
            
            from splurge_key_custodian import __version__ as version
            self.assertEqual(version, "1.2.3")
            mock_version.assert_called_once_with("splurge-key-custodian")

    def test_version_fallback_when_importlib_metadata_unavailable(self):
        """Test version retrieval fallback when importlib.metadata is not available."""
        with patch('importlib.metadata.version', side_effect=ImportError("No module named 'importlib.metadata'")):
            # Re-import to test the fallback path
            import importlib
            import sys
            if 'splurge_key_custodian' in sys.modules:
                del sys.modules['splurge_key_custodian']
            
            from splurge_key_custodian import __version__ as version
            self.assertEqual(version, "unknown")

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
            self.assertIn(export, __all__)
        
        # Check that __all__ doesn't contain unexpected items
        self.assertEqual(len(__all__), len(expected_exports))


if __name__ == "__main__":
    unittest.main() 