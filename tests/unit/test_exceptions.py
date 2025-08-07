"""Tests for the exceptions module."""

import pickle
import unittest

from splurge_key_custodian.exceptions import (
    KeyCustodianError,
    ValidationError,
    FileOperationError,
    EncryptionError,
    KeyNotFoundError,
    KeyRotationError,
    MasterKeyError,
)


class TestExceptions(unittest.TestCase):
    """Test cases for the exceptions module."""

    def test_key_custodian_error(self):
        """Test KeyCustodianError exception."""
        error = KeyCustodianError("Test error message")
        
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "Test error message")

    def test_validation_error(self):
        """Test ValidationError exception."""
        error = ValidationError("Validation failed")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "Validation failed")

    def test_file_operation_error(self):
        """Test FileOperationError exception."""
        error = FileOperationError("File operation failed")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "File operation failed")

    def test_encryption_error(self):
        """Test EncryptionError exception."""
        error = EncryptionError("Encryption failed")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "Encryption failed")

    def test_key_not_found_error(self):
        """Test KeyNotFoundError exception."""
        error = KeyNotFoundError("Key not found")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "Key not found")

    def test_key_rotation_error(self):
        """Test KeyRotationError exception."""
        error = KeyRotationError("Key rotation failed")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "Key rotation failed")

    def test_master_key_error(self):
        """Test MasterKeyError exception."""
        error = MasterKeyError("Master key error")
        
        self.assertIsInstance(error, KeyCustodianError)
        self.assertEqual(str(error), "Master key error")

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from KeyCustodianError."""
        exceptions = [
            ValidationError,
            FileOperationError,
            EncryptionError,
            KeyNotFoundError,
            KeyRotationError,
            MasterKeyError,
        ]
        
        for exception_class in exceptions:
            with self.subTest(exception=exception_class.__name__):
                error = exception_class("Test message")
                self.assertIsInstance(error, KeyCustodianError)

    def test_exception_with_empty_message(self):
        """Test exceptions with empty messages."""
        error = ValidationError("")
        self.assertEqual(str(error), "")

    def test_exception_with_special_characters(self):
        """Test exceptions with special characters in messages."""
        message = "Error with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        error = ValidationError(message)
        self.assertEqual(str(error), message)

    def test_exception_with_unicode(self):
        """Test exceptions with unicode characters."""
        message = "Error with unicode: 你好世界 🌍"
        error = ValidationError(message)
        self.assertEqual(str(error), message)



    def test_exception_attributes(self):
        """Test that exceptions have the expected attributes."""
        error = ValidationError("Test message")
        
        # Should have message attribute
        self.assertEqual(error.args[0], "Test message")
        
        # Should be stringifiable
        self.assertEqual(str(error), "Test message")
        self.assertEqual(repr(error), "ValidationError('Test message')")



    def test_exception_usage_in_context(self):
        """Test exceptions in a realistic usage context."""
        def validate_input(value):
            if not value:
                raise ValidationError("Value cannot be empty")
            if len(value) < 3:
                raise ValidationError("Value must be at least 3 characters")
            return True
        
        # Test valid input
        self.assertTrue(validate_input("valid"))
        
        # Test empty input
        with self.assertRaises(ValidationError) as cm:
            validate_input("")
        self.assertEqual(str(cm.exception), "Value cannot be empty")
        
        # Test short input
        with self.assertRaises(ValidationError) as cm:
            validate_input("ab")
        self.assertEqual(str(cm.exception), "Value must be at least 3 characters")




if __name__ == "__main__":
    unittest.main() 