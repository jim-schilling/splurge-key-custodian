"""Tests for the exceptions module."""

import pickle

import pytest
from splurge_key_custodian.exceptions import (
    EncryptionError,
    FileOperationError,
    KeyCustodianError,
    KeyNotFoundError,
    KeyRotationError,
    MasterKeyError,
    ValidationError,
)


class TestExceptions:
    """Test cases for the exceptions module."""

    def test_key_custodian_error(self):
        """Test KeyCustodianError exception."""
        error = KeyCustodianError("Test error message")

        assert isinstance(error, Exception)
        assert str(error) == "Test error message"

    def test_validation_error(self):
        """Test ValidationError exception."""
        error = ValidationError("Validation failed")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "Validation failed"

    def test_file_operation_error(self):
        """Test FileOperationError exception."""
        error = FileOperationError("File operation failed")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "File operation failed"

    def test_encryption_error(self):
        """Test EncryptionError exception."""
        error = EncryptionError("Encryption failed")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "Encryption failed"

    def test_key_not_found_error(self):
        """Test KeyNotFoundError exception."""
        error = KeyNotFoundError("Key not found")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "Key not found"

    def test_key_rotation_error(self):
        """Test KeyRotationError exception."""
        error = KeyRotationError("Key rotation failed")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "Key rotation failed"

    def test_master_key_error(self):
        """Test MasterKeyError exception."""
        error = MasterKeyError("Master key error")

        assert isinstance(error, KeyCustodianError)
        assert str(error) == "Master key error"

    @pytest.mark.parametrize(
        "exception_class",
        [
            ValidationError,
            FileOperationError,
            EncryptionError,
            KeyNotFoundError,
            KeyRotationError,
            MasterKeyError,
        ],
        ids=["row_0", "row_1", "row_2", "row_3", "row_4", "row_5"],
    )
    def test_exception_inheritance(self, exception_class):
        """Test that all exceptions inherit from KeyCustodianError."""
        error = exception_class("Test message")
        assert isinstance(error, KeyCustodianError)

    def test_exception_with_empty_message(self):
        """Test exceptions with empty messages."""
        error = ValidationError("")
        assert str(error) == ""

    def test_exception_with_special_characters(self):
        """Test exceptions with special characters in messages."""
        message = "Error with special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        error = ValidationError(message)
        assert str(error) == message

    def test_exception_with_unicode(self):
        """Test exceptions with unicode characters."""
        message = "Error with unicode: 你好世界 🌍"
        error = ValidationError(message)
        assert str(error) == message

    def test_exception_attributes(self):
        """Test that exceptions have the expected attributes."""
        error = ValidationError("Test message")

        # Should have message attribute
        assert error.args[0] == "Test message"

        # Should be stringifiable
        assert str(error) == "Test message"
        assert repr(error) == "ValidationError('Test message')"

    def test_exception_usage_in_context(self):
        """Test exceptions in a realistic usage context."""

        def validate_input(value):
            if not value:
                raise ValidationError("Value cannot be empty")
            if len(value) < 3:
                raise ValidationError("Value must be at least 3 characters")
            return True

        # Test valid input
        assert validate_input("valid")

        # Test empty input
        with pytest.raises(ValidationError) as cm:
            validate_input("")
        assert str(cm.value) == "Value cannot be empty"

        # Test short input
        with pytest.raises(ValidationError) as cm:
            validate_input("ab")
        assert str(cm.value) == "Value must be at least 3 characters"
