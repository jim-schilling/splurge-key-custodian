"""Tests for the validation_utils module."""

import unittest

from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import ValidationError
from splurge_key_custodian.validation_utils import validate_master_password_complexity


class TestValidationUtils(unittest.TestCase):
    """Test cases for validation utilities."""

    def test_validate_master_password_complexity_valid(self):
        """Test password validation with valid password."""
        valid_password = "MySecurePassword123!@#ThisIsLongEnough"
        # Should not raise an exception
        validate_master_password_complexity(valid_password)

    def test_validate_master_password_complexity_too_short(self):
        """Test password validation with password that's too short."""
        short_password = "Short1!"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(short_password)
        
        self.assertIn(f"at least {Constants.MIN_PASSWORD_LENGTH()} characters", str(cm.exception))

    def test_validate_master_password_complexity_too_long(self):
        """Test password validation with password that's too long."""
        # Create a password that exceeds the maximum length
        long_password = "A" * (Constants.MAX_PASSWORD_LENGTH() + 1) + "1!a"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(long_password)
        
        self.assertIn(f"less than {Constants.MAX_PASSWORD_LENGTH()} characters", str(cm.exception))

    def test_validate_master_password_complexity_missing_uppercase(self):
        """Test password validation with password missing uppercase letters."""
        password_without_upper = "mypassword123!@#thisislongenoughtomeetlength"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(password_without_upper)
        
        self.assertIn("uppercase letter", str(cm.exception))

    def test_validate_master_password_complexity_missing_lowercase(self):
        """Test password validation with password missing lowercase letters."""
        password_without_lower = "MYPASSWORD123!@#THISISLONGENOUGHTOMEETLENGTH"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(password_without_lower)
        
        self.assertIn("lowercase letter", str(cm.exception))

    def test_validate_master_password_complexity_missing_numeric(self):
        """Test password validation with password missing numeric characters."""
        password_without_numeric = "MyPassword!@#ThisIsLongEnoughToMeetLength"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(password_without_numeric)
        
        self.assertIn("numeric character", str(cm.exception))

    def test_validate_master_password_complexity_missing_special(self):
        """Test password validation with password missing special characters."""
        password_without_special = "MyPassword123ThisIsLongEnoughToMeetLength"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(password_without_special)
        
        self.assertIn("special character", str(cm.exception))

    def test_validate_master_password_complexity_multiple_issues(self):
        """Test password validation with multiple complexity issues."""
        bad_password = "short"
        
        with self.assertRaises(ValidationError) as cm:
            validate_master_password_complexity(bad_password)
        
        # Should fail on the first check (length), not proceed to others
        self.assertIn(f"at least {Constants.MIN_PASSWORD_LENGTH()} characters", str(cm.exception))

    def test_validate_master_password_complexity_edge_case_minimum_length(self):
        """Test password validation with exactly minimum length."""
        # Create a password with exactly the minimum length and all required character classes
        min_length = Constants.MIN_PASSWORD_LENGTH()
        edge_password = "A" + "a" + "1" + "!" + "x" * (min_length - 4)
        
        # Should not raise an exception
        validate_master_password_complexity(edge_password)

    def test_validate_master_password_complexity_edge_case_maximum_length(self):
        """Test password validation with exactly maximum length."""
        # Create a password with exactly the maximum length and all required character classes
        max_length = Constants.MAX_PASSWORD_LENGTH()
        edge_password = "A" + "a" + "1" + "!" + "x" * (max_length - 4)
        
        # Should not raise an exception
        validate_master_password_complexity(edge_password)

    def test_validate_master_password_complexity_uses_constants(self):
        """Test that validation uses the correct constants for character classes."""
        # Test with a password that uses the exact character sets from constants
        valid_chars = (
            Constants.ALLOWABLE_ALPHA_UPPER()[0] +  # One uppercase
            Constants.ALLOWABLE_ALPHA_LOWER()[0] +  # One lowercase  
            Constants.ALLOWABLE_DIGITS()[0] +       # One digit
            Constants.ALLOWABLE_SPECIAL()[0] + # One special
            "x" * (Constants.MIN_PASSWORD_LENGTH() - 4)  # Fill to minimum length
        )
        
        # Should not raise an exception
        validate_master_password_complexity(valid_chars)


if __name__ == '__main__':
    unittest.main()
