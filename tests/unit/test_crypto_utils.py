"""Tests for the crypto_utils module."""

import base64
import unittest
from unittest.mock import patch, MagicMock

from splurge_key_custodian.base58 import Base58, Base58ValidationError
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import EncryptionError
from splurge_key_custodian.exceptions import ValidationError


class TestCryptoUtils(unittest.TestCase):
    """Test cases for the CryptoUtils class."""

    def test_generate_random_key(self):
        """Test random key generation."""
        key = CryptoUtils.generate_random_key()
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), Constants.KEY_SIZE_BYTES())  # 256 bits = 32 bytes
        
        # Test that keys are different
        key2 = CryptoUtils.generate_random_key()
        self.assertNotEqual(key, key2)

    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        password = "test-password"
        salt = b"test-salt-32-bytes-long-for-testing"
        
        key = CryptoUtils.derive_key_from_password(password, salt)
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), Constants.KEY_SIZE_BYTES())  # 256 bits = 32 bytes
        
        # Same password and salt should produce same key
        key2 = CryptoUtils.derive_key_from_password(password, salt)
        self.assertEqual(key, key2)
        
        # Different salt should produce different key
        different_salt = b"different-salt-32-bytes-long-for-testing"
        key3 = CryptoUtils.derive_key_from_password(password, different_salt)
        self.assertNotEqual(key, key3)

    def test_derive_key_from_password_different_password(self):
        """Test that different passwords produce different keys."""
        salt = b"test-salt-32-bytes-long-for-testing"
        
        key1 = CryptoUtils.derive_key_from_password("password1", salt)
        key2 = CryptoUtils.derive_key_from_password("password2", salt)
        
        self.assertNotEqual(key1, key2)

    def test_encrypt_with_fernet(self):
        """Test Fernet encryption."""
        key = CryptoUtils.generate_random_key()
        data = b"test data to encrypt"
        
        encrypted = CryptoUtils.encrypt_with_fernet(key, data)
        
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, data)  # Should be encrypted
        
        # Should be able to decrypt
        decrypted = CryptoUtils.decrypt_with_fernet(key, encrypted)
        self.assertEqual(decrypted, data)

    def test_decrypt_with_fernet(self):
        """Test Fernet decryption."""
        key = CryptoUtils.generate_random_key()
        data = b"test data to encrypt"
        
        encrypted = CryptoUtils.encrypt_with_fernet(key, data)
        decrypted = CryptoUtils.decrypt_with_fernet(key, encrypted)
        
        self.assertEqual(decrypted, data)

    def test_decrypt_with_fernet_invalid_key(self):
        """Test Fernet decryption with invalid key."""
        key1 = CryptoUtils.generate_random_key()
        key2 = CryptoUtils.generate_random_key()
        data = b"test data to encrypt"
        
        encrypted = CryptoUtils.encrypt_with_fernet(key1, data)
        
        with self.assertRaises(EncryptionError):
            CryptoUtils.decrypt_with_fernet(key2, encrypted)

    def test_decrypt_with_fernet_invalid_data(self):
        """Test Fernet decryption with invalid data."""
        key = CryptoUtils.generate_random_key()
        invalid_data = b"invalid encrypted data"
        
        with self.assertRaises(EncryptionError):
            CryptoUtils.decrypt_with_fernet(key, invalid_data)

    def test_encrypt_key_with_master(self):
        """Test key encryption with master key."""
        master_key = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key)
        
        self.assertIsInstance(encrypted_key, bytes)
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), Constants.DEFAULT_SALT_SIZE())  # 64-byte salt
        self.assertNotEqual(encrypted_key, key_to_encrypt)  # Should be encrypted

    def test_encrypt_key_with_master_custom_salt(self):
        """Test key encryption with custom salt."""
        master_key = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        custom_salt = b"custom-salt-64-bytes-long-for-testing-purposes-only"
        
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key, custom_salt)
        
        self.assertEqual(salt, custom_salt)
        self.assertNotEqual(encrypted_key, key_to_encrypt)

    def test_decrypt_key_with_master(self):
        """Test key decryption with master key."""
        master_key = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key)
        decrypted_key = CryptoUtils.decrypt_key_with_master(encrypted_key, master_key, salt)
        
        self.assertEqual(decrypted_key, key_to_encrypt)

    def test_decrypt_key_with_master_invalid_master_key(self):
        """Test key decryption with invalid master key."""
        master_key1 = CryptoUtils.generate_random_key()
        master_key2 = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key1)
        
        with self.assertRaises(EncryptionError):
            CryptoUtils.decrypt_key_with_master(encrypted_key, master_key2, salt)

    def test_decrypt_key_with_master_salt_usage(self):
        """Test that the salt parameter is actually used in key derivation."""
        master_key = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        
        # Encrypt with one salt
        salt1 = b"first-salt-64-bytes-long-for-testing-purposes-only"
        encrypted_key1, _ = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key, salt1)
        
        # Encrypt with a different salt
        salt2 = b"second-salt-64-bytes-long-for-testing-purposes-only"
        encrypted_key2, _ = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key, salt2)
        
        # The encrypted keys should be different because different salts produce different derived keys
        self.assertNotEqual(encrypted_key1, encrypted_key2)
        
        # Both should decrypt correctly with their respective salts
        decrypted_key1 = CryptoUtils.decrypt_key_with_master(encrypted_key1, master_key, salt1)
        decrypted_key2 = CryptoUtils.decrypt_key_with_master(encrypted_key2, master_key, salt2)
        
        self.assertEqual(decrypted_key1, key_to_encrypt)
        self.assertEqual(decrypted_key2, key_to_encrypt)
        
        # Using the wrong salt should fail
        with self.assertRaises(EncryptionError):
            CryptoUtils.decrypt_key_with_master(encrypted_key1, master_key, salt2)
        
        with self.assertRaises(EncryptionError):
            CryptoUtils.decrypt_key_with_master(encrypted_key2, master_key, salt1)
      
    def test_encrypt_decrypt_roundtrip(self):
        """Test complete encrypt/decrypt roundtrip."""
        # Generate keys
        master_key = CryptoUtils.generate_random_key()
        key_to_encrypt = CryptoUtils.generate_random_key()
        
        # Encrypt
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(key_to_encrypt, master_key)
        
        # Decrypt
        decrypted_key = CryptoUtils.decrypt_key_with_master(encrypted_key, master_key, salt)
        
        # Verify
        self.assertEqual(decrypted_key, key_to_encrypt)

    def test_fernet_roundtrip(self):
        """Test complete Fernet encrypt/decrypt roundtrip."""
        key = CryptoUtils.generate_random_key()
        data = b"test data for fernet roundtrip"
        
        # Encrypt
        encrypted = CryptoUtils.encrypt_with_fernet(key, data)
        
        # Decrypt
        decrypted = CryptoUtils.decrypt_with_fernet(key, encrypted)
        
        # Verify
        self.assertEqual(decrypted, data)

    def test_key_derivation_consistency(self):
        """Test that key derivation is consistent."""
        password = "consistent-password"
        salt = b"consistent-salt-32-bytes-long-for-testing"
        
        key1 = CryptoUtils.derive_key_from_password(password, salt)
        key2 = CryptoUtils.derive_key_from_password(password, salt)
        key3 = CryptoUtils.derive_key_from_password(password, salt)
        
        self.assertEqual(key1, key2)
        self.assertEqual(key2, key3)

    def test_encryption_deterministic(self):
        """Test that encryption with same key produces different results (due to IV)."""
        key = CryptoUtils.generate_random_key()
        data = b"test data"
        
        encrypted1 = CryptoUtils.encrypt_with_fernet(key, data)
        encrypted2 = CryptoUtils.encrypt_with_fernet(key, data)
        
        # Should be different due to random IV
        self.assertNotEqual(encrypted1, encrypted2)
        
        # But both should decrypt to same data
        decrypted1 = CryptoUtils.decrypt_with_fernet(key, encrypted1)
        decrypted2 = CryptoUtils.decrypt_with_fernet(key, encrypted2)
        
        self.assertEqual(decrypted1, data)
        self.assertEqual(decrypted2, data)

    def test_derive_key_from_password_validation(self):
        """Test validation in key derivation."""
        # Test with empty password
        with self.assertRaises(ValidationError):
            CryptoUtils.derive_key_from_password("", b"test-salt-32-bytes-long-for-testing")
        
        # Test with None password
        with self.assertRaises(ValidationError):
            CryptoUtils.derive_key_from_password(None, b"test-salt-32-bytes-long-for-testing")
        
        # Test with salt too small
        with self.assertRaises(ValidationError):
            CryptoUtils.derive_key_from_password("password", b"small-salt")
        
        # Test with iterations too small
        with self.assertRaises(ValidationError):
            CryptoUtils.derive_key_from_password("password", b"test-salt-32-bytes-long-for-testing", iterations=Constants.MIN_ITERATIONS() - 1)
        
        # Test with valid parameters
        try:
            CryptoUtils.derive_key_from_password("password", b"test-salt-32-bytes-long-for-testing")
        except ValidationError:
            self.fail("Valid parameters should not raise ValidationError")

    def test_encrypt_with_fernet_validation(self):
        """Test validation in Fernet encryption."""
        # Test with wrong key size
        with self.assertRaises(ValidationError):
            CryptoUtils.encrypt_with_fernet(b"short-key", b"data")
        
        # Test with empty data
        key = CryptoUtils.generate_random_key()
        with self.assertRaises(ValidationError):
            CryptoUtils.encrypt_with_fernet(key, b"")
        
        # Test with None data
        with self.assertRaises(ValidationError):
            CryptoUtils.encrypt_with_fernet(key, None)

    def test_decrypt_with_fernet_validation(self):
        """Test validation in Fernet decryption."""
        # Test with wrong key size
        with self.assertRaises(ValidationError):
            CryptoUtils.decrypt_with_fernet(b"short-key", b"data")
        
        # Test with empty encrypted data
        key = CryptoUtils.generate_random_key()
        with self.assertRaises(ValidationError):
            CryptoUtils.decrypt_with_fernet(key, b"")
        
        # Test with None encrypted data
        with self.assertRaises(ValidationError):
            CryptoUtils.decrypt_with_fernet(key, None)

    def test_secure_zero(self):
        """Test secure zero functionality."""
        # Test with bytearray
        test_bytes = bytearray(b"secret data")
        CryptoUtils.secure_zero(test_bytes)
        
        # Test with string
        test_string = "secret string"
        CryptoUtils.secure_zero_string(test_string)
        
        # Test with empty data
        CryptoUtils.secure_zero(bytearray(b""))
        CryptoUtils.secure_zero_string("")
        
        # Test with None (should not raise)
        CryptoUtils.secure_zero(None)
        CryptoUtils.secure_zero_string(None)


if __name__ == "__main__":
    unittest.main() 