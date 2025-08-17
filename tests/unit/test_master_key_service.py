"""Unit tests for the MasterKeyService module."""

import tempfile
import unittest
from unittest.mock import Mock, patch

from splurge_key_custodian.services.master_key_service import MasterKeyService
from splurge_key_custodian.exceptions import ValidationError, FileOperationError
from splurge_key_custodian.models import MasterKey
from splurge_key_custodian.constants import Constants
from tests.test_utility import TestDataHelper


class TestMasterKeyService(unittest.TestCase):
    """Unit tests for MasterKeyService class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = Mock()
        self.service = MasterKeyService(self.file_manager)
        self.master_password = TestDataHelper.create_test_master_password()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialize_master_key_success(self):
        """Test successful master key initialization."""
        self.file_manager.read_master_keys.return_value = None
        self.file_manager.save_master_keys.return_value = None

        with patch('splurge_key_custodian.services.master_key_service.CryptoUtils') as mock_crypto:
            mock_crypto.generate_salt.return_value = b"test_salt"
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.encrypt_with_fernet.return_value = b"encrypted_data"

            master_key = self.service.initialize_master_key(
                self.master_password,
                iterations=Constants.MIN_ITERATIONS()
            )

        # Verify master key was created correctly
        self.assertIsInstance(master_key, MasterKey)
        self.assertIsNotNone(master_key.key_id)
        self.assertIsNotNone(master_key.salt)
        self.assertIsNotNone(master_key.credentials)

        # Verify file manager was called to save master keys
        self.file_manager.save_master_keys.assert_called_once()

    def test_initialize_master_key_none_password(self):
        """Test master key initialization with None password."""
        with self.assertRaises(TypeError) as cm:
            self.service.initialize_master_key(None)

        self.assertIn("NoneType", str(cm.exception))

    def test_initialize_master_key_empty_password(self):
        """Test master key initialization with empty password."""
        with self.assertRaises(ValidationError) as cm:
            self.service.initialize_master_key("")

        self.assertIn("at least", str(cm.exception))

    def test_initialize_master_key_already_exists(self):
        """Test master key initialization when one already exists."""
        self.file_manager.read_master_keys.return_value = {"master_keys": [{"key_id": "existing"}]}

        with self.assertRaises(ValidationError) as cm:
            self.service.initialize_master_key(self.master_password)

        self.assertIn("already exists", str(cm.exception))

    def test_load_master_key_success(self):
        """Test successful master key loading."""
        master_key_data = TestDataHelper.create_master_keys_data()

        self.file_manager.read_master_keys.return_value = master_key_data

        master_key = self.service.load_master_key()

        # Verify master key was loaded correctly
        self.assertIsInstance(master_key, MasterKey)
        self.assertEqual(master_key.key_id, "test-key-id")
        self.assertEqual(master_key.salt, "2NEpo7TZRRrLZSi2U")
        self.assertEqual(master_key.iterations, Constants.MIN_ITERATIONS())

    def test_load_master_key_not_found(self):
        """Test master key loading when no master key exists."""
        self.file_manager.read_master_keys.return_value = None

        result = self.service.load_master_key()

        # Should return None when no master key exists
        self.assertIsNone(result)

    def test_load_master_key_empty_list(self):
        """Test master key loading when master keys list is empty."""
        self.file_manager.read_master_keys.return_value = {"master_keys": []}

        result = self.service.load_master_key()

        # Should return None when master keys list is empty
        self.assertIsNone(result)

    def test_validate_master_password_success(self):
        """Test successful master password validation."""
        master_key = TestDataHelper.create_test_master_key()

        # Mock the load_master_key method to return our test master key
        self.service.load_master_key = lambda: master_key

        with patch('splurge_key_custodian.services.master_key_service.CryptoUtils') as mock_crypto:
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.decrypt_with_fernet.return_value = b"\x00"

            is_valid = self.service.validate_master_password(self.master_password)

        self.assertTrue(is_valid)

    def test_validate_master_password_failure(self):
        """Test master password validation failure."""
        master_key = TestDataHelper.create_test_master_key()

        # Mock the load_master_key method to return our test master key
        self.service.load_master_key = lambda: master_key

        with patch('splurge_key_custodian.services.master_key_service.CryptoUtils') as mock_crypto:
            # Simulate key derivation failure
            mock_crypto.derive_key_from_password.side_effect = Exception("Invalid password")

            is_valid = self.service.validate_master_password("wrong_password")

        self.assertFalse(is_valid)

    def test_change_master_password_success(self):
        """Test successful master password change."""
        old_master_key = TestDataHelper.create_test_master_key(key_id="old-key-id")

        new_password = "NewMasterPassword123!@#ComplexityRequired"

        # Mock the load_master_key method to return our test master key
        self.service.load_master_key = lambda: old_master_key
        # Mock the validate_master_password method to return True
        self.service.validate_master_password = lambda password, iterations=None: True

        self.file_manager.save_master_keys.return_value = None

        with patch('splurge_key_custodian.services.master_key_service.CryptoUtils') as mock_crypto:
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.generate_salt.return_value = b"new_salt"
            mock_crypto.encrypt_with_fernet.return_value = b"encrypted_data"

            new_master_key = self.service.change_master_password(
                self.master_password,
                new_password
            )

        # Verify new master key was created
        self.assertIsInstance(new_master_key, MasterKey)
        self.assertNotEqual(new_master_key.key_id, old_master_key.key_id)
        self.assertNotEqual(new_master_key.salt, old_master_key.salt)

        # Verify file manager was called to save new master keys
        self.file_manager.save_master_keys.assert_called_once()

    def test_change_master_password_invalid_old_password(self):
        """Test master password change with invalid old password."""
        old_master_key = TestDataHelper.create_test_master_key(key_id="old-key-id")

        self.file_manager.read_master_keys.return_value = {
            "master_keys": [old_master_key.to_dict()]
        }

        with patch('splurge_key_custodian.services.master_key_service.CryptoUtils') as mock_crypto:
            # Simulate key derivation failure for old password
            mock_crypto.derive_key_from_password.side_effect = Exception("Invalid password")

            with self.assertRaises(ValidationError) as cm:
                self.service.change_master_password(
                    "WrongOldPassword123!@#ComplexityRequired",
                    "NewPassword123!@#ComplexityRequired"
                )

        self.assertIn("Invalid", str(cm.exception))

    def test_get_master_key_info(self):
        """Test getting master key information."""
        master_key = TestDataHelper.create_test_master_key()

        # Mock the load_master_key method to return our test master key
        self.service.load_master_key = lambda: master_key

        info = self.service.get_master_key_info()

        # Verify info contains expected fields
        self.assertIn("key_id", info)
        self.assertIn("salt_length", info)
        self.assertIn("credentials_length", info)
        self.assertEqual(info["key_id"], "test-key-id")

    def test_get_master_key_info_not_found(self):
        """Test getting master key information when no master key exists."""
        # Mock the load_master_key method to return None
        self.service.load_master_key = lambda: None

        info = self.service.get_master_key_info()

        # Should return None when no master key exists
        self.assertIsNone(info)
