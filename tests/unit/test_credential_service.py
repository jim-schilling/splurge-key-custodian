"""Unit tests for the CredentialService module."""

import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from splurge_key_custodian.services.credential_service import CredentialService
from splurge_key_custodian.exceptions import ValidationError, FileOperationError
from splurge_key_custodian.models import CredentialFile
from splurge_key_custodian.constants import Constants
from tests.test_utility import TestDataHelper


class TestCredentialService(unittest.TestCase):
    """Unit tests for CredentialService class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = Mock()
        self.service = CredentialService(self.file_manager)
        self.master_password = TestDataHelper.create_test_master_password()
        self.test_credentials = TestDataHelper.create_test_credentials()
        self.test_meta_data = TestDataHelper.create_test_meta_data()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_credential_success(self):
        """Test successful credential creation."""
        # Mock file manager responses
        self.file_manager.list_credential_files.return_value = []
        self.file_manager.read_master_keys.return_value = TestDataHelper.create_master_keys_data()
        self.file_manager.save_credential_file.return_value = None

        with patch('splurge_key_custodian.services.credential_service.CryptoUtils') as mock_crypto:
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.generate_random_key.return_value = b"credential_key"
            mock_crypto.encrypt_key_with_master.return_value = (b"encrypted_key", b"salt")
            mock_crypto.encrypt_with_fernet.return_value = b"encrypted_data"

            key_id = self.service.create_credential(
                "Test Credential",
                self.test_credentials,
                self.master_password,
                meta_data=self.test_meta_data
            )

        # Verify key_id is returned
        self.assertIsInstance(key_id, str)
        self.assertGreater(len(key_id), 0)

        # Verify file manager was called correctly
        self.file_manager.save_credential_file.assert_called_once()
        call_args = self.file_manager.save_credential_file.call_args[0]
        self.assertEqual(call_args[0], key_id)
        self.assertIsInstance(call_args[1], CredentialFile)

    def test_create_credential_duplicate_name(self):
        """Test credential creation with duplicate name."""
        # Mock existing credential with same name
        existing_credential = TestDataHelper.create_test_credential_file(
            name="Test Credential",
            key_id="existing-id"
        )
        
        self.file_manager.list_credential_files.return_value = ["existing-id"]
        self.file_manager.read_credential_file.return_value = existing_credential

        with self.assertRaises(ValidationError) as cm:
            self.service.create_credential(
                "Test Credential",
                self.test_credentials,
                self.master_password
            )

        self.assertIn("already exists", str(cm.exception))

    def test_create_credential_none_name(self):
        """Test credential creation with None name."""
        with self.assertRaises(ValidationError) as cm:
            self.service.create_credential(
                None,
                self.test_credentials,
                self.master_password
            )

        self.assertIn("Credential name cannot be None", str(cm.exception))

    def test_create_credential_empty_name(self):
        """Test credential creation with empty name."""
        with self.assertRaises(ValidationError) as cm:
            self.service.create_credential(
                "",
                self.test_credentials,
                self.master_password
            )

        self.assertIn("Credential name cannot be empty", str(cm.exception))

    def test_create_credential_none_credentials(self):
        """Test credential creation with None credentials."""
        with self.assertRaises(ValidationError) as cm:
            self.service.create_credential(
                "Test Credential",
                None,
                self.master_password
            )

        self.assertIn("Credentials cannot be None", str(cm.exception))

    def test_create_credential_empty_credentials(self):
        """Test credential creation with empty credentials."""
        with self.assertRaises(ValidationError) as cm:
            self.service.create_credential(
                "Test Credential",
                {},
                self.master_password
            )

        self.assertIn("Credentials cannot be empty", str(cm.exception))

    def test_create_credential_no_master_key(self):
        """Test credential creation when no master key exists."""
        self.file_manager.list_credential_files.return_value = []
        self.file_manager.read_master_keys.return_value = None

        with self.assertRaises(FileOperationError) as cm:
            self.service.create_credential(
                "Test Credential",
                self.test_credentials,
                self.master_password
            )

        self.assertIn("No master key found", str(cm.exception))

    def test_read_credential_success(self):
        """Test successful credential reading."""
        credential_file = TestDataHelper.create_test_credential_file(
            name="Test Credential",
            key_id="test-id"
        )

        self.file_manager.read_credential_file.return_value = credential_file
        self.file_manager.read_master_keys.return_value = TestDataHelper.create_master_keys_data()

        with patch('splurge_key_custodian.services.credential_service.CryptoUtils') as mock_crypto:
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.decrypt_key_with_master.return_value = b"credential_key"
            mock_crypto.decrypt_with_fernet.return_value = json.dumps({
                "credentials": self.test_credentials,
                "meta_data": self.test_meta_data
            }).encode("utf-8")

            result = self.service.read_credential("test-id", self.master_password)

        self.assertEqual(result["credentials"], self.test_credentials)
        self.assertEqual(result["meta_data"], self.test_meta_data)

    def test_read_credential_not_found(self):
        """Test reading non-existent credential."""
        self.file_manager.read_credential_file.return_value = None

        with self.assertRaises(FileOperationError) as cm:
            self.service.read_credential("non-existent", self.master_password)

        self.assertIn("not found", str(cm.exception))

    def test_update_credential_success(self):
        """Test successful credential update."""
        existing_credential = TestDataHelper.create_test_credential_file(
            name="Test Credential",
            key_id="test-id"
        )

        self.file_manager.read_credential_file.return_value = existing_credential
        self.file_manager.read_master_keys.return_value = TestDataHelper.create_master_keys_data()
        self.file_manager.save_credential_file.return_value = None

        with patch('splurge_key_custodian.services.credential_service.CryptoUtils') as mock_crypto:
            mock_crypto.derive_key_from_password.return_value = b"derived_key"
            mock_crypto.generate_random_key.return_value = b"new_credential_key"
            mock_crypto.encrypt_key_with_master.return_value = (b"encrypted_key", b"key_salt")
            mock_crypto.encrypt_with_fernet.return_value = b"encrypted_data"

            self.service.update_credential(
                "test-id",
                self.master_password,
                name="Updated Credential",
                credentials=self.test_credentials,
                meta_data=self.test_meta_data
            )

        # Verify file manager was called to save updated credential
        self.file_manager.save_credential_file.assert_called_once()

    def test_delete_credential_success(self):
        """Test successful credential deletion."""
        self.file_manager.delete_credential_file.return_value = None

        self.service.delete_credential("test-id")

        self.file_manager.delete_credential_file.assert_called_once_with("test-id")

    def test_list_credentials(self):
        """Test listing credentials."""
        credential_files = [
            TestDataHelper.create_test_credential_file(
                name="Credential 1",
                key_id="id-1",
                created_at="2023-01-01T00:00:00Z"
            ),
            TestDataHelper.create_test_credential_file(
                name="Credential 2", 
                key_id="id-2",
                created_at="2023-01-02T00:00:00Z"
            )
        ]

        self.file_manager.list_credential_files.return_value = ["id-1", "id-2"]
        self.file_manager.read_credential_file.side_effect = credential_files

        result = self.service.list_credentials()

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "Credential 1")
        self.assertEqual(result[1]["name"], "Credential 2")

    def test_find_credential_by_name(self):
        """Test finding credential by name."""
        target_credential = TestDataHelper.create_test_credential_file(
            name="Target Credential",
            key_id="target-id"
        )

        self.file_manager.list_credential_files.return_value = ["target-id"]
        self.file_manager.read_credential_file.return_value = target_credential

        result = self.service.find_credential_by_name("Target Credential")

        self.assertEqual(result["key_id"], "target-id")
        self.assertEqual(result["name"], "Target Credential")

    def test_find_credential_by_name_not_found(self):
        """Test finding non-existent credential by name."""
        self.file_manager.list_credential_files.return_value = []
        self.file_manager.read_credential_file.return_value = None

        result = self.service.find_credential_by_name("Non-existent")

        self.assertIsNone(result)
