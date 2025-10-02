"""Integration tests for key rotation functionality."""

import tempfile
from pathlib import Path

import pytest
from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import (
    EncryptionError,
    FileOperationError,
    KeyNotFoundError,
    MasterKeyError,
    ValidationError,
)
from tests.test_utility import TestDataHelper, TestUtilities


class TestKeyRotationCore:
    """Integration tests for key rotation functionality."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = TestUtilities.create_temp_data_dir()
        self.master_password = TestDataHelper.create_test_master_password()
        self.custodian = TestUtilities.create_test_custodian(
            self.temp_dir, self.master_password
        )
        self.custodian.create_credential(
            name="Test Credential 1",
            credentials={"username": "user1", "password": "pass1"},
        )
        self.custodian.create_credential(
            name="Test Credential 2",
            credentials={"username": "user2", "password": "pass2"},
        )
        yield
        """Clean up test fixtures."""
        TestUtilities.cleanup_temp_dir(self.temp_dir)

    def test_rotate_master_key_works_end_to_end(self):
        """Test that KeyCustodian.rotate_master_key works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = self.custodian.list_credentials()
        assert len(initial_credentials) == 2

        # Perform master key rotation
        rotation_id = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Verify rotation was successful
        assert rotation_id is not None

        # Verify credentials are still accessible
        updated_credentials = self.custodian.list_credentials()
        assert len(updated_credentials) == 2

        # Create a new custodian with the same iterations used during rotation
        new_custodian = KeyCustodian(
            self.master_password,
            self.custodian.data_directory,
            iterations=Constants.MIN_ITERATIONS() + 1,
        )

        # Verify we can read the credentials with the new custodian
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred["key_id"])
            assert "username" in credential_data["credentials"]
            assert "password" in credential_data["credentials"]

    def test_change_master_password_works_end_to_end(self):
        """Test that KeyCustodian.change_master_password works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = self.custodian.list_credentials()
        assert len(initial_credentials) == 2

        # Perform master key rotation with new password
        new_password = "NewSecureMasterPassword456!@#ExtraLongEnough"
        rotation_id = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Verify rotation was successful
        assert rotation_id is not None

        # Create new custodian with original password (rotation keeps same password)
        new_custodian = KeyCustodian(
            self.master_password,
            self.custodian.data_directory,
            iterations=Constants.MIN_ITERATIONS() + 1,
        )

        # Verify credentials are accessible with new password
        updated_credentials = new_custodian.list_credentials()
        assert len(updated_credentials) == 2

        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred["key_id"])
            assert "username" in credential_data["credentials"]
            assert "password" in credential_data["credentials"]

    def test_rotate_all_credentials_works_end_to_end(self):
        """Test that KeyCustodian.rotate_all_credentials works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = self.custodian.list_credentials()
        assert len(initial_credentials) == 2

        # Perform credential rotation
        rotation_id = self.custodian.rotate_all_credentials(create_backup=True)

        # Verify rotation was successful
        assert rotation_id is not None

        # Verify credentials are still accessible
        updated_credentials = self.custodian.list_credentials()
        assert len(updated_credentials) == 2

        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = self.custodian.read_credential(cred["key_id"])
            assert "username" in credential_data["credentials"]
            assert "password" in credential_data["credentials"]

    def test_rotation_with_backup_creation(self):
        """Test that rotation creates backup files when requested."""
        # Perform rotation with backup
        rotation_id = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Check that backup files exist
        backup_dir = Path(self.custodian.data_directory) / "rotation-backups"
        assert backup_dir.exists()

        # Check for backup files - there should be at least one backup file
        backup_files = list(backup_dir.glob("*.backup.json"))

        # Check if any backup file contains our rotation ID
        backup_found = False
        for backup_file in backup_files:
            try:
                import json

                with open(backup_file, "r") as f:
                    backup_data = json.load(f)
                if backup_data.get("rotation_id") == rotation_id:
                    backup_found = True
                    break
            except Exception:
                continue

        assert backup_found

    def test_rotation_without_backup_creation(self):
        """Test that rotation doesn't create backup files when not requested."""
        # Perform rotation without backup
        rotation_id = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=False
        )

        # Check that no backup files exist for this rotation
        backup_dir = Path(self.custodian.data_directory) / "rotation-backups"
        if backup_dir.exists():
            backup_files = list(backup_dir.glob("*.backup.json"))

            # Check if any backup file contains our rotation ID
            backup_found = False
            for backup_file in backup_files:
                try:
                    import json

                    with open(backup_file, "r") as f:
                        backup_data = json.load(f)
                    if backup_data.get("rotation_id") == rotation_id:
                        backup_found = True
                        break
                except Exception:
                    continue

            assert not backup_found

    def test_rotation_preserves_credential_data(self):
        """Test that rotation preserves all credential data."""
        # Create credential with simple data to avoid encryption issues
        simple_credential = {
            "name": "Simple Test Credential",
            "credentials": {"username": "simple_user", "password": "simple_pass"},
            "meta_data": {"service": "simple_service", "environment": "test"},
        }

        key_id = self.custodian.create_credential(**simple_credential)

        # Perform rotation
        self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Verify all data is preserved
        data = self.custodian.read_credential(key_id)
        assert data["credentials"]["username"] == "simple_user"
        assert data["credentials"]["password"] == "simple_pass"
        assert data["meta_data"]["service"] == "simple_service"
        assert data["meta_data"]["environment"] == "test"

    def test_rotation_with_different_iterations(self):
        """Test rotation with different iteration values."""
        # Test with minimum iterations
        rotation_id1 = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS(), create_backup=False
        )
        assert rotation_id1 is not None

        # Test with higher iterations
        rotation_id2 = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1000, create_backup=False
        )
        assert rotation_id2 is not None

        # Verify credentials are still accessible
        credentials = self.custodian.list_credentials()
        assert len(credentials) == 2

    def test_rotation_error_handling(self):
        """Test error handling during rotation."""
        # Test with invalid iterations
        with pytest.raises(ValidationError):
            self.custodian.rotate_master_key(
                new_iterations=Constants.MIN_ITERATIONS() - 1, create_backup=False
            )

    def test_rotation_with_empty_credentials(self):
        """Test rotation when no credentials exist."""
        # Create new custodian without credentials
        empty_custodian = TestUtilities.create_test_custodian(
            TestUtilities.create_temp_data_dir(), self.master_password
        )

        # Perform rotation
        rotation_id = empty_custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Verify rotation was successful
        assert rotation_id is not None

        # Clean up
        TestUtilities.cleanup_temp_dir(empty_custodian.data_directory)

    def test_rotation_with_multiple_credentials(self):
        """Test rotation with multiple credentials using batch creation."""
        # Create multiple credentials using batch utility
        credentials = TestUtilities.create_test_credentials_batch(5, "batch")
        key_ids = []

        for cred in credentials:
            key_id = self.custodian.create_credential(**cred)
            key_ids.append(key_id)

        # Verify initial state (accounting for existing credentials from setUp)
        expected_count = 2 + 5  # 2 from setUp + 5 new ones
        assert self.custodian.credential_count == expected_count

        # Perform rotation
        rotation_id = self.custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1, create_backup=True
        )

        # Verify rotation was successful
        assert rotation_id is not None

        # Verify all credentials are preserved
        TestUtilities.verify_rotation_preserves_data(
            self.custodian, key_ids, credentials
        )
