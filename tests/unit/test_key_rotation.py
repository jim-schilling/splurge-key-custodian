#!/usr/bin/env python3
"""Unit tests for key rotation functionality."""

import json
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import (
    KeyRotationError,
    RotationBackupError,
    RotationHistoryError,
    RotationRollbackError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.key_custodian import KeyCustodian
from splurge_key_custodian.key_rotation import KeyRotationManager
from splurge_key_custodian.models import (
    CredentialFile,
    RotationBackup,
    RotationHistory,
)


class TestKeyRotationManager:
    """Test KeyRotationManager functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def file_manager(self, temp_dir):
        """Create a FileManager instance."""
        return FileManager(temp_dir)

    @pytest.fixture
    def rotation_manager(self, file_manager):
        """Create a KeyRotationManager instance."""
        return KeyRotationManager(file_manager=file_manager)

    @pytest.fixture
    def master_password(self):
        """Valid master password for testing."""
        return "MySecureMasterPassword123!@#ExtraLongEnough"

    def test_rotation_history_is_recorded(self, rotation_manager, file_manager, master_password):
        """Test that rotation operations are recorded in history."""
        # Test that history recording works
        rotation_id = str(uuid.uuid4())
        rotation_manager._record_rotation_history(
            rotation_id=rotation_id,
            rotation_type="master",
            old_master_key_id="old-key",
            new_master_key_id="new-key",
            affected_credentials=["cred1"],
            metadata={"test": "data"}
        )
        
        # Verify history was recorded
        history = rotation_manager.get_rotation_history()
        assert len(history) == 1
        assert history[0].rotation_id == rotation_id
        assert history[0].rotation_type == "master"

    def test_backup_is_created_during_rotation(self, rotation_manager, file_manager, master_password):
        """Test that backups are created during rotation operations."""
        # Create a test backup
        backup_data = {"test": "data"}
        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data=backup_data,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Save backup
        file_manager.save_rotation_backup(backup)
        
        # Verify backup was created
        backup_ids = file_manager.list_rotation_backups()
        assert len(backup_ids) == 1
        assert backup_ids[0] == backup.backup_id
        
        # Read the backup to verify its content
        read_backup = file_manager.read_rotation_backup(backup.backup_id)
        assert read_backup.backup_type == "master"
        assert not read_backup.is_expired()

    def test_cleanup_expired_backups_removes_old_backups(self, rotation_manager, file_manager, master_password):
        """Test that cleanup removes expired backups."""
        # Create expired backup
        expired_backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc) - timedelta(days=10),
            expires_at=datetime.now(timezone.utc) - timedelta(days=5)  # Expired
        )
        
        # Create valid backup
        valid_backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="bulk",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)  # Not expired
        )
        
        # Save both backups
        file_manager.save_rotation_backup(expired_backup)
        file_manager.save_rotation_backup(valid_backup)
        
        # Verify both backups exist
        backup_ids = file_manager.list_rotation_backups()
        assert len(backup_ids) == 2
        assert expired_backup.backup_id in backup_ids
        assert valid_backup.backup_id in backup_ids
        
        # Cleanup expired backups
        cleaned_count = rotation_manager.cleanup_expired_backups()
        
        # Verify only expired backup was removed
        assert cleaned_count == 1
        remaining_backup_ids = file_manager.list_rotation_backups()
        assert len(remaining_backup_ids) == 1
        assert remaining_backup_ids[0] == valid_backup.backup_id

    def test_backup_expiration_check(self, file_manager):
        """Test backup expiration checking."""
        # Create expired backup
        expired_backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) - timedelta(days=1)  # Expired
        )
        
        # Create valid backup
        valid_backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="bulk",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=1)  # Not expired
        )
        
        # Check expiration
        assert expired_backup.is_expired()
        assert not valid_backup.is_expired()

    def test_invalid_rotation_id_raises_error(self, rotation_manager, master_password):
        """Test that invalid rotation ID raises appropriate error."""
        with pytest.raises(KeyRotationError):
            rotation_manager.rollback_rotation(
                rotation_id="invalid-rotation-id",
                master_password=master_password
            )

    def test_missing_backup_raises_error(self, rotation_manager, master_password):
        """Test that missing backup raises appropriate error."""
        # Create a fake rotation ID
        fake_rotation_id = str(uuid.uuid4())
        
        with pytest.raises(KeyRotationError):
            rotation_manager.rollback_rotation(
                rotation_id=fake_rotation_id,
                master_password=master_password
            )


class TestKeyCustodianRotationIntegration:
    """Test KeyCustodian integration with rotation functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def master_password(self):
        """Valid master password for testing."""
        return "MySecureMasterPassword123!@#ExtraLongEnough"

    @pytest.fixture
    def custodian(self, temp_dir, master_password):
        """Create a KeyCustodian instance with test credentials."""
        custodian = KeyCustodian(master_password, temp_dir)
        
        # Create some test credentials
        custodian.create_credential(
            name="Test Credential 1",
            credentials={"username": "user1", "password": "pass1"}
        )
        custodian.create_credential(
            name="Test Credential 2", 
            credentials={"username": "user2", "password": "pass2"}
        )
        
        return custodian

    def test_custodian_rotate_master_key_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.rotate_master_key works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform master key rotation
        rotation_id = custodian.rotate_master_key(
            new_iterations=1500000,
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Verify credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Create a new custodian with the same iterations used during rotation
        new_custodian = KeyCustodian(master_password, custodian.data_directory, iterations=1500000)
        
        # Verify we can read the credentials with the new custodian
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_change_master_password_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.change_master_password works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform master password change
        new_password = "NewSecureMasterPassword456!@#ExtraLongEnough"
        rotation_id = custodian.change_master_password(
            new_master_password=new_password,
            new_iterations=1500000,
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Create new custodian with new password
        new_custodian = KeyCustodian(new_password, custodian.data_directory, iterations=1500000)
        
        # Verify credentials are accessible with new password
        updated_credentials = new_custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_rotate_all_credentials_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.rotate_all_credentials works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform bulk rotation
        rotation_id = custodian.rotate_all_credentials(
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Verify credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_get_rotation_history_returns_history(self, custodian, master_password):
        """Test that KeyCustodian.get_rotation_history returns rotation history."""
        # Perform a rotation to create history
        custodian.rotate_master_key(
            create_backup=True
        )
        
        # Get rotation history
        history = custodian.get_rotation_history()
        
        # Verify history contains the rotation
        assert len(history) == 1
        assert history[0].rotation_type == "master"

    def test_custodian_cleanup_expired_backups_works(self, custodian, master_password):
        """Test that KeyCustodian.cleanup_expired_backups works."""
        # Perform a rotation to create a backup
        custodian.rotate_master_key(
            create_backup=True,
            backup_retention_days=1  # Short retention for testing
        )
        
        # Cleanup expired backups (should not remove recent backup)
        cleaned_count = custodian.cleanup_expired_backups()
        
        # Verify no recent backups were cleaned
        assert cleaned_count == 0
