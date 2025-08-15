#!/usr/bin/env python3
"""Unit tests for FileManager rotation functionality."""

import json
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from splurge_key_custodian.exceptions import (
    FileOperationError,
    RotationBackupError,
    RotationHistoryError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import (
    RotationBackup,
    RotationHistory,
)


class TestFileManagerRotation:
    """Test FileManager rotation-related functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def file_manager(self, temp_dir):
        """Create a FileManager instance."""
        return FileManager(temp_dir)

    def test_save_and_read_rotation_history(self, file_manager):
        """Test saving and reading rotation history."""
        # Create test rotation history
        history_entry = RotationHistory(
            rotation_id=str(uuid.uuid4()),
            rotation_type="master",
            target_key_id=str(uuid.uuid4()),
            old_master_key_id=str(uuid.uuid4()),
            new_master_key_id=str(uuid.uuid4()),
            affected_credentials=["cred1", "cred2"],
            created_at=datetime.now(timezone.utc),
            metadata={"test": "data"}
        )
        
        # Save rotation history (expects a list)
        file_manager.save_rotation_history([history_entry])
        
        # Read rotation history
        history = file_manager.read_rotation_history()
        
        # Verify history was saved and read correctly
        assert len(history) == 1
        saved_entry = history[0]
        assert saved_entry.rotation_id == history_entry.rotation_id
        assert saved_entry.rotation_type == history_entry.rotation_type
        assert saved_entry.target_key_id == history_entry.target_key_id
        assert saved_entry.old_master_key_id == history_entry.old_master_key_id
        assert saved_entry.new_master_key_id == history_entry.new_master_key_id
        assert saved_entry.affected_credentials == history_entry.affected_credentials
        assert saved_entry.metadata == history_entry.metadata

    def test_save_and_read_rotation_backup(self, file_manager):
        """Test saving and reading rotation backup."""
        # Create test rotation backup
        backup_data = {
            "master_keys": [{"key_id": "test-key", "salt": "test-salt"}],
            "credentials": [{"key_id": "cred1", "name": "Test Credential"}]
        }
        
        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data=backup_data,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Save rotation backup
        file_manager.save_rotation_backup(backup)
        
        # Read rotation backup
        read_backup = file_manager.read_rotation_backup(backup.backup_id)
        
        # Verify backup was saved and read correctly
        assert read_backup.backup_id == backup.backup_id
        assert read_backup.rotation_id == backup.rotation_id
        assert read_backup.backup_type == backup.backup_type
        assert read_backup.original_data == backup.original_data
        assert not read_backup.is_expired()

    def test_list_rotation_backups(self, file_manager):
        """Test listing rotation backups."""
        # Create multiple test backups
        backup1 = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data1"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        backup2 = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="bulk",
            original_data={"test": "data2"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Save backups
        file_manager.save_rotation_backup(backup1)
        file_manager.save_rotation_backup(backup2)
        
        # List backups (returns backup IDs, not objects)
        backup_ids = file_manager.list_rotation_backups()
        
        # Verify all backups are listed
        assert len(backup_ids) == 2
        assert backup1.backup_id in backup_ids
        assert backup2.backup_id in backup_ids

    def test_delete_rotation_backup(self, file_manager):
        """Test deleting rotation backup."""
        # Create test backup
        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        # Save backup
        file_manager.save_rotation_backup(backup)
        
        # Verify backup exists
        backup_ids = file_manager.list_rotation_backups()
        assert len(backup_ids) == 1
        
        # Delete backup
        file_manager.delete_rotation_backup(backup.backup_id)
        
        # Verify backup was deleted
        backup_ids = file_manager.list_rotation_backups()
        assert len(backup_ids) == 0

    def test_cleanup_expired_backups(self, file_manager):
        """Test cleaning up expired backups."""
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
        
        # Cleanup expired backups
        cleaned_count = file_manager.cleanup_expired_backups()
        
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

    def test_rotation_history_file_path_property(self, file_manager):
        """Test rotation history file path property."""
        expected_path = Path(file_manager._data_dir) / "key-custodian-rotation-history.json"
        assert file_manager.rotation_history_file_path == expected_path

    def test_backups_directory_property(self, file_manager):
        """Test backups directory property."""
        expected_path = Path(file_manager._data_dir) / "rotation-backups"
        assert file_manager.backups_directory == expected_path

    def test_ensure_data_directory_creates_backups_dir(self, file_manager):
        """Test that ensure_data_directory creates the backups directory."""
        # Remove backups directory if it exists
        backups_dir = file_manager.backups_directory
        if backups_dir.exists():
            import shutil
            shutil.rmtree(backups_dir)
        
        # Ensure data directory
        file_manager._ensure_data_directory()
        
        # Verify backups directory was created
        assert backups_dir.exists()
        assert backups_dir.is_dir()

    def test_backup_files_includes_rotation_data(self, file_manager):
        """Test that backup_files includes rotation history and backups."""
        # Create some rotation data
        history_entry = RotationHistory(
            rotation_id=str(uuid.uuid4()),
            rotation_type="master",
            target_key_id=str(uuid.uuid4()),
            old_master_key_id=str(uuid.uuid4()),
            new_master_key_id=str(uuid.uuid4()),
            affected_credentials=[],
            created_at=datetime.now(timezone.utc),
            metadata={}
        )
        file_manager.save_rotation_history([history_entry])
        
        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        file_manager.save_rotation_backup(backup)
        
        # Create a dummy credential file to ensure backup has content
        from splurge_key_custodian.models import CredentialFile
        dummy_credential = CredentialFile(
            key_id="test",
            name="Test Credential",
            salt="test-salt",
            data="test-data",
            rotation_version=1
        )
        file_manager.save_credential_file("test", dummy_credential)
        
        # Create backup files
        backup_path = Path(file_manager._data_dir) / "test-backup.zip"
        file_manager.backup_files(backup_path)
        
        # Verify backup file was created and has content
        assert backup_path.exists()
        assert backup_path.stat().st_size > 0

    def test_cleanup_temp_files_includes_backups_dir(self, file_manager):
        """Test that cleanup_temp_files cleans up backups directory temp files."""
        # Create a temporary file in backups directory with .temp extension
        backups_dir = file_manager.backups_directory
        temp_file = backups_dir / "temp_file.temp"
        temp_file.write_text("test content")
        
        # Verify temp file exists
        assert temp_file.exists()
        
        # Cleanup temp files
        file_manager.cleanup_temp_files()
        
        # Verify temp file was removed
        assert not temp_file.exists()

    def test_read_rotation_history_empty_file(self, file_manager):
        """Test reading rotation history from empty file."""
        # Ensure rotation history file doesn't exist
        history_file = file_manager.rotation_history_file_path
        if history_file.exists():
            history_file.unlink()
        
        # Read rotation history
        history = file_manager.read_rotation_history()
        
        # Should return empty list
        assert history == []

    def test_read_rotation_backup_not_found(self, file_manager):
        """Test reading non-existent rotation backup."""
        fake_backup_id = str(uuid.uuid4())
        
        # This should return None when backup doesn't exist
        result = file_manager.read_rotation_backup(fake_backup_id)
        assert result is None

    def test_delete_rotation_backup_not_found(self, file_manager):
        """Test deleting non-existent rotation backup."""
        fake_backup_id = str(uuid.uuid4())
        
        # Should not raise an error, just do nothing
        file_manager.delete_rotation_backup(fake_backup_id)

    def test_save_rotation_history_creates_directory(self, file_manager):
        """Test that save_rotation_history creates the data directory if needed."""
        # Remove data directory
        import shutil
        if file_manager._data_dir.exists():
            shutil.rmtree(file_manager._data_dir)
        
        # Create and save rotation history
        history_entry = RotationHistory(
            rotation_id=str(uuid.uuid4()),
            rotation_type="master",
            target_key_id=str(uuid.uuid4()),
            old_master_key_id=str(uuid.uuid4()),
            new_master_key_id=str(uuid.uuid4()),
            affected_credentials=[],
            created_at=datetime.now(timezone.utc),
            metadata={}
        )
        
        file_manager.save_rotation_history([history_entry])
        
        # Verify data directory was created
        assert file_manager._data_dir.exists()
        assert file_manager.rotation_history_file_path.exists()

    def test_save_rotation_backup_creates_directory(self, file_manager):
        """Test that save_rotation_backup creates the backups directory if needed."""
        # Remove backups directory
        backups_dir = file_manager.backups_directory
        if backups_dir.exists():
            import shutil
            shutil.rmtree(backups_dir)
        
        # Create and save rotation backup
        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=str(uuid.uuid4()),
            backup_type="master",
            original_data={"test": "data"},
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30)
        )
        
        file_manager.save_rotation_backup(backup)
        
        # Verify backups directory was created
        assert backups_dir.exists()
        assert (backups_dir / f"{backup.backup_id}.backup.json").exists()
