"""Unit tests for the RotationTransaction module."""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from splurge_key_custodian.exceptions import KeyRotationError
from splurge_key_custodian.services.rotation.transaction import RotationTransaction


class TestRotationTransaction:
    """Unit tests for RotationTransaction class."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = Mock()
        self.transaction = RotationTransaction(self.file_manager)
        self.test_data = {"test": "data"}
        yield
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_transaction_initialization(self):
        """Test transaction initialization."""
        assert not self.transaction._is_committed
        assert not self.transaction._is_rolled_back
        assert len(self.transaction._backup_files) == 0
        assert len(self.transaction._original_states) == 0

    def test_backup_file_success(self):
        """Test successful file backup."""
        file_path = Path("test.json")

        self.transaction.backup_file(file_path, self.test_data)

        # Verify backup was recorded
        assert str(file_path) in self.transaction._backup_files
        assert self.transaction._backup_files[str(file_path)] == self.test_data

    def test_backup_file_duplicate(self):
        """Test backing up the same file multiple times."""
        file_path = Path("test.json")

        # First backup
        self.transaction.backup_file(file_path, self.test_data)

        # Second backup with different data (should not overwrite)
        new_data = {"updated": "data"}
        self.transaction.backup_file(file_path, new_data)

        # Verify only the first data is kept (no overwrite)
        assert len(self.transaction._backup_files) == 1
        assert self.transaction._backup_files[str(file_path)] == self.test_data

    def test_commit_success(self):
        """Test successful transaction commit."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        self.file_manager.write_json_atomic.return_value = None

        self.transaction.commit()

        # Verify transaction was committed
        assert self.transaction._is_committed
        assert not self.transaction._is_rolled_back

        # Verify transaction was committed (no file operations needed)
        assert self.transaction._is_committed

    def test_commit_empty_transaction(self):
        """Test committing empty transaction."""
        self.transaction.commit()

        # Verify transaction was committed even with no backups
        assert self.transaction._is_committed
        assert not self.transaction._is_rolled_back

    def test_commit_already_committed(self):
        """Test committing already committed transaction."""
        self.transaction.commit()

        # Second commit should not cause issues
        self.transaction.commit()

        assert self.transaction._is_committed

    def test_commit_after_rollback(self):
        """Test committing after rollback."""
        self.transaction.rollback()

        # Commit should succeed after rollback (implementation allows this)
        self.transaction.commit()

        # Verify transaction is committed
        assert self.transaction._is_committed

    def test_rollback_success(self):
        """Test successful transaction rollback."""
        file_path = Path("test-id.credential.json")
        self.transaction.backup_file(file_path, self.test_data)

        # Mock file manager methods for rollback
        self.file_manager.save_credential_file.return_value = None

        self.transaction.rollback()

        # Verify transaction was rolled back
        assert not self.transaction._is_committed
        assert self.transaction._is_rolled_back

        # Verify file manager was called to restore data
        self.file_manager.save_credential_file.assert_called_once_with(
            "test-id", self.test_data
        )

    def test_rollback_empty_transaction(self):
        """Test rolling back empty transaction."""
        self.transaction.rollback()

        # Verify transaction was rolled back even with no backups
        assert not self.transaction._is_committed
        assert self.transaction._is_rolled_back

    def test_rollback_already_rolled_back(self):
        """Test rolling back already rolled back transaction."""
        self.transaction.rollback()

        # Second rollback should not cause issues (idempotent)
        self.transaction.rollback()

        assert self.transaction._is_rolled_back

    def test_rollback_after_commit(self):
        """Test rolling back after commit."""
        self.transaction.commit()

        with pytest.raises(KeyRotationError) as cm:
            self.transaction.rollback()

        assert "Cannot rollback committed transaction" in str(cm.value)

    def test_rollback_missing_file(self):
        """Test rolling back when original file doesn't exist."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        # Mock that the file doesn't exist
        self.file_manager.read_json.return_value = None

        self.transaction.rollback()

        # Verify rollback still succeeds
        assert self.transaction._is_rolled_back

        # Verify rollback completed successfully
        assert self.transaction._is_rolled_back

    def test_context_manager_success(self):
        """Test transaction as context manager with success."""
        file_path = Path("test.json")

        with self.transaction as txn:
            txn.backup_file(file_path, self.test_data)

        # Verify transaction was not committed (context manager doesn't auto-commit)
        assert not self.transaction._is_committed
        assert not self.transaction._is_rolled_back

    def test_context_manager_exception(self):
        """Test transaction as context manager with exception."""
        file_path = Path("test.json")

        with pytest.raises(ValueError):
            with self.transaction as txn:
                txn.backup_file(file_path, self.test_data)
                raise ValueError("Test exception")

        # Verify transaction was rolled back
        assert not self.transaction._is_committed
        assert self.transaction._is_rolled_back

    def test_get_backup_files(self):
        """Test getting list of backup files."""
        file_paths = [Path("file1.json"), Path("file2.json")]

        for path in file_paths:
            self.transaction.backup_file(path, self.test_data)

        # Verify all backup files are recorded
        assert len(self.transaction._backup_files) == 2
        assert str(file_paths[0]) in self.transaction._backup_files
        assert str(file_paths[1]) in self.transaction._backup_files

    def test_get_backup_data(self):
        """Test getting backup data for a specific file."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        backup_data = self.transaction._backup_files.get(str(file_path))

        # Verify backup data is returned
        assert backup_data == self.test_data

    def test_get_backup_data_not_found(self):
        """Test getting backup data for non-existent file."""
        file_path = Path("test.json")

        backup_data = self.transaction._backup_files.get(str(file_path))

        # Verify None is returned for non-existent file
        assert backup_data is None

    def test_is_committed(self):
        """Test checking if transaction is committed."""
        assert not self.transaction._is_committed

        self.transaction.commit()

        assert self.transaction._is_committed

    def test_is_rolled_back(self):
        """Test checking if transaction is rolled back."""
        assert not self.transaction._is_rolled_back

        self.transaction.rollback()

        assert self.transaction._is_rolled_back

    def test_clear_backups(self):
        """Test clearing all backups."""
        file_paths = [Path("file1.json"), Path("file2.json")]

        for path in file_paths:
            self.transaction.backup_file(path, self.test_data)

        self.transaction.commit()

        # Verify all backups were cleared after commit
        assert len(self.transaction._backup_files) == 0
        assert len(self.transaction._original_states) == 0

    def test_backup_multiple_files(self):
        """Test backing up multiple files."""
        files_data = {
            Path("file1.json"): {"data": "1"},
            Path("file2.json"): {"data": "2"},
            Path("file3.json"): {"data": "3"},
        }

        for file_path, data in files_data.items():
            self.transaction.backup_file(file_path, data)

        # Verify all files were backed up
        assert len(self.transaction._backup_files) == 3

        for file_path, data in files_data.items():
            assert str(file_path) in self.transaction._backup_files
            assert self.transaction._backup_files[str(file_path)] == data
