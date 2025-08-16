"""Unit tests for the RotationTransaction module."""

import tempfile
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

from splurge_key_custodian.services.rotation.transaction import RotationTransaction
from splurge_key_custodian.exceptions import KeyRotationError


class TestRotationTransaction(unittest.TestCase):
    """Unit tests for RotationTransaction class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = Mock()
        self.transaction = RotationTransaction(self.file_manager)
        self.test_data = {"test": "data"}

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_transaction_initialization(self):
        """Test transaction initialization."""
        self.assertFalse(self.transaction._is_committed)
        self.assertFalse(self.transaction._is_rolled_back)
        self.assertEqual(len(self.transaction._backup_files), 0)
        self.assertEqual(len(self.transaction._original_states), 0)

    def test_backup_file_success(self):
        """Test successful file backup."""
        file_path = Path("test.json")
        
        self.transaction.backup_file(file_path, self.test_data)

        # Verify backup was recorded
        self.assertIn(str(file_path), self.transaction._backup_files)
        self.assertEqual(self.transaction._backup_files[str(file_path)], self.test_data)

    def test_backup_file_duplicate(self):
        """Test backing up the same file multiple times."""
        file_path = Path("test.json")
        
        # First backup
        self.transaction.backup_file(file_path, self.test_data)
        
        # Second backup with different data (should not overwrite)
        new_data = {"updated": "data"}
        self.transaction.backup_file(file_path, new_data)

        # Verify only the first data is kept (no overwrite)
        self.assertEqual(len(self.transaction._backup_files), 1)
        self.assertEqual(self.transaction._backup_files[str(file_path)], self.test_data)

    def test_commit_success(self):
        """Test successful transaction commit."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        self.file_manager.write_json_atomic.return_value = None

        self.transaction.commit()

        # Verify transaction was committed
        self.assertTrue(self.transaction._is_committed)
        self.assertFalse(self.transaction._is_rolled_back)

        # Verify transaction was committed (no file operations needed)
        self.assertTrue(self.transaction._is_committed)

    def test_commit_empty_transaction(self):
        """Test committing empty transaction."""
        self.transaction.commit()

        # Verify transaction was committed even with no backups
        self.assertTrue(self.transaction._is_committed)
        self.assertFalse(self.transaction._is_rolled_back)

    def test_commit_already_committed(self):
        """Test committing already committed transaction."""
        self.transaction.commit()

        # Second commit should not cause issues
        self.transaction.commit()

        self.assertTrue(self.transaction._is_committed)

    def test_commit_after_rollback(self):
        """Test committing after rollback."""
        self.transaction.rollback()

        # Commit should succeed after rollback (implementation allows this)
        self.transaction.commit()

        # Verify transaction is committed
        self.assertTrue(self.transaction._is_committed)

    def test_rollback_success(self):
        """Test successful transaction rollback."""
        file_path = Path("test-id.credential.json")
        self.transaction.backup_file(file_path, self.test_data)

        # Mock file manager methods for rollback
        self.file_manager.save_credential_file.return_value = None

        self.transaction.rollback()

        # Verify transaction was rolled back
        self.assertFalse(self.transaction._is_committed)
        self.assertTrue(self.transaction._is_rolled_back)

        # Verify file manager was called to restore data
        self.file_manager.save_credential_file.assert_called_once_with("test-id", self.test_data)

    def test_rollback_empty_transaction(self):
        """Test rolling back empty transaction."""
        self.transaction.rollback()

        # Verify transaction was rolled back even with no backups
        self.assertFalse(self.transaction._is_committed)
        self.assertTrue(self.transaction._is_rolled_back)

    def test_rollback_already_rolled_back(self):
        """Test rolling back already rolled back transaction."""
        self.transaction.rollback()

        # Second rollback should not cause issues (idempotent)
        self.transaction.rollback()

        self.assertTrue(self.transaction._is_rolled_back)

    def test_rollback_after_commit(self):
        """Test rolling back after commit."""
        self.transaction.commit()

        with self.assertRaises(KeyRotationError) as cm:
            self.transaction.rollback()

        self.assertIn("Cannot rollback committed transaction", str(cm.exception))

    def test_rollback_missing_file(self):
        """Test rolling back when original file doesn't exist."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        # Mock that the file doesn't exist
        self.file_manager.read_json.return_value = None

        self.transaction.rollback()

        # Verify rollback still succeeds
        self.assertTrue(self.transaction._is_rolled_back)

        # Verify rollback completed successfully
        self.assertTrue(self.transaction._is_rolled_back)

    def test_context_manager_success(self):
        """Test transaction as context manager with success."""
        file_path = Path("test.json")

        with self.transaction as txn:
            txn.backup_file(file_path, self.test_data)

        # Verify transaction was not committed (context manager doesn't auto-commit)
        self.assertFalse(self.transaction._is_committed)
        self.assertFalse(self.transaction._is_rolled_back)

    def test_context_manager_exception(self):
        """Test transaction as context manager with exception."""
        file_path = Path("test.json")

        with self.assertRaises(ValueError):
            with self.transaction as txn:
                txn.backup_file(file_path, self.test_data)
                raise ValueError("Test exception")

        # Verify transaction was rolled back
        self.assertFalse(self.transaction._is_committed)
        self.assertTrue(self.transaction._is_rolled_back)

    def test_get_backup_files(self):
        """Test getting list of backup files."""
        file_paths = [Path("file1.json"), Path("file2.json")]
        
        for path in file_paths:
            self.transaction.backup_file(path, self.test_data)

        # Verify all backup files are recorded
        self.assertEqual(len(self.transaction._backup_files), 2)
        self.assertIn(str(file_paths[0]), self.transaction._backup_files)
        self.assertIn(str(file_paths[1]), self.transaction._backup_files)

    def test_get_backup_data(self):
        """Test getting backup data for a specific file."""
        file_path = Path("test.json")
        self.transaction.backup_file(file_path, self.test_data)

        backup_data = self.transaction._backup_files.get(str(file_path))

        # Verify backup data is returned
        self.assertEqual(backup_data, self.test_data)

    def test_get_backup_data_not_found(self):
        """Test getting backup data for non-existent file."""
        file_path = Path("test.json")

        backup_data = self.transaction._backup_files.get(str(file_path))

        # Verify None is returned for non-existent file
        self.assertIsNone(backup_data)

    def test_is_committed(self):
        """Test checking if transaction is committed."""
        self.assertFalse(self.transaction._is_committed)
        
        self.transaction.commit()
        
        self.assertTrue(self.transaction._is_committed)

    def test_is_rolled_back(self):
        """Test checking if transaction is rolled back."""
        self.assertFalse(self.transaction._is_rolled_back)
        
        self.transaction.rollback()
        
        self.assertTrue(self.transaction._is_rolled_back)

    def test_clear_backups(self):
        """Test clearing all backups."""
        file_paths = [Path("file1.json"), Path("file2.json")]
        
        for path in file_paths:
            self.transaction.backup_file(path, self.test_data)

        self.transaction.commit()

        # Verify all backups were cleared after commit
        self.assertEqual(len(self.transaction._backup_files), 0)
        self.assertEqual(len(self.transaction._original_states), 0)

    def test_backup_multiple_files(self):
        """Test backing up multiple files."""
        files_data = {
            Path("file1.json"): {"data": "1"},
            Path("file2.json"): {"data": "2"},
            Path("file3.json"): {"data": "3"}
        }

        for file_path, data in files_data.items():
            self.transaction.backup_file(file_path, data)

        # Verify all files were backed up
        self.assertEqual(len(self.transaction._backup_files), 3)
        
        for file_path, data in files_data.items():
            self.assertIn(str(file_path), self.transaction._backup_files)
            self.assertEqual(self.transaction._backup_files[str(file_path)], data)
