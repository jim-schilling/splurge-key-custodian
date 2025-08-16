"""Unit tests for BackupService."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from splurge_key_custodian.exceptions import FileOperationError, ValidationError
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.services.backup_service import BackupService


class TestBackupService(unittest.TestCase):
    """Test cases for BackupService."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = FileManager(self.temp_dir)
        self.backup_service = BackupService(self.file_manager)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test BackupService initialization."""
        self.assertIsInstance(self.backup_service, BackupService)
        self.assertEqual(self.backup_service._file_manager, self.file_manager)

    def test_backup_credentials_none_backup_dir(self):
        """Test backup_credentials with None backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.backup_service.backup_credentials(None)
        
        self.assertIn("Backup directory cannot be None", str(cm.exception))

    def test_backup_credentials_empty_backup_dir(self):
        """Test backup_credentials with empty backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.backup_service.backup_credentials("")
        
        self.assertIn("Backup directory cannot be empty", str(cm.exception))

    def test_backup_credentials_whitespace_only_backup_dir(self):
        """Test backup_credentials with whitespace-only backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.backup_service.backup_credentials("   \t\n   ")
        
        self.assertIn("Backup directory cannot contain only whitespace", str(cm.exception))

    def test_backup_credentials_success(self):
        """Test successful backup operation."""
        backup_dir = os.path.join(self.temp_dir, "backup")
        
        # Mock the file manager's backup_files method
        with patch.object(self.file_manager, 'backup_files') as mock_backup:
            self.backup_service.backup_credentials(backup_dir)
            
            # Verify the file manager's backup method was called
            mock_backup.assert_called_once_with(backup_dir)

    def test_backup_credentials_file_operation_error(self):
        """Test backup_credentials when FileManager raises FileOperationError."""
        backup_dir = os.path.join(self.temp_dir, "backup")
        
        # Mock the file manager to raise FileOperationError
        with patch.object(self.file_manager, 'backup_files') as mock_backup:
            mock_backup.side_effect = FileOperationError("Backup failed")
            
            with self.assertRaises(FileOperationError) as cm:
                self.backup_service.backup_credentials(backup_dir)
            
            self.assertIn("Backup failed", str(cm.exception))

    def test_backup_credentials_general_exception(self):
        """Test backup_credentials when FileManager raises general exception."""
        backup_dir = os.path.join(self.temp_dir, "backup")
        
        # Mock the file manager to raise a general exception
        with patch.object(self.file_manager, 'backup_files') as mock_backup:
            mock_backup.side_effect = Exception("Unexpected error")
            
            with self.assertRaises(ValidationError) as cm:
                self.backup_service.backup_credentials(backup_dir)
            
            self.assertIn("Backup failed: Unexpected error", str(cm.exception))

    def test_backup_credentials_with_real_file_manager(self):
        """Test backup_credentials with actual FileManager operations."""
        # Create a test credential file (which FileManager would back up)
        credential_file = Path(self.temp_dir) / "test-credential.credential.json"
        credential_file.write_text('{"test": "content"}')
        
        backup_dir = os.path.join(self.temp_dir, "backup")
        
        # Perform backup
        self.backup_service.backup_credentials(backup_dir)
        
        # Verify backup directory was created
        self.assertTrue(os.path.exists(backup_dir))
        
        # Verify the credential file was backed up
        backup_credential_file = Path(backup_dir) / "test-credential.credential.json"
        self.assertTrue(backup_credential_file.exists())
        self.assertEqual(backup_credential_file.read_text(), '{"test": "content"}')


if __name__ == "__main__":
    unittest.main()
