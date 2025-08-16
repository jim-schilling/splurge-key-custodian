"""Rotation transaction management for atomic operations."""

import logging
from pathlib import Path
from typing import Any

from splurge_key_custodian.exceptions import KeyRotationError
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import CredentialsIndex

logger = logging.getLogger(__name__)


class RotationTransaction:
    """Manages atomic key rotation operations with rollback capability."""
    
    def __init__(self, file_manager: FileManager):
        """Initialize rotation transaction.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager
        self._backup_files: dict[str, Any] = {}
        self._original_states: dict[str, Any] = {}
        self._is_committed = False
        self._is_rolled_back = False
        
    def backup_file(self, file_path: Path, data: Any) -> None:
        """Backup a file's current state.
        
        Args:
            file_path: Path to the file to backup
            data: Current data to backup
        """
        if str(file_path) not in self._backup_files:
            self._backup_files[str(file_path)] = data
            
    def backup_master_keys(self) -> None:
        """Backup current master keys."""
        master_keys_data = self._file_manager.read_master_keys()
        if master_keys_data:
            self.backup_file(self._file_manager.master_file_path, master_keys_data)
            
    def backup_credential_file(self, key_id: str) -> None:
        """Backup a specific credential file.
        
        Args:
            key_id: Key ID of the credential to backup
        """
        credential_data = self._file_manager.read_credential_file(key_id)
        if credential_data:
            file_path = self._file_manager.data_directory / f"{key_id}.credential.json"
            self.backup_file(file_path, credential_data)
            
    def backup_all_credentials(self) -> None:
        """Backup all credential files."""
        credential_files = self._file_manager.list_credential_files()
        for key_id in credential_files:
            self.backup_credential_file(key_id)
            
    def commit(self) -> None:
        """Commit the transaction - no rollback possible after this."""
        self._is_committed = True
        self._backup_files.clear()
        self._original_states.clear()
        
    def rollback(self) -> None:
        """Rollback all changes made during the transaction."""
        if self._is_committed:
            raise KeyRotationError("Cannot rollback committed transaction")
            
        if self._is_rolled_back:
            return
            
        self._is_rolled_back = True
        
        try:
            # Restore all backed up files
            for file_path_str, data in self._backup_files.items():
                file_path = Path(file_path_str)
                if file_path.name.endswith('.credential.json'):
                    # Extract key_id from filename
                    key_id = file_path.stem.replace('.credential', '')
                    self._file_manager.save_credential_file(key_id, data)
                elif file_path.name == 'key-custodian-master.json':
                    self._file_manager.save_master_keys(data.get('master_keys', []))
                elif file_path.name == 'key-custodian-index.json':
                    index = CredentialsIndex.from_dict(data)
                    self._file_manager.save_credentials_index(index)
                    
            logger.info("Rotation transaction rolled back successfully")
            
        except Exception as e:
            logger.error(f"Failed to rollback rotation transaction: {e}")
            raise KeyRotationError(f"Rollback failed: {e}") from e
            
    def __enter__(self):
        """Enter transaction context."""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit transaction context - rollback on exception."""
        if exc_type is not None and not self._is_committed:
            logger.warning("Exception occurred during rotation, rolling back transaction")
            self.rollback()
