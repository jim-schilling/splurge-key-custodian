"""File management utilities for hybrid approach with separate credential files."""

import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional

from splurge_key_custodian.exceptions import FileOperationError
from splurge_key_custodian.models import (
    CredentialFile, 
    CredentialsIndex, 
    RotationHistory, 
    RotationBackup
)


class FileManager:
    """Manages file operations for the key custodian system with atomic operations."""

    def __init__(
        self, 
        data_dir: str
    ):
        """Initialize the file manager.

        Args:
            data_dir: Directory to store key files
        """
        self._data_dir = Path(data_dir)
        self._master_file = self._data_dir / "key-custodian-master.json"
        self._index_file = self._data_dir / "key-custodian-index.json"
        self._rotation_history_file = self._data_dir / "key-custodian-rotation-history.json"
        self._backups_dir = self._data_dir / "rotation-backups"
        self._ensure_data_directory()

    def _ensure_data_directory(self) -> None:
        """Ensure the data directory exists."""
        self._ensure_data_directory_with_dependencies(data_dir=self._data_dir)

    def _ensure_data_directory_with_dependencies(
        self,
        *,
        data_dir: Path
    ) -> None:
        """Ensure the data directory exists with explicit dependencies.

        Args:
            data_dir: Directory path to ensure exists
        """
        data_dir.mkdir(parents=True, exist_ok=True)
        # Ensure backups directory exists
        self._backups_dir.mkdir(parents=True, exist_ok=True)

    def _write_json_atomic(
        self,
        file_path: Path,
        data: dict[str, Any]
    ) -> None:
        """Write JSON data atomically using temporary file.

        Args:
            file_path: Path to the target file
            data: Data to write

        Raises:
            FileOperationError: If write operation fails
        """
        temp_file = file_path.with_suffix(".temp")
        archive_file = file_path.with_suffix(".archive")

        try:
            # Ensure parent directory exists for atomic operation
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file
            with temp_file.open("w", encoding="utf-8") as f:
                json.dump(
                    data, 
                    f, 
                    indent=2, 
                    ensure_ascii=False
                )

            # If original file exists, rename it to archive
            if file_path.exists():
                shutil.move(str(file_path), str(archive_file))

            # Rename temporary file to target file
            shutil.move(str(temp_file), str(file_path))

            # Set secure permissions on the final file
            self._set_secure_permissions(file_path)

            # Remove archive file if it exists
            if archive_file.exists():
                archive_file.unlink()

        except Exception as e:
            # Clean up temporary file if it exists
            if temp_file.exists():
                temp_file.unlink()
            raise FileOperationError(f"Failed to write file {file_path}: {e}") from e

    def _read_json(self, file_path: Path) -> Optional[dict[str, Any]]:
        """Read JSON data from file.

        Args:
            file_path: Path to the file to read

        Returns:
            JSON data as dictionary, or None if file doesn't exist

        Raises:
            FileOperationError: If read operation fails
        """
        if not file_path.exists():
            return None

        try:
            with file_path.open(encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            raise FileOperationError(f"Failed to read file {file_path}: {e}") from e

    def save_master_keys(self, master_keys: list) -> None:
        """Save master keys to file atomically.

        Args:
            master_keys: List of master key dictionaries

        Raises:
            FileOperationError: If save operation fails
        """
        data = {
            "master_keys": master_keys,
            "version": "1.0",
        }
        self._write_json_atomic(self._master_file, data)

    def read_master_keys(self) -> Optional[dict[str, Any]]:
        """Read master keys from file.

        Returns:
            Master keys data as dictionary, or None if file doesn't exist

        Raises:
            FileOperationError: If read operation fails
        """
        return self._read_json(self._master_file)

    def save_credentials_index(self, index: CredentialsIndex) -> None:
        """Save credentials index to file atomically.

        Args:
            index: CredentialsIndex object to save

        Raises:
            FileOperationError: If save operation fails
        """
        self._write_json_atomic(self._index_file, index.to_dict())

    def read_credentials_index(self) -> Optional[CredentialsIndex]:
        """Read credentials index from file.

        Returns:
            CredentialsIndex object, or None if file doesn't exist

        Raises:
            FileOperationError: If read operation fails
        """
        data = self._read_json(self._index_file)
        if data is None:
            return None

        try:
            return CredentialsIndex.from_dict(data)
        except Exception as e:
            raise FileOperationError(f"Failed to parse credentials index: {e}") from e

    def save_credential_file(
        self, 
        key_id: str, 
        credential_file: CredentialFile
    ) -> None:
        """Save individual credential file atomically.

        Args:
            key_id: Key ID for the credential
            credential_file: CredentialFile object to save

        Raises:
            FileOperationError: If save operation fails
        """
        file_path = self._data_dir / f"{key_id}.credential.json"
        self._write_json_atomic(file_path, credential_file.to_dict())

    def read_credential_file(self, key_id: str) -> Optional[CredentialFile]:
        """Read individual credential file.

        Args:
            key_id: Key ID for the credential

        Returns:
            CredentialFile object, or None if file doesn't exist

        Raises:
            FileOperationError: If read operation fails
        """
        file_path = self._data_dir / f"{key_id}.credential.json"
        data = self._read_json(file_path)
        if data is None:
            return None

        try:
            return CredentialFile.from_dict(data)
        except Exception as e:
            raise FileOperationError(f"Failed to parse credential file: {e}") from e

    def delete_credential_file(self, key_id: str) -> None:
        """Delete individual credential file.

        Args:
            key_id: Key ID for the credential

        Raises:
            FileOperationError: If delete operation fails
        """
        file_path = self._data_dir / f"{key_id}.credential.json"
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            raise FileOperationError(f"Failed to delete file {file_path}: {e}") from e

    def list_credential_files(self) -> list[str]:
        """List all credential file IDs.

        Returns:
            List of key IDs for existing credential files
        """
        credential_files = []
        for file_path in self._data_dir.glob("*.credential.json"):
            # Extract key_id from filename (remove .credential.json suffix)
            key_id = file_path.stem.replace(".credential", "")
            credential_files.append(key_id)
        return credential_files

    def save_rotation_history(self, history: list[RotationHistory]) -> None:
        """Save rotation history to file atomically.

        Args:
            history: List of RotationHistory objects to save

        Raises:
            FileOperationError: If save operation fails
        """
        data = {
            "rotation_history": [h.to_dict() for h in history],
            "version": "1.0",
        }
        self._write_json_atomic(self._rotation_history_file, data)

    def read_rotation_history(self) -> list[RotationHistory]:
        """Read rotation history from file.

        Returns:
            List of RotationHistory objects

        Raises:
            FileOperationError: If read operation fails
        """
        data = self._read_json(self._rotation_history_file)
        if data is None:
            return []

        try:
            history_list = []
            for history_data in data.get("rotation_history", []):
                history = RotationHistory.from_dict(history_data)
                history_list.append(history)
            return history_list
        except Exception as e:
            raise FileOperationError(f"Failed to parse rotation history: {e}") from e

    def save_rotation_backup(self, backup: RotationBackup) -> None:
        """Save rotation backup to file atomically.

        Args:
            backup: RotationBackup object to save

        Raises:
            FileOperationError: If save operation fails
        """
        file_path = self._backups_dir / f"{backup.backup_id}.backup.json"
        self._write_json_atomic(file_path, backup.to_dict())

    def read_rotation_backup(self, backup_id: str) -> Optional[RotationBackup]:
        """Read rotation backup from file.

        Args:
            backup_id: Backup ID to read

        Returns:
            RotationBackup object, or None if file doesn't exist

        Raises:
            FileOperationError: If read operation fails
        """
        file_path = self._backups_dir / f"{backup_id}.backup.json"
        data = self._read_json(file_path)
        if data is None:
            return None

        try:
            return RotationBackup.from_dict(data)
        except Exception as e:
            raise FileOperationError(f"Failed to parse rotation backup: {e}") from e

    def delete_rotation_backup(self, backup_id: str) -> None:
        """Delete rotation backup file.

        Args:
            backup_id: Backup ID to delete

        Raises:
            FileOperationError: If delete operation fails
        """
        file_path = self._backups_dir / f"{backup_id}.backup.json"
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception as e:
            raise FileOperationError(f"Failed to delete backup file {file_path}: {e}") from e

    def list_rotation_backups(self) -> list[str]:
        """List all rotation backup IDs.

        Returns:
            List of backup IDs for existing backup files
        """
        backup_files = []
        for file_path in self._backups_dir.glob("*.backup.json"):
            # Extract backup_id from filename (remove .backup.json suffix)
            backup_id = file_path.stem.replace(".backup", "")
            backup_files.append(backup_id)
        return backup_files

    def cleanup_expired_backups(self) -> int:
        """Clean up expired rotation backups.

        Returns:
            Number of backups cleaned up
        """
        cleaned_count = 0
        for backup_id in self.list_rotation_backups():
            backup = self.read_rotation_backup(backup_id)
            if backup and backup.is_expired():
                try:
                    self.delete_rotation_backup(backup_id)
                    cleaned_count += 1
                except Exception:
                    # Log but continue with other backups
                    pass
        return cleaned_count

    def backup_files(self, backup_dir: str) -> None:
        """Create a backup of all key files.

        Args:
            backup_dir: Directory to store backups

        Raises:
            FileOperationError: If backup operation fails
        """
        backup_path = Path(backup_dir)
        backup_path.mkdir(parents=True, exist_ok=True)

        try:
            # Backup master file
            if self._master_file.exists():
                shutil.copy2(self._master_file, backup_path / self._master_file.name)

            # Backup index file
            if self._index_file.exists():
                shutil.copy2(self._index_file, backup_path / self._index_file.name)

            # Backup rotation history file
            if self._rotation_history_file.exists():
                shutil.copy2(self._rotation_history_file, backup_path / self._rotation_history_file.name)

            # Backup credential files
            for file_path in self._data_dir.glob("*.credential.json"):
                shutil.copy2(file_path, backup_path / file_path.name)

            # Backup rotation backups directory
            if self._backups_dir.exists():
                backup_backups_dir = backup_path / "rotation-backups"
                if backup_backups_dir.exists():
                    shutil.rmtree(backup_backups_dir)
                shutil.copytree(self._backups_dir, backup_backups_dir)

        except Exception as e:
            raise FileOperationError(f"Failed to create backup: {e}") from e

    def cleanup_temp_files(self) -> None:
        """Clean up any temporary files that may have been left behind."""
        try:
            for temp_file in self._data_dir.glob("*.temp"):
                temp_file.unlink()
            for temp_file in self._backups_dir.glob("*.temp"):
                temp_file.unlink()
        except Exception:
            # Ignore cleanup errors
            pass

    def _set_secure_permissions(self, file_path: Path) -> None:
        """Set secure file permissions (owner read/write only).
        
        Args:
            file_path: Path to the file to secure
        """
        try:
            # Set file permissions to owner read/write only (600)
            os.chmod(file_path, 0o600)
        except Exception:
            # Ignore permission errors - they may not be critical
            pass

    @property
    def data_directory(self) -> Path:
        """Get the data directory path."""
        return self._data_dir

    @property
    def master_file_path(self) -> Path:
        """Get the master file path."""
        return self._master_file

    @property
    def index_file_path(self) -> Path:
        """Get the index file path."""
        return self._index_file

    @property
    def rotation_history_file_path(self) -> Path:
        """Get the rotation history file path."""
        return self._rotation_history_file

    @property
    def backups_directory(self) -> Path:
        """Get the backups directory path."""
        return self._backups_dir
