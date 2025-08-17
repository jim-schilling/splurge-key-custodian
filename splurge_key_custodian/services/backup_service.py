"""Backup service for non-rotation backup operations."""

import logging
from pathlib import Path

from splurge_key_custodian.exceptions import FileOperationError, ValidationError
from splurge_key_custodian.file_manager import FileManager

logger = logging.getLogger(__name__)


class BackupService:
    """Service for managing non-rotation backups."""

    def __init__(self, file_manager: FileManager):
        """Initialize the backup service.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager

    def backup_credentials(self, backup_dir: str) -> None:
        """Backup all credentials and related files to a directory.

        Args:
            backup_dir: Directory to backup to

        Raises:
            ValidationError: If backup_dir is invalid
            FileOperationError: If backup fails
        """
        if backup_dir is None:
            raise ValidationError("Backup directory cannot be None")

        if not backup_dir:
            raise ValidationError("Backup directory cannot be empty")
        
        if not backup_dir.strip():
            raise ValidationError("Backup directory cannot contain only whitespace")

        try:
            # Use FileManager's comprehensive backup method
            self._file_manager.backup_files(backup_dir)
            
            logger.info(f"Successfully created backup in: {backup_dir}")
            
        except FileOperationError:
            # Re-raise FileOperationError as-is
            raise
        except Exception as e:
            # Wrap other exceptions as ValidationError for consistency
            raise ValidationError(f"Backup failed: {e}") from e
