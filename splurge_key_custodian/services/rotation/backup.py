"""Rotation backup service for creating and restoring backups."""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import KeyRotationError
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import RotationBackup

logger = logging.getLogger(__name__)


class RotationBackupService:
    """Service for managing rotation backups."""

    def __init__(self, file_manager: FileManager):
        """Initialize the rotation backup service.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager

    def create_master_key_backup(
        self,
        rotation_id: str,
        old_master_key_data: dict[str, Any],
        backup_retention_days: int | None = None
    ) -> None:
        """Create a backup of the current master key state and all credentials.

        Args:
            rotation_id: ID of the rotation operation
            old_master_key_data: Current master key data to backup
            backup_retention_days: Days to retain backup (optional)
        """
        retention_days = backup_retention_days or Constants.BACKUP_RETENTION_DAYS()
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        # Backup all credential files as well for complete rollback capability
        credential_files = self._file_manager.list_credential_files()
        backup_credential_data = {}
        for key_id in credential_files:
            credential_data = self._file_manager.read_credential_file(key_id)
            if credential_data:
                backup_credential_data[key_id] = credential_data.to_dict()

        # Create comprehensive backup with both master key and credentials
        backup_data = {
            "master_key": old_master_key_data,
            "credentials": backup_credential_data
        }

        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=rotation_id,
            backup_type="master",
            original_data=backup_data,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at
        )

        self._file_manager.save_rotation_backup(backup)

    def create_bulk_backup(
        self,
        rotation_id: str,
        credential_files: list[str],
        backup_retention_days: int | None = None
    ) -> None:
        """Create a backup of all credential files.

        Args:
            rotation_id: ID of the rotation operation
            credential_files: List of credential file IDs to backup
            backup_retention_days: Days to retain backup (optional)
        """
        retention_days = backup_retention_days or Constants.BACKUP_RETENTION_DAYS()
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        # Backup all credential files
        backup_data = {}
        for key_id in credential_files:
            credential_data = self._file_manager.read_credential_file(key_id)
            if credential_data:
                backup_data[key_id] = credential_data.to_dict()

        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=rotation_id,
            backup_type="bulk",
            original_data=backup_data,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at
        )

        self._file_manager.save_rotation_backup(backup)

    def find_backup_for_rotation(self, rotation_id: str) -> RotationBackup | None:
        """Find backup for a specific rotation.

        Args:
            rotation_id: ID of the rotation to find backup for

        Returns:
            RotationBackup object if found, None otherwise
        """
        backup_ids = self._file_manager.list_rotation_backups()
        for backup_id in backup_ids:
            backup = self._file_manager.read_rotation_backup(backup_id)
            if backup and backup.rotation_id == rotation_id:
                return backup
        return None

    def restore_credential_files(
        self,
        credential_data: dict[str, Any]
    ) -> None:
        """Restore credential files from backup data.

        This method handles various failure scenarios during credential restoration:
        - Backup data corruption: Invalid credential data structure
        - File system errors: Disk write failures, permission issues
        - Memory errors: Large credential data processing failures
        - Partial restoration: Some credentials succeed, others fail

        Args:
            credential_data: Dictionary mapping key_id to credential data

        Raises:
            KeyRotationError: If restoration fails completely or backup data is corrupted
        """
        if not isinstance(credential_data, dict):
            raise KeyRotationError(
                f"Invalid backup data format: expected dict, got {type(credential_data).__name__}"
            )

        failed_restorations = []
        successful_restorations = []

        for key_id, credential_data_item in credential_data.items():
            try:
                # Validate key_id format
                if not isinstance(key_id, str) or not key_id.strip():
                    logger.error(f"Invalid key_id in backup data: {key_id}")
                    failed_restorations.append((key_id, "Invalid key_id format"))
                    continue

                # Convert dictionary to CredentialFile object if needed
                if isinstance(credential_data_item, dict):
                    try:
                        from splurge_key_custodian.models import CredentialFile
                        credential_file = CredentialFile.from_dict(credential_data_item)
                    except (KeyError, ValueError, TypeError) as e:
                        logger.error(f"Failed to parse credential data for {key_id}: {e}")
                        failed_restorations.append((key_id, f"Data parsing error: {e}"))
                        continue
                elif hasattr(credential_data_item, 'to_dict'):  # CredentialFile object
                    credential_file = credential_data_item
                else:
                    logger.error(f"Invalid credential data type for {key_id}: {type(credential_data_item).__name__}")
                    failed_restorations.append((key_id, f"Invalid data type: {type(credential_data_item).__name__}"))
                    continue

                # Save credential file
                try:
                    self._file_manager.save_credential_file(key_id, credential_file)
                    successful_restorations.append(key_id)
                    logger.debug(f"Successfully restored credential: {key_id}")
                except Exception as e:
                    logger.error(f"Failed to save credential file for {key_id}: {e}")
                    failed_restorations.append((key_id, f"File operation error: {e}"))

            except Exception as e:
                logger.error(f"Unexpected error processing credential {key_id}: {e}")
                failed_restorations.append((key_id, f"Processing error: {e}"))

        # Handle restoration results
        if not successful_restorations and failed_restorations:
            # Complete failure - no credentials restored
            error_details = "; ".join([f"{key_id}: {error}" for key_id, error in failed_restorations])
            raise KeyRotationError(
                f"Bulk rotation rollback failed completely. Failed restorations: {error_details}"
            )
        elif failed_restorations:
            # Partial failure - some credentials restored, others failed
            error_details = "; ".join([f"{key_id}: {error}" for key_id, error in failed_restorations])
            logger.warning(
                f"Bulk rotation rollback completed with partial failures. "
                f"Successfully restored: {len(successful_restorations)}, "
                f"Failed: {len(failed_restorations)}. "
                f"Failed restorations: {error_details}"
            )
            # Continue with partial restoration - this is acceptable for rollback
        else:
            # Complete success
            logger.info(f"Successfully restored all {len(successful_restorations)} credentials")

    def rollback_master_key_rotation(
        self,
        backup: RotationBackup
    ) -> None:
        """Rollback a master key rotation.

        Args:
            backup: Backup containing the original state
        """
        # Check backup structure and restore accordingly
        if isinstance(backup.original_data, dict) and "master_key" in backup.original_data:
            self._rollback_comprehensive_master_key_backup(backup)
        elif isinstance(backup.original_data, dict) and "credentials" in backup.original_data:
            self._rollback_legacy_credentials_backup(backup)
        else:
            self._rollback_legacy_master_key_only_backup(backup)

    def _rollback_comprehensive_master_key_backup(
        self,
        backup: RotationBackup
    ) -> None:
        """Rollback using comprehensive backup format with both master key and credentials.

        Args:
            backup: Backup containing comprehensive master key and credential data
        """
        original_master_key_data = backup.original_data["master_key"]
        original_credentials = backup.original_data["credentials"]
        
        # Restore original master key
        self._file_manager.save_master_keys([original_master_key_data])
        
        # Restore original credentials
        self.restore_credential_files(original_credentials)
        
        logger.info("Master key rotation rollback completed - original master key and credentials restored")

    def _rollback_legacy_credentials_backup(
        self,
        backup: RotationBackup
    ) -> None:
        """Rollback using legacy backup format with only credentials.

        Args:
            backup: Backup containing only credential data
        """
        original_credentials = backup.original_data["credentials"]
        
        # Restore original credentials
        self.restore_credential_files(original_credentials)
        
        logger.warning("Master key rotation rollback completed - credentials restored but master key backup may be incomplete")

    def _rollback_legacy_master_key_only_backup(
        self,
        backup: RotationBackup
    ) -> None:
        """Rollback using legacy backup format with only master key data.

        Args:
            backup: Backup containing only master key data

        Raises:
            KeyRotationError: If credential backup is not available
        """
        original_master_key_data = backup.original_data
        self._file_manager.save_master_keys([original_master_key_data])
        
        # No credential backup available - this is a critical limitation
        logger.error("Master key rotation rollback incomplete - no credential backup available")
        logger.error("Credentials may be in an inconsistent state and may require manual recovery")
        raise KeyRotationError(
            (
                "Master key rotation rollback failed - credential backup not available. "
                "Manual recovery may be required."
            )
        )

    def rollback_bulk_rotation(
        self,
        backup: RotationBackup
    ) -> None:
        """Rollback a bulk credential rotation.

        This method restores all credentials to their original state before a bulk
        rotation operation. It processes each credential in the backup and converts
        dictionary data back to CredentialFile objects before saving them to disk.

        The restoration process:
        1. Iterates through all credentials in the backup
        2. Converts dictionary data to CredentialFile objects if needed
        3. Saves each credential file to its original location
        4. Overwrites any existing credential files with the backed-up versions

        Potential failure scenarios:
        - Backup data corruption: If the backup contains invalid credential data
        - File system errors: If the file manager cannot write to disk
        - Memory errors: If credential data is too large to process
        - Partial restoration: If some credentials restore successfully but others fail

        Args:
            backup: Backup containing the original credential states

        Raises:
            KeyRotationError: If the restoration process fails completely
        """
        try:
            # Validate backup data structure
            if not hasattr(backup, 'original_data') or backup.original_data is None:
                raise KeyRotationError("Backup data is missing or corrupted")

            if not isinstance(backup.original_data, dict):
                raise KeyRotationError(
                    f"Invalid backup data format: expected dict, got {type(backup.original_data).__name__}"
                )

            # Check if backup contains credential data
            if not backup.original_data:
                raise KeyRotationError("Backup contains no credential data to restore")

            logger.info(f"Starting bulk rotation rollback for {len(backup.original_data)} credentials")

            # Restore original credential files using shared method
            self.restore_credential_files(backup.original_data)

            logger.info("Bulk rotation rollback completed successfully")

        except KeyRotationError:
            # Re-raise KeyRotationError as-is
            raise
        except Exception as e:
            # Catch any other unexpected errors
            logger.error(f"Unexpected error during bulk rotation rollback: {e}")
            raise KeyRotationError(f"Bulk rotation rollback failed due to unexpected error: {e}") from e
