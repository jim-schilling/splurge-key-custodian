"""Key rotation manager that orchestrates rotation operations."""

import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import (
    KeyRotationError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import (
    MasterKey,
    RotationHistory,
)
from splurge_key_custodian.validation_utils import validate_master_password_complexity

from splurge_key_custodian.services.rotation.transaction import RotationTransaction
from splurge_key_custodian.services.rotation.backup import RotationBackupService
from splurge_key_custodian.services.rotation.operations import (
    re_encrypt_with_new_master,
    re_encrypt_for_password_change,
    re_encrypt_with_new_key,
)

logger = logging.getLogger(__name__)


class KeyRotationManager:
    """Manages key rotation operations for the Splurge Key Custodian."""

    def __init__(self, file_manager: FileManager):
        """Initialize the key rotation manager.

        Args:
            file_manager: File manager instance for data persistence
        """
        self._file_manager = file_manager
        self._backup_service = RotationBackupService(file_manager)

    @contextmanager
    def _rotation_transaction(self):
        """Context manager for atomic rotation operations.
        
        Yields:
            RotationTransaction: Transaction object for managing atomicity
        """
        transaction = RotationTransaction(self._file_manager)
        try:
            yield transaction
            transaction.commit()
        except Exception:
            if not transaction._is_committed:
                transaction.rollback()
            raise

    def rotate_master_key(
        self,
        *,
        master_password: str,
        new_iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None
    ) -> str:
        """Rotate the master encryption key while keeping the same password.

        This operation generates a new salt and derives a new master key from
        the same master password, then re-encrypts all credentials.

        Args:
            master_password: Current master password
            new_iterations: New iterations for key derivation (optional, defaults to current or 1,000,000)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional, defaults to 30)

        Returns:
            Rotation ID for tracking the operation

        Raises:
            KeyRotationError: If rotation fails
            ValidationError: If parameters are invalid
        """
        if not master_password:
            raise ValidationError("Master password is required")

        rotation_id = str(uuid.uuid4())
        affected_credentials = []

        with self._rotation_transaction() as transaction:
            # Backup current state
            transaction.backup_master_keys()
            transaction.backup_all_credentials()

            # Read current master keys
            master_keys_data = self._file_manager.read_master_keys()
            if not master_keys_data or not master_keys_data.get("master_keys"):
                raise KeyRotationError("No master keys found")

            old_master_key_data = master_keys_data["master_keys"][0]
            old_master_key_id = old_master_key_data["key_id"]

            # Create backup if requested
            if create_backup:
                self._backup_service.create_master_key_backup(
                    rotation_id=rotation_id,
                    old_master_key_data=old_master_key_data,
                    backup_retention_days=backup_retention_days
                )

            # Read all credential files
            credential_files = self._file_manager.list_credential_files()
            affected_credentials = credential_files.copy()

            # Create new master key with same password but new salt
            new_master_key_id = str(uuid.uuid4())
            new_salt = CryptoUtils.generate_salt()
            new_derived_key = CryptoUtils.derive_key_from_password(
                master_password,
                new_salt,
                iterations=new_iterations or Constants.DEFAULT_ITERATIONS()
            )

            # Create and encrypt placeholder credential for new master key
            placeholder_data = b"\x00"
            encrypted_placeholder = CryptoUtils.encrypt_with_fernet(
                new_derived_key,
                placeholder_data
            )

            new_master_key = MasterKey(
                key_id=new_master_key_id,
                credentials=Base58.encode(encrypted_placeholder),
                salt=Base58.encode(new_salt),
                iterations=new_iterations or Constants.DEFAULT_ITERATIONS(),
            )

            # Re-encrypt all credentials with new master key
            for key_id in credential_files:
                re_encrypt_with_new_master(
                    key_id=key_id,
                    master_password=master_password,
                    new_master_key=new_master_key,
                    file_manager=self._file_manager,
                    new_iterations=new_iterations
                )

            # Save new master key
            self._file_manager.save_master_keys([new_master_key.to_dict()])
            
            # Record rotation history
            self._record_rotation_history(
                rotation_id=rotation_id,
                rotation_type="master",
                old_master_key_id=old_master_key_id,
                new_master_key_id=new_master_key_id,
                affected_credentials=affected_credentials,
                metadata={
                    "new_iterations": new_iterations or Constants.DEFAULT_ITERATIONS(),
                    "backup_created": create_backup,
                    "rotation_type": "key_only"
                }
            )

            logger.info(f"Master key rotation completed successfully", extra={
                "rotation_id": rotation_id,
                "affected_credentials": len(affected_credentials),
                "event": "master_key_rotation_completed"
            })

            return rotation_id

    def change_master_password(
        self,
        *,
        old_master_password: str,
        new_master_password: str,
        old_iterations: int | None = None,
        new_iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None
    ) -> str:
        """Change the master password and rotate the master key.

        This operation re-encrypts all credentials with a new master key derived
        from the new master password.

        Args:
            old_master_password: Current master password
            new_master_password: New master password
            old_iterations: Current iterations for key derivation (optional)
            new_iterations: New iterations for key derivation (optional, defaults to current or 1,000,000)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional, defaults to 30)

        Returns:
            Rotation ID for tracking the operation

        Raises:
            KeyRotationError: If rotation fails
            ValidationError: If parameters are invalid
        """
        # Validate inputs
        if not old_master_password or not new_master_password:
            raise ValidationError("Both old and new master passwords are required")

        if old_master_password == new_master_password:
            raise ValidationError("New master password must be different from old password")

        # Validate new password complexity
        self._validate_master_password_complexity(new_master_password)

        rotation_id = str(uuid.uuid4())
        affected_credentials = []

        with self._rotation_transaction() as transaction:
            # Backup current state
            transaction.backup_master_keys()
            transaction.backup_all_credentials()

            # Read current master keys
            master_keys_data = self._file_manager.read_master_keys()
            if not master_keys_data or not master_keys_data.get("master_keys"):
                raise KeyRotationError("No master keys found")

            old_master_key_data = master_keys_data["master_keys"][0]
            old_master_key_id = old_master_key_data["key_id"]

            # Create backup if requested
            if create_backup:
                self._backup_service.create_master_key_backup(
                    rotation_id=rotation_id,
                    old_master_key_data=old_master_key_data,
                    backup_retention_days=backup_retention_days
                )

            # Read all credential files
            credential_files = self._file_manager.list_credential_files()
            affected_credentials = credential_files.copy()

            # Create new master key with new password
            new_master_key_id = str(uuid.uuid4())
            new_salt = CryptoUtils.generate_salt()
            new_derived_key = CryptoUtils.derive_key_from_password(
                new_master_password,
                new_salt,
                iterations=new_iterations or Constants.DEFAULT_ITERATIONS()
            )

            # Create and encrypt placeholder credential for new master key
            placeholder_data = b"\x00"
            encrypted_placeholder = CryptoUtils.encrypt_with_fernet(
                new_derived_key,
                placeholder_data
            )

            new_master_key = MasterKey(
                key_id=new_master_key_id,
                credentials=Base58.encode(encrypted_placeholder),
                salt=Base58.encode(new_salt),
            )

            # Re-encrypt all credentials with new master key
            for key_id in credential_files:
                re_encrypt_for_password_change(
                    key_id=key_id,
                    current_master_password=old_master_password,
                    new_master_password=new_master_password,
                    new_master_salt=new_salt,  # Use the same salt as the master key
                    file_manager=self._file_manager,
                    current_iterations=old_iterations or Constants.DEFAULT_ITERATIONS(),
                    new_iterations=new_iterations
                )

            # Save new master key
            self._file_manager.save_master_keys([new_master_key.to_dict()])
            
            # Record rotation history
            self._record_rotation_history(
                rotation_id=rotation_id,
                rotation_type="master",
                old_master_key_id=old_master_key_id,
                new_master_key_id=new_master_key_id,
                affected_credentials=affected_credentials,
                metadata={
                    "new_iterations": new_iterations or Constants.DEFAULT_ITERATIONS(),
                    "backup_created": create_backup,
                    "rotation_type": "password_change"
                }
            )

            logger.info(f"Master password change completed successfully", extra={
                "rotation_id": rotation_id,
                "affected_credentials": len(affected_credentials),
                "event": "master_password_change_completed"
            })

            return rotation_id

    def rotate_all_credentials(
        self,
        *,
        master_password: str,
        iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None,
        batch_size: int | None = None
    ) -> str:
        """Rotate encryption keys for all credentials.

        This operation re-encrypts all credentials with new individual keys while
        keeping the same master key.

        Args:
            master_password: Master password for decryption/encryption
            iterations: Iterations for key derivation (optional)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional, defaults to 30)
            batch_size: Number of credentials to rotate in each batch (optional)

        Returns:
            Rotation ID for tracking the operation

        Raises:
            KeyRotationError: If rotation fails
            ValidationError: If parameters are invalid
        """
        if not master_password:
            raise ValidationError("Master password is required")

        rotation_id = str(uuid.uuid4())
        credential_files = self._file_manager.list_credential_files()
        affected_credentials = []

        if not credential_files:
            logger.info("No credentials found to rotate")
            return rotation_id

        batch_size = batch_size or Constants.ROTATION_BATCH_SIZE()

        with self._rotation_transaction() as transaction:
            # Backup current state
            transaction.backup_all_credentials()

            # Create backup if requested
            if create_backup:
                self._backup_service.create_bulk_backup(
                    rotation_id=rotation_id,
                    credential_files=credential_files,
                    backup_retention_days=backup_retention_days
                )

            # Rotate credentials in batches
            for i in range(0, len(credential_files), batch_size):
                batch = credential_files[i:i + batch_size]
                for key_id in batch:
                    re_encrypt_with_new_key(
                        key_id=key_id,
                        master_password=master_password,
                        file_manager=self._file_manager,
                        iterations=iterations
                    )
                    affected_credentials.append(key_id)

            # Record rotation history
            self._record_rotation_history(
                rotation_id=rotation_id,
                rotation_type="bulk",
                old_master_key_id="",  # No master key change
                new_master_key_id="",  # No master key change
                affected_credentials=affected_credentials,
                metadata={
                    "iterations": iterations or Constants.DEFAULT_ITERATIONS(),
                    "backup_created": create_backup,
                    "batch_size": batch_size
                }
            )

            logger.info(f"Bulk credential rotation completed successfully", extra={
                "rotation_id": rotation_id,
                "affected_credentials": len(affected_credentials),
                "event": "bulk_rotation_completed"
            })

            return rotation_id

    def rollback_rotation(
        self,
        *,
        rotation_id: str,
        master_password: str
    ) -> None:
        """Rollback a specific rotation operation.

        Args:
            rotation_id: ID of the rotation to rollback
            master_password: Master password for decryption

        Raises:
            KeyRotationError: If rollback fails
            ValidationError: If parameters are invalid
        """
        if not rotation_id:
            raise ValidationError("Rotation ID is required")

        if not master_password:
            raise ValidationError("Master password is required")

        # Find the backup for this rotation
        backup = self._backup_service.find_backup_for_rotation(rotation_id)
        if not backup:
            raise KeyRotationError(f"No backup found for rotation {rotation_id}")

        if backup.is_expired():
            raise KeyRotationError(f"Backup for rotation {rotation_id} has expired")

        try:
            if backup.backup_type == "master":
                self._backup_service.rollback_master_key_rotation(backup)
            elif backup.backup_type == "bulk":
                self._backup_service.rollback_bulk_rotation(backup)
            else:
                raise KeyRotationError(f"Unknown backup type: {backup.backup_type}")

            logger.info(f"Rotation rollback completed successfully", extra={
                "rotation_id": rotation_id,
                "backup_type": backup.backup_type,
                "event": "rotation_rollback_completed"
            })

        except Exception as e:
            logger.error(f"Rotation rollback failed", extra={
                "rotation_id": rotation_id,
                "error": str(e),
                "event": "rotation_rollback_failed"
            })
            raise KeyRotationError(f"Rollback failed: {e}") from e

    def get_rotation_history(self, *, limit: int | None = None) -> list[RotationHistory]:
        """Get rotation history.

        Args:
            limit: Maximum number of history entries to return (optional)

        Returns:
            List of rotation history entries
        """
        history = self._file_manager.read_rotation_history()
        if limit is not None:
            history = history[-limit:]
        return history

    def cleanup_expired_backups(self) -> int:
        """Clean up expired rotation backups.

        Returns:
            Number of backups cleaned up
        """
        return self._file_manager.cleanup_expired_backups()

    def _validate_master_password_complexity(self, password: str) -> None:
        """Validate master password complexity.

        This method delegates to the shared validation utility function
        to ensure consistent validation rules across the codebase.

        Args:
            password: Password to validate

        Raises:
            ValidationError: If password doesn't meet complexity requirements
        """
        validate_master_password_complexity(password)

    def _record_rotation_history(
        self,
        rotation_id: str,
        rotation_type: str,
        old_master_key_id: str,
        new_master_key_id: str,
        affected_credentials: list[str],
        metadata: dict[str, Any]
    ) -> None:
        """Record rotation history.

        Args:
            rotation_id: ID of the rotation operation
            rotation_type: Type of rotation (master, bulk)
            old_master_key_id: ID of the old master key
            new_master_key_id: ID of the new master key
            affected_credentials: List of affected credential IDs
            metadata: Additional metadata about the rotation
        """
        history_entry = RotationHistory(
            rotation_id=rotation_id,
            rotation_type=rotation_type,
            target_key_id=new_master_key_id,
            old_master_key_id=old_master_key_id,
            new_master_key_id=new_master_key_id,
            affected_credentials=affected_credentials,
            created_at=datetime.now(timezone.utc),
            metadata=metadata
        )

        # Read existing history
        history = self._file_manager.read_rotation_history()
        history.append(history_entry)

        # Keep only the most recent entries
        max_history = Constants.MAX_ROTATION_HISTORY()
        if len(history) > max_history:
            history = history[-max_history:]

        # Save updated history
        self._file_manager.save_rotation_history(history)
