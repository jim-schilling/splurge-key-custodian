#!/usr/bin/env python3
"""Key rotation functionality for the Splurge Key Custodian."""

import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

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
    RotationBackup,
    RotationHistory,
)

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
            file_path = self._file_manager._data_dir / f"{key_id}.credential.json"
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
                    from splurge_key_custodian.models import CredentialsIndex
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


class KeyRotationManager:
    """Manages key rotation operations for the Splurge Key Custodian."""

    def __init__(self, file_manager: FileManager):
        """Initialize the key rotation manager.

        Args:
            file_manager: File manager instance for data persistence
        """
        self._file_manager = file_manager

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
        new_iterations: Optional[int] = None,
        create_backup: bool = True,
        backup_retention_days: Optional[int] = None
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
                self._create_master_key_backup(
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
            )

            # Re-encrypt all credentials with new master key
            for key_id in credential_files:
                self._re_encrypt_credential_with_new_master(
                    key_id=key_id,
                    master_password=master_password,
                    new_master_key=new_master_key,
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
        old_iterations: Optional[int] = None,
        new_iterations: Optional[int] = None,
        create_backup: bool = True,
        backup_retention_days: Optional[int] = None
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
                self._create_master_key_backup(
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
                self._re_encrypt_credential_for_password_change(
                    key_id=key_id,
                    current_master_password=old_master_password,
                    new_master_password=new_master_password,
                    new_master_salt=new_salt,  # Use the same salt as the master key
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
        iterations: Optional[int] = None,
        create_backup: bool = True,
        backup_retention_days: Optional[int] = None,
        batch_size: Optional[int] = None
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
                self._create_bulk_backup(
                    rotation_id=rotation_id,
                    credential_files=credential_files,
                    backup_retention_days=backup_retention_days
                )

            # Rotate credentials in batches
            for i in range(0, len(credential_files), batch_size):
                batch = credential_files[i:i + batch_size]
                for key_id in batch:
                    self._re_encrypt_credential_with_new_key(
                        key_id=key_id,
                        master_password=master_password,
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
        backup = self._find_backup_for_rotation(rotation_id)
        if not backup:
            raise KeyRotationError(f"No backup found for rotation {rotation_id}")

        if backup.is_expired():
            raise KeyRotationError(f"Backup for rotation {rotation_id} has expired")

        try:
            if backup.backup_type == "master":
                self._rollback_master_key_rotation(backup, master_password)
            elif backup.backup_type == "bulk":
                self._rollback_bulk_rotation(backup, master_password)
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

    def get_rotation_history(self, *, limit: Optional[int] = None) -> list[RotationHistory]:
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

        Args:
            password: Password to validate

        Raises:
            ValidationError: If password doesn't meet complexity requirements
        """
        if len(password) < 32:
            raise ValidationError("Master password must be at least 32 characters long")

        # Add more complexity requirements as needed
        if not any(c.isupper() for c in password):
            raise ValidationError("Master password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            raise ValidationError("Master password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            raise ValidationError("Master password must contain at least one digit")

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            raise ValidationError("Master password must contain at least one special character")

    def _create_master_key_backup(
        self,
        rotation_id: str,
        old_master_key_data: dict[str, Any],
        backup_retention_days: Optional[int] = None
    ) -> None:
        """Create a backup of the current master key state.

        Args:
            rotation_id: ID of the rotation operation
            old_master_key_data: Current master key data to backup
            backup_retention_days: Days to retain backup (optional)
        """
        retention_days = backup_retention_days or Constants.BACKUP_RETENTION_DAYS()
        expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        backup = RotationBackup(
            backup_id=str(uuid.uuid4()),
            rotation_id=rotation_id,
            backup_type="master",
            original_data=old_master_key_data,
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at
        )

        self._file_manager.save_rotation_backup(backup)

    def _create_bulk_backup(
        self,
        rotation_id: str,
        credential_files: list[str],
        backup_retention_days: Optional[int] = None
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

    def _re_encrypt_credential_with_new_master(
        self,
        key_id: str,
        master_password: str,
        new_master_key: MasterKey,
        new_iterations: Optional[int] = None
    ) -> None:
        """Re-encrypt a credential with a new master key.

        Args:
            key_id: Key ID of the credential to re-encrypt
            master_password: Master password for decryption
            new_master_key: New master key to use for encryption
            new_iterations: New iterations for key derivation (optional)
        """
        # Read current credential
        credential_data = self._file_manager.read_credential_file(key_id)
        if not credential_data:
            raise KeyRotationError(f"Credential {key_id} not found")

        # Read current master key for decryption
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            raise KeyRotationError("No master keys found")

        current_master_key_data = master_keys_data["master_keys"][0]
        current_salt = Base58.decode(current_master_key_data["salt"])
        current_iterations = Constants.DEFAULT_ITERATIONS()  # Use default for now

        # Derive current master key for decryption
        current_master_key = CryptoUtils.derive_key_from_password(
            master_password,
            current_salt,
            iterations=current_iterations
        )

        # Decrypt credential key with current master key
        # The credential data is stored as base58-encoded JSON containing encrypted_key and encrypted_data
        combined_data = json.loads(Base58.decode(credential_data.data).decode("utf-8"))
        
        # Decrypt the credential key using the current master key
        encrypted_key = Base58.decode(combined_data["encrypted_key"])
        credential_key = CryptoUtils.decrypt_key_with_master(
            encrypted_key,
            current_master_key,
            Base58.decode(credential_data.salt)
        )

        # Derive new master key for encryption
        new_salt = Base58.decode(new_master_key.salt)
        new_derived_key = CryptoUtils.derive_key_from_password(
            master_password,
            new_salt,
            iterations=new_iterations or Constants.DEFAULT_ITERATIONS()
        )

        # Re-encrypt the credential key with the new master key
        new_encrypted_key, new_salt = CryptoUtils.encrypt_key_with_master(
            credential_key,
            new_derived_key
        )

        # Update the combined data with the new encrypted key
        combined_data["encrypted_key"] = Base58.encode(new_encrypted_key)
        
        # Update credential with new encrypted data and salt
        credential_data.data = Base58.encode(json.dumps(combined_data).encode("utf-8"))
        credential_data.salt = Base58.encode(new_salt)
        credential_data.rotation_version = credential_data.rotation_version + 1

        # Save updated credential
        self._file_manager.save_credential_file(key_id, credential_data)

    def _re_encrypt_credential_for_password_change(
        self,
        key_id: str,
        current_master_password: str,
        new_master_password: str,
        new_master_salt: bytes,
        current_iterations: Optional[int] = None,
        new_iterations: Optional[int] = None
    ) -> None:
        """Re-encrypt a credential for master password change.

        Args:
            key_id: Key ID of the credential to re-encrypt
            current_master_password: Current master password for decryption
            new_master_password: New master password for encryption
            new_master_salt: New master salt for key derivation
            current_iterations: Current iterations for key derivation (optional)
            new_iterations: New iterations for key derivation (optional)
        """
        # Read current credential
        credential_data = self._file_manager.read_credential_file(key_id)
        if not credential_data:
            raise KeyRotationError(f"Credential {key_id} not found")

        # Read current master key for decryption
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            raise KeyRotationError("No master keys found")

        current_master_key_data = master_keys_data["master_keys"][0]
        current_salt = Base58.decode(current_master_key_data["salt"])

        # Derive current master key for decryption
        current_master_key = CryptoUtils.derive_key_from_password(
            current_master_password,
            current_salt,
            iterations=current_iterations or Constants.DEFAULT_ITERATIONS()
        )

        # Decrypt credential key with current master key
        # The credential data is stored as base58-encoded JSON containing encrypted_key and encrypted_data
        combined_data = json.loads(Base58.decode(credential_data.data).decode("utf-8"))
        
        # Decrypt the credential key using the current master key
        encrypted_key = Base58.decode(combined_data["encrypted_key"])
        credential_key = CryptoUtils.decrypt_key_with_master(
            encrypted_key,
            current_master_key,
            Base58.decode(credential_data.salt)
        )

        # Derive new master key for encryption
        new_derived_key = CryptoUtils.derive_key_from_password(
            new_master_password,
            new_master_salt,
            iterations=new_iterations or Constants.DEFAULT_ITERATIONS()
        )

        # Re-encrypt the credential key with the new master key
        new_encrypted_key, new_salt = CryptoUtils.encrypt_key_with_master(
            credential_key,
            new_derived_key
        )

        # Update the combined data with the new encrypted key
        combined_data["encrypted_key"] = Base58.encode(new_encrypted_key)
        
        # Update credential with new encrypted data and salt
        credential_data.data = Base58.encode(json.dumps(combined_data).encode("utf-8"))
        credential_data.salt = Base58.encode(new_salt)
        credential_data.rotation_version = credential_data.rotation_version + 1

        # Save updated credential
        self._file_manager.save_credential_file(key_id, credential_data)

    def _re_encrypt_credential_with_new_key(
        self,
        key_id: str,
        master_password: str,
        iterations: Optional[int] = None
    ) -> None:
        """Re-encrypt a credential with a new individual key.

        Args:
            key_id: Key ID of the credential to re-encrypt
            master_password: Master password for decryption/encryption
            iterations: Iterations for key derivation (optional)
        """
        # Read current credential
        credential_data = self._file_manager.read_credential_file(key_id)
        if not credential_data:
            raise KeyRotationError(f"Credential {key_id} not found")

        # Read current master key
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            raise KeyRotationError("No master keys found")

        current_master_key_data = master_keys_data["master_keys"][0]
        current_salt = Base58.decode(current_master_key_data["salt"])

        # Derive current master key for decryption
        current_master_key = CryptoUtils.derive_key_from_password(
            master_password,
            current_salt,
            iterations=iterations or Constants.DEFAULT_ITERATIONS()
        )

        # Decrypt credential data with current credential key
        # The credential data is stored as base58-encoded JSON containing encrypted_key and encrypted_data
        combined_data = json.loads(Base58.decode(credential_data.data).decode("utf-8"))
        
        # Decrypt the credential key using the current master key
        encrypted_key = Base58.decode(combined_data["encrypted_key"])
        credential_key = CryptoUtils.decrypt_key_with_master(
            encrypted_key,
            current_master_key,
            Base58.decode(credential_data.salt)
        )
        
        # Decrypt the actual credential data using the credential key
        encrypted_data = Base58.decode(combined_data["encrypted_data"])
        decrypted_data = CryptoUtils.decrypt_with_fernet(credential_key, encrypted_data)

        # Generate new credential key for this credential
        new_credential_key = CryptoUtils.generate_random_key()

        # Re-encrypt the credential data with the new credential key
        new_encrypted_data = CryptoUtils.encrypt_with_fernet(new_credential_key, decrypted_data)

        # Re-encrypt the new credential key with the master key
        new_encrypted_key, new_salt = CryptoUtils.encrypt_key_with_master(
            new_credential_key,
            current_master_key
        )

        # Update the combined data with the new encrypted key and data
        combined_data["encrypted_key"] = Base58.encode(new_encrypted_key)
        combined_data["encrypted_data"] = Base58.encode(new_encrypted_data)
        
        # Update credential with new encrypted data and salt
        credential_data.data = Base58.encode(json.dumps(combined_data).encode("utf-8"))
        credential_data.salt = Base58.encode(new_salt)
        credential_data.rotation_version = credential_data.rotation_version + 1

        # Save updated credential
        self._file_manager.save_credential_file(key_id, credential_data)

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

    def _find_backup_for_rotation(self, rotation_id: str) -> Optional[RotationBackup]:
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

    def _rollback_master_key_rotation(
        self,
        backup: RotationBackup,
        master_password: str
    ) -> None:
        """Rollback a master key rotation.

        Args:
            backup: Backup containing the original state
            master_password: Master password for decryption
        """
        # Restore original master key
        original_master_key_data = backup.original_data
        self._file_manager.save_master_keys([original_master_key_data])

        # Re-encrypt all credentials with the original master key
        # This is a simplified rollback - in a real implementation,
        # you might want to store the original credential states as well
        logger.warning("Master key rotation rollback may require manual credential re-encryption")

    def _rollback_bulk_rotation(
        self,
        backup: RotationBackup,
        master_password: str
    ) -> None:
        """Rollback a bulk credential rotation.

        Args:
            backup: Backup containing the original credential states
            master_password: Master password for decryption
        """
        # Restore original credential files
        original_credentials = backup.original_data
        for key_id, credential_data in original_credentials.items():
            self._file_manager.save_credential_file(key_id, credential_data)
