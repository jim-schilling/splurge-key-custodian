"""Key Custodian class for file-based credential management with separate files."""

import logging
import os
from typing import Any, Dict

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import (
    EncryptionError,
    FileOperationError,
    KeyNotFoundError,
    MasterKeyError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.services import (
    BackupService,
    MasterKeyService,
    CredentialService,
    IndexService,
    KeyRotationManager,
)
from splurge_key_custodian.validation_utils import validate_master_password_complexity

logger = logging.getLogger(__name__)


class KeyCustodian:
    """File-based key custodian for secure credential management using service layer."""

    @classmethod
    def _validate_master_password_complexity(cls, password: str) -> None:
        """Validate master password complexity requirements.

        This method delegates to the shared validation utility function
        to ensure consistent validation rules across the codebase.

        Args:
            password: Master password to validate

        Raises:
            ValidationError: If password doesn't meet complexity requirements
        """
        validate_master_password_complexity(password)

    @classmethod
    def init_from_environment(
        cls,
        env_variable: str,
        data_dir: str,
        *,
        iterations: int | None = None
    ) -> "KeyCustodian":
        """Create KeyCustodian instance from environment variable.

        Args:
            env_variable: Environment variable name containing Base58-encoded master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (default: 1,000,000, minimum: 10,000)

        Returns:
            KeyCustodian instance

        Raises:
            ValidationError: If environment variable name is invalid, environment variable is
                           missing/empty/invalid, if master password does not meet complexity requirements
                           (at least 32 characters with uppercase, lowercase, numeric, and symbol
                           characters), or if iterations is less than minimum
        """
        # Guard against None env_variable parameter
        if env_variable is None:
            raise ValidationError("Environment variable name cannot be None")

        # Guard against empty env_variable parameter
        if env_variable == "":
            raise ValidationError("Environment variable name cannot be empty")

        # Guard against whitespace-only env_variable parameter
        if env_variable.strip() == "":
            raise ValidationError("Environment variable name cannot contain only whitespace")

        # Guard against None environment variable
        master_password_b58 = os.getenv(env_variable)
        if master_password_b58 is None:
            raise ValidationError(f"Environment variable {env_variable} not set")

        # Guard against empty string
        if master_password_b58 == "":
            raise ValidationError(f"Environment variable {env_variable} is empty")

        # Guard against whitespace-only string
        if master_password_b58.strip() == "":
            raise ValidationError(f"Environment variable {env_variable} contains only whitespace")

        try:
            master_password_bytes = Base58.decode(master_password_b58)
            master_password = master_password_bytes.decode("utf-8")
        except Exception as e:
            raise ValidationError(f"Invalid Base58 in {env_variable}: {e}") from e

        # Validate master password complexity requirements
        cls._validate_master_password_complexity(master_password)

        return cls(master_password, data_dir, iterations=iterations)

    def __init__(
        self,
        master_password: str,
        data_dir: str,
        *,
        iterations: int | None = None
    ) -> None:
        """Initialize the Key Custodian.

        Args:
            master_password: Master password for encryption/decryption. Must be at least 32 characters
                           and contain uppercase, lowercase, numeric, and symbol characters.
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (default: 1,000,000, minimum: 10,000)

        Raises:
            ValidationError: If data_dir or master_password is empty, if master_password
                           does not meet complexity requirements, or if iterations is less than minimum
            MasterKeyError: If master key operations fail
        """
        # Guard against None master_password parameter
        if master_password is None:
            raise ValidationError("Master password cannot be None")

        # Guard against empty master_password parameter
        if master_password == "":
            raise ValidationError("Master password cannot be empty")

        # Guard against whitespace-only master_password parameter
        if master_password.strip() == "":
            raise ValidationError("Master password cannot contain only whitespace")

        # Guard against None data_dir parameter
        if data_dir is None:
            raise ValidationError("Data directory cannot be None")

        # Guard against empty data_dir parameter
        if data_dir == "":
            raise ValidationError("Data directory cannot be empty")

        # Guard against whitespace-only data_dir parameter
        if data_dir.strip() == "":
            raise ValidationError("Data directory cannot contain only whitespace")

        # Validate master password complexity requirements
        self._validate_master_password_complexity(master_password)

        # Validate iterations parameter
        if iterations is not None and iterations < Constants.MIN_ITERATIONS():
            raise ValidationError(f"Iterations must be at least {Constants.MIN_ITERATIONS():,}")

        self._master_password = master_password
        self._data_dir = data_dir
        self._iterations = iterations
        self._file_manager = FileManager(data_dir)

        # Initialize services
        self._master_key_service = MasterKeyService(self._file_manager)
        self._credential_service = CredentialService(self._file_manager)
        self._index_service = IndexService(self._file_manager)
        self._backup_service = BackupService(self._file_manager)
        self._rotation_manager = KeyRotationManager(self._file_manager)

        # Initialize or load master key
        self._initialize_master_key()

    def _initialize_master_key(self) -> None:
        """Initialize or load the master key."""
        # Check if master key exists
        existing_master_key = self._master_key_service.load_master_key()

        if existing_master_key:
            # Validate master password against existing key
            if not self._master_key_service.validate_master_password(
                self._master_password,
                self._iterations
            ):
                raise MasterKeyError("Invalid master password")

            logger.info("Master key loaded successfully")
        else:
            # Initialize new master key
            self._master_key_service.initialize_master_key(
                self._master_password,
                self._iterations
            )
            logger.info("Master key initialized successfully")

    def create_credential(
        self,
        *,
        name: str,
        credentials: Dict[str, Any],
        meta_data: Dict[str, Any] | None = None,
    ) -> str:
        """Create a new credential.

        Args:
            name: Name for the credential
            credentials: Credential data
            meta_data: Optional metadata

        Returns:
            Key ID of the created credential

        Raises:
            ValidationError: If name is empty or already exists
            EncryptionError: If encryption fails
        """
        try:
            # Create credential using service
            key_id = self._credential_service.create_credential(
                name=name,
                credentials=credentials,
                master_password=self._master_password,
                iterations=self._iterations,
                meta_data=meta_data
            )

            # Add to index
            self._index_service.add_credential_to_index(
                key_id=key_id,
                name=name,
                metadata=meta_data
            )

            return key_id
        except ValidationError:
            raise
        except FileOperationError as e:
            raise EncryptionError(f"Failed to create credential due to file operation error: {e}") from e
        except Exception as e:
            raise EncryptionError(f"Failed to create credential: {e}") from e

    def read_credential(self, key_id: str) -> Dict[str, Any]:
        """Read a credential by key ID.

        Args:
            key_id: Key ID of the credential to read

        Returns:
            Dictionary containing credential data

        Raises:
            KeyNotFoundError: If credential not found
            EncryptionError: If decryption fails
        """
        try:
            return self._credential_service.read_credential(
                key_id=key_id,
                master_password=self._master_password,
                iterations=self._iterations
            )
        except ValidationError:
            raise
        except FileOperationError as e:
            raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found") from e
        except Exception as e:
            raise KeyNotFoundError(f"Credential {key_id} not found: {e}") from e

    def update_credential(
        self,
        key_id: str,
        *,
        name: str | None = None,
        credentials: Dict[str, Any] | None = None,
        meta_data: Dict[str, Any] | None = None,
    ) -> None:
        """Update a credential.

        Args:
            key_id: Key ID of the credential to update
            name: New name for the credential (optional)
            credentials: New credential data (optional)
            meta_data: New metadata (optional)

        Raises:
            KeyNotFoundError: If credential not found
            ValidationError: If name is empty or already exists
            EncryptionError: If encryption fails
        """
        try:
            # Update credential using service
            self._credential_service.update_credential(
                key_id=key_id,
                master_password=self._master_password,
                name=name,
                credentials=credentials,
                meta_data=meta_data,
                iterations=self._iterations
            )

            # Update index
            self._index_service.update_credential_in_index(
                key_id=key_id,
                name=name,
                metadata=meta_data
            )
        except ValidationError:
            raise
        except FileOperationError as e:
            raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found") from e
        except Exception as e:
            raise KeyNotFoundError(f"Credential {key_id} not found: {e}") from e

    def delete_credential(self, key_id: str) -> None:
        """Delete a credential.

        Args:
            key_id: Key ID of the credential to delete

        Raises:
            KeyNotFoundError: If credential not found
        """
        try:
            # Delete credential using service
            self._credential_service.delete_credential(key_id)

            # Remove from index
            self._index_service.remove_credential_from_index(key_id)
        except ValidationError:
            raise
        except FileOperationError as e:
            raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found") from e
        except Exception as e:
            raise KeyNotFoundError(f"Credential {key_id} not found: {e}") from e

    def list_credentials(self) -> list[Dict[str, Any]]:
        """List all credentials.

        Returns:
            List of credential metadata dictionaries
        """
        return self._credential_service.list_credentials()

    def search_credentials(self, name_pattern: str) -> Dict[str, Dict[str, Any]]:
        """Search credentials by name pattern.

        Args:
            name_pattern: Name pattern to search for (case-insensitive)

        Returns:
            Dictionary mapping key_id to credential index data for matching credentials
        """
        return self._index_service.search_credentials_by_name(name_pattern)

    def change_master_password(
        self,
        new_master_password: str,
        *,
        new_iterations: int | None = None
    ) -> None:
        """Change the master password.

        Args:
            new_master_password: New master password
            new_iterations: New iterations for key derivation (optional)

        Raises:
            ValidationError: If new password is invalid
            MasterKeyError: If password change fails
        """
        self._master_key_service.change_master_password(
            old_master_password=self._master_password,
            new_master_password=new_master_password,
            old_iterations=self._iterations,
            new_iterations=new_iterations
        )

        # Update instance variables
        self._master_password = new_master_password
        if new_iterations is not None:
            self._iterations = new_iterations

    def get_master_key_info(self) -> Dict[str, Any] | None:
        """Get information about the current master key.

        Returns:
            Dictionary with master key information or None if not found
        """
        return self._master_key_service.get_master_key_info()

    def get_credential_metadata(self, key_id: str) -> Dict[str, Any] | None:
        """Get metadata for a credential.

        Args:
            key_id: Key ID of the credential

        Returns:
            Dictionary with credential metadata or None if not found
        """
        return self._credential_service.get_credential_metadata(key_id)

    def get_index_statistics(self) -> Dict[str, Any]:
        """Get statistics about the credentials index.

        Returns:
            Dictionary with index statistics
        """
        return self._index_service.get_index_statistics()

    def rebuild_index(self) -> None:
        """Rebuild the credentials index from credential files.

        This method reads all credential files and rebuilds the index
        to ensure consistency between the index and actual credential files.
        """
        self._index_service.rebuild_index()

    # Rotation methods delegate to rotation manager
    def rotate_master_key(
        self,
        *,
        new_iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None
    ) -> str:
        """Rotate the master encryption key while keeping the same password.

        Args:
            new_iterations: New iterations for key derivation (optional)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional)

        Returns:
            Rotation ID for tracking the operation
        """
        rotation_id = self._rotation_manager.rotate_master_key(
            master_password=self._master_password,
            new_iterations=new_iterations,
            create_backup=create_backup,
            backup_retention_days=backup_retention_days
        )
        
        # Update the iterations value after successful rotation
        if new_iterations is not None:
            self._iterations = new_iterations
        
        return rotation_id

    def rotate_all_credentials(
        self,
        *,
        create_backup: bool = True,
        backup_retention_days: int | None = None,
        batch_size: int | None = None
    ) -> str:
        """Rotate encryption keys for all credentials.

        Args:
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional)
            batch_size: Number of credentials to rotate in each batch (optional)

        Returns:
            Rotation ID for tracking the operation
        """
        return self._rotation_manager.rotate_all_credentials(
            master_password=self._master_password,
            iterations=self._iterations,
            create_backup=create_backup,
            backup_retention_days=backup_retention_days,
            batch_size=batch_size
        )

    def rollback_rotation(self, rotation_id: str) -> None:
        """Rollback a specific rotation operation.

        Args:
            rotation_id: ID of the rotation to rollback
        """
        self._rotation_manager.rollback_rotation(
            rotation_id=rotation_id,
            master_password=self._master_password
        )

    def get_rotation_history(self, *, limit: int | None = None) -> list:
        """Get rotation history.

        Args:
            limit: Maximum number of history entries to return (optional)

        Returns:
            List of rotation history entries
        """
        return self._rotation_manager.get_rotation_history(limit=limit)

    def cleanup_expired_backups(self) -> int:
        """Clean up expired rotation backups.

        Returns:
            Number of backups cleaned up
        """
        return self._rotation_manager.cleanup_expired_backups()

    @property
    def file_manager(self) -> FileManager:
        """Get the file manager instance.

        Returns:
            FileManager instance
        """
        return self._file_manager

    @property
    def rotation_manager(self) -> KeyRotationManager:
        """Get the rotation manager instance.

        Returns:
            KeyRotationManager instance
        """
        return self._rotation_manager

    def find_credential_by_name(self, name: str) -> Dict[str, Any] | None:
        """Find a credential by name.

        Args:
            name: Name of the credential

        Returns:
            Credential info dictionary with key_id and name, or None if not found

        Raises:
            ValidationError: If name is empty
        """
        return self._credential_service.find_credential_by_name(name)

    # Essential properties for tests and CLI
    @property
    def data_directory(self) -> str:
        """Get the data directory."""
        return self._data_dir

    @property
    def master_key_id(self) -> str:
        """Get the master key ID."""
        master_key = self._master_key_service.load_master_key()
        return master_key.key_id if master_key else ""

    @property
    def credential_count(self) -> int:
        """Get the number of credentials."""
        return len(self._credential_service.list_credentials())

    @property
    def iterations(self) -> int | None:
        """Get the iterations value used for key derivation.

        Returns:
            The iterations value, or None if using default iterations
        """
        return self._iterations

    def backup_credentials(self, backup_dir: str) -> None:
        """Backup all credentials to a directory.

        Args:
            backup_dir: Directory to backup to

        Raises:
            ValidationError: If backup_dir is empty
            FileOperationError: If backup fails
        """
        self._backup_service.backup_credentials(backup_dir)
