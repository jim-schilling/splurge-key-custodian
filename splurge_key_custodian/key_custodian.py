"""Key Custodian class for file-based credential management with separate files."""

import json
import logging
import os
import shutil
import uuid
from pathlib import Path
from typing import Any, Optional

# Configure logging
logger = logging.getLogger(__name__)

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import (
    EncryptionError,
    KeyNotFoundError,
    MasterKeyError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.key_rotation import KeyRotationManager
from splurge_key_custodian.models import (
    CredentialData,
    CredentialFile,
    CredentialsIndex,
    MasterKey,
    RotationHistory,
)
from splurge_key_custodian.validation_utils import validate_master_password_complexity


class KeyCustodian:
    """File-based key custodian for secure credential management."""

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
            iterations: Number of iterations for key derivation (default: 1,000,000, minimum: 100,000)

        Returns:
            KeyCustodian instance

        Raises:
            ValidationError: If environment variable name is invalid, environment variable is missing/empty/invalid,
                           if master password does not meet complexity requirements (at least 32 characters
                           with uppercase, lowercase, numeric, and symbol characters), or if iterations is less than minimum
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
            iterations: Number of iterations for key derivation (default: 1,000,000, minimum: 100,000)

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
        self._credentials_index: CredentialsIndex | None = None
        self._current_master_key: MasterKey | None = None
        self._rotation_manager = KeyRotationManager(file_manager=self._file_manager)
        # Internal-only state; no caches or rate limiting retained

        # Initialize or load master key
        self._initialize_master_key()

    def _initialize_master_key(self) -> None:
        """Initialize or load the master key."""
        self._initialize_master_key_with_dependencies(
            master_password=self._master_password,
            data_dir=self._data_dir,
            file_manager=self._file_manager
        )

    def _initialize_master_key_with_dependencies(
        self,
        *,
        master_password: str,
        data_dir: str,
        file_manager: FileManager
    ) -> None:
        """Initialize or load the master key with explicit dependencies.

        Args:
            master_password: Master password for encryption/decryption
            data_dir: Directory to store key files
            file_manager: File manager instance

        Raises:
            MasterKeyError: If master key operations fail
        """
        # Guard against missing master password
        if not master_password:
            raise MasterKeyError("Master password is not set")

        # Guard against missing data directory
        if not data_dir:
            raise MasterKeyError("Data directory is not set")

        # Guard against missing file manager
        if not file_manager:
            raise MasterKeyError("File manager is not initialized")

        try:
            master_keys_data = file_manager.read_master_keys()
            
            if master_keys_data and master_keys_data.get("master_keys"):
                # Load existing master key
                master_key_data = master_keys_data["master_keys"][0]
                master_key = MasterKey.from_dict(master_key_data)
                
                # Validate the password by attempting to decrypt the placeholder credential
                try:
                    # Use iterations from master key data if available, otherwise use default
                    # This ensures backward compatibility with existing master keys
                    iterations = master_key.iterations or self._iterations or Constants.DEFAULT_ITERATIONS()
                    
                    # Derive the master key from the password
                    derived_master_key = CryptoUtils.derive_key_from_password(
                        master_password, 
                        Base58.decode(master_key.salt),
                        iterations=iterations
                    )
                    
                    # Try to decrypt the placeholder credential to validate the password
                    placeholder_credential = Base58.decode(master_key.credentials)
                    decrypted_placeholder = CryptoUtils.decrypt_with_fernet(
                        derived_master_key, 
                        placeholder_credential
                    )
                    
                    # Verify the decrypted data is what we expect (single zero byte)
                    if not CryptoUtils.constant_time_compare(decrypted_placeholder, b"\x00"):
                        # Clean up sensitive data before raising exception
                        CryptoUtils.secure_zero(bytearray(derived_master_key))
                        CryptoUtils.secure_zero(bytearray(decrypted_placeholder))
                        raise MasterKeyError("Invalid master key data")
                    
                    # If decryption succeeds and data is correct, the password is correct
                    self._current_master_key = master_key
                    # Successful validation
                    # Clean up sensitive data
                    CryptoUtils.secure_zero(bytearray(derived_master_key))
                    CryptoUtils.secure_zero(bytearray(decrypted_placeholder))
                    
                except Exception as e:
                    # If decryption fails, the password is wrong
                    logger.warning("Failed authentication attempt", extra={
                        "event": "auth_failed",
                        "reason": "invalid_password",
                        "attempts": 1
                    })
                    raise MasterKeyError(f"Invalid master password: {e}") from e
            else:
                # Create new master key
                key_id = str(uuid.uuid4())
                salt = CryptoUtils.generate_salt()
                derived_key = CryptoUtils.derive_key_from_password(
                    master_password, 
                    salt,
                    iterations=self._iterations
                )

                # Create and encrypt a placeholder credential to validate the password later
                placeholder_data = b"\x00"  # Single zero byte for new master key
                encrypted_placeholder = CryptoUtils.encrypt_with_fernet(
                    derived_key, 
                    placeholder_data
                )

                master_key = MasterKey(
                    key_id=key_id,
                    credentials=Base58.encode(encrypted_placeholder),
                    salt=Base58.encode(salt),
                    iterations=self._iterations,
                )
                self._current_master_key = master_key

                # Save the master key
                file_manager.save_master_keys([master_key.to_dict()])

            # Load or initialize credentials index
            self._load_credentials_index_with_dependencies(
                file_manager=file_manager,
                data_dir=data_dir
            )

        except Exception as e:
            raise MasterKeyError(f"Failed to initialize master key: {e}") from e

    def _load_credentials_index(self) -> None:
        """Load the credentials index from file."""
        self._load_credentials_index_with_dependencies(
            file_manager=self._file_manager,
            data_dir=self._data_dir
        )

    def _load_credentials_index_with_dependencies(
        self,
        *,
        file_manager: FileManager,
        data_dir: str
    ) -> None:
        """Load the credentials index from file with explicit dependencies.

        Args:
            file_manager: File manager instance
            data_dir: Directory to store key files

        Raises:
            ValidationError: If file manager or data directory is not set
        """
        # Guard against missing file manager
        if not file_manager:
            raise ValidationError("File manager is not initialized")

        # Guard against missing data directory
        if not data_dir:
            raise ValidationError("Data directory is not set")

        try:
            self._credentials_index = file_manager.read_credentials_index()
            if self._credentials_index is None:
                # Check if there are credential files that need to be indexed
                credential_files = file_manager.list_credential_files()
                if credential_files:
                    # Rebuild index from existing files
                    self._rebuild_index_from_files_with_dependencies(
                        file_manager=file_manager,
                        data_dir=data_dir
                    )
                else:
                    # Create empty index
                    self._credentials_index = CredentialsIndex()
                    file_manager.save_credentials_index(self._credentials_index)

        except Exception as e:
            # If index loading fails, try to rebuild it
            logging.warning(f"Failed to load credentials index: {e}")
            self._rebuild_index_from_files_with_dependencies(
                file_manager=file_manager,
                data_dir=data_dir
            )

    def _rebuild_index_from_files(self) -> None:
        """Rebuild the credentials index by scanning credential files."""
        self._rebuild_index_from_files_with_dependencies(
            file_manager=self._file_manager,
            data_dir=self._data_dir
        )

    def _rebuild_index_from_files_with_dependencies(
        self,
        *,
        file_manager: FileManager,
        data_dir: str
    ) -> None:
        """Rebuild the credentials index by scanning credential files with explicit dependencies.

        Args:
            file_manager: File manager instance
            data_dir: Directory to store key files

        Raises:
            ValidationError: If file manager or data directory is not set, or if rebuild fails
        """
        # Guard against missing file manager
        if not file_manager:
            raise ValidationError("File manager is not initialized")

        # Guard against missing data directory
        if not data_dir:
            raise ValidationError("Data directory is not set")

        self._credentials_index = CredentialsIndex()

        try:
            credential_files = file_manager.list_credential_files()
            for key_id in credential_files:
                try:
                    credential_file = file_manager.read_credential_file(key_id)
                    if credential_file:
                        self._credentials_index.add_credential(
                            key_id, 
                            credential_file.name
                        )
                except Exception as e:
                    # Log the error but continue with other files
                    logging.warning(f"Could not read credential file {key_id}: {e}")

            # Save the rebuilt index
            file_manager.save_credentials_index(self._credentials_index)

        except Exception as e:
            raise ValidationError(f"Failed to rebuild index: {e}") from e

    def _should_rebuild_index(self) -> bool:
        """Check if the index should be rebuilt."""
        return self._should_rebuild_index_with_dependencies(
            file_manager=self._file_manager,
            data_dir=self._data_dir,
            credentials_index=self._credentials_index
        )

    def _should_rebuild_index_with_dependencies(
        self,
        *,
        file_manager: FileManager,
        data_dir: str,
        credentials_index: CredentialsIndex | None
    ) -> bool:
        """Check if the index should be rebuilt with explicit dependencies.

        Args:
            file_manager: File manager instance
            data_dir: Directory to store key files
            credentials_index: Current credentials index

        Returns:
            True if index should be rebuilt, False otherwise
        """
        # Guard against missing file manager
        if not file_manager:
            return False

        # Guard against missing data directory
        if not data_dir:
            return False

        master_keys_data = file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            return False

        # Check if there are credential files that aren't in the index
        try:
            credential_files = file_manager.list_credential_files()
            if not credentials_index:
                return len(credential_files) > 0

            indexed_credentials = set(credentials_index.credentials.keys())
            file_credentials = set(credential_files)

            return file_credentials != indexed_credentials

        except Exception:
            return True

    def _check_name_uniqueness(
        self, 
        name: str, 
        exclude_key_id: str | None = None
    ) -> None:
        """Check that a credential name is unique.

        Args:
            name: Name to check
            exclude_key_id: Key ID to exclude from uniqueness check (for updates)

        Raises:
            ValidationError: If name is not unique or invalid
        """
        self._check_name_uniqueness_with_dependencies(
            name=name,
            exclude_key_id=exclude_key_id,
            credentials_index=self._credentials_index
        )

    def _check_name_uniqueness_with_dependencies(
        self,
        *,
        name: str,
        exclude_key_id: str | None,
        credentials_index: CredentialsIndex | None
    ) -> None:
        """Check that a credential name is unique with explicit dependencies.

        Args:
            name: Name to check
            exclude_key_id: Key ID to exclude from uniqueness check (for updates)
            credentials_index: Current credentials index

        Raises:
            ValidationError: If name is not unique or invalid
        """
        # Guard against None name parameter
        if name is None:
            raise ValidationError("Credential name cannot be None")

        # Guard against empty name parameter
        if name == "":
            raise ValidationError("Credential name cannot be empty")

        # Guard against whitespace-only name parameter
        if name.strip() == "":
            raise ValidationError("Credential name cannot contain only whitespace")

        # Ensure credentials index is initialized
        if credentials_index is None:
            credentials_index = CredentialsIndex()

        if credentials_index.has_name(name):
            # If we're updating, check if the name belongs to the same credential
            if exclude_key_id:
                existing_key_id = credentials_index.get_key_id(name)
                if existing_key_id == exclude_key_id:
                    return  # Same credential, name is fine

            raise ValidationError(f"Credential name '{name}' already exists")

    def create_credential(
        self,
        *,
        name: str,
        credentials: dict[str, Any],
        meta_data: dict[str, Any] | None = None,
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
        # Guard against None name parameter
        if name is None:
            raise ValidationError("Credential name cannot be None")

        # Guard against empty name parameter
        if name == "":
            raise ValidationError("Credential name cannot be empty")

        # Guard against whitespace-only name parameter
        if name.strip() == "":
            raise ValidationError("Credential name cannot contain only whitespace")

        # Guard against None credentials parameter
        if credentials is None:
            raise ValidationError("Credentials cannot be None")

        # Guard against empty credentials parameter
        if credentials == {}:
            raise ValidationError("Credentials cannot be empty")

        # Check name uniqueness
        self._check_name_uniqueness(name)

        # Generate unique key ID
        key_id = str(uuid.uuid4())

        # Generate encryption key for this credential
        credential_key = CryptoUtils.generate_random_key()

        # Use iterations from master key data if available, otherwise use default
        # This ensures backward compatibility with existing master keys
        iterations = self._current_master_key.iterations or self._iterations or Constants.DEFAULT_ITERATIONS()
        
        # Derive the master key from the password
        derived_master_key = CryptoUtils.derive_key_from_password(
            self._master_password, 
            Base58.decode(self._current_master_key.salt),
            iterations=iterations
        )

        # Encrypt the credential key with the master key
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(
            credential_key, 
            derived_master_key
        )

        # Create credential data
        credential_data = CredentialData(
            credentials=credentials,
            meta_data=meta_data or {},
        )

        # Encrypt the credential data
        encrypted_data = CryptoUtils.encrypt_with_fernet(
            credential_key, 
            json.dumps(credential_data.to_dict()).encode("utf-8")
        )

        # Combine encrypted key and data
        combined_data = {
            "encrypted_key": Base58.encode(encrypted_key),
            "encrypted_data": Base58.encode(encrypted_data),
        }

        # Create credential file
        credential_file = CredentialFile(
            key_id=key_id,
            name=name,
            salt=Base58.encode(salt),
            data=Base58.encode(json.dumps(combined_data).encode("utf-8")),
        )

        try:
            # Save credential file
            self._file_manager.save_credential_file(key_id, credential_file)

            # Update index
            if self._credentials_index is None:
                self._credentials_index = CredentialsIndex()

            self._credentials_index.add_credential(key_id, name)
            self._file_manager.save_credentials_index(self._credentials_index)

            return key_id

        except Exception as e:
            if isinstance(e, (ValidationError, EncryptionError)):
                raise
            raise EncryptionError(f"Failed to create credential: {e}") from e

    def read_credential(self, key_id: str) -> dict[str, Any]:
        """Read a credential by key ID.

        Args:
            key_id: Key ID of the credential

        Returns:
            Credential data as dictionary

        Raises:
            ValidationError: If key_id is empty
            KeyNotFoundError: If credential is not found
            EncryptionError: If decryption fails
        """
        # Guard against None key_id parameter
        if key_id is None:
            raise ValidationError("Key ID cannot be None")

        # Guard against empty key_id parameter
        if key_id == "":
            raise ValidationError("Key ID cannot be empty")

        # Guard against whitespace-only key_id parameter
        if key_id.strip() == "":
            raise ValidationError("Key ID cannot contain only whitespace")

        try:
            # Load credential file
            credential_file = self._file_manager.read_credential_file(key_id)
            if not credential_file:
                raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found")

            # Decode the combined data
            combined_data_json = Base58.decode(credential_file.data).decode("utf-8")
            combined_data = json.loads(combined_data_json)

            # Use iterations from master key data if available, otherwise use default
            # This ensures backward compatibility with existing master keys
            iterations = self._current_master_key.iterations or self._iterations or Constants.DEFAULT_ITERATIONS()
            
            # Derive the master key from the password
            derived_master_key = CryptoUtils.derive_key_from_password(
                self._master_password, 
                Base58.decode(self._current_master_key.salt),
                iterations=iterations
            )

            # Decrypt the credential key using the master key
            credential_key = CryptoUtils.decrypt_key_with_master(
                Base58.decode(combined_data["encrypted_key"]),
                derived_master_key,
                Base58.decode(credential_file.salt),
            )

            # Decrypt the credential data
            decrypted_data = CryptoUtils.decrypt_with_fernet(
                credential_key, 
                Base58.decode(combined_data["encrypted_data"])
            )

            # Parse the decrypted data
            credential_data_dict = json.loads(decrypted_data.decode("utf-8"))

            return credential_data_dict

        except Exception as e:
            if isinstance(e, (ValidationError, KeyNotFoundError, EncryptionError)):
                raise
            raise EncryptionError(f"Failed to read credential: {e}") from e

    def update_credential(
        self,
        *,
        key_id: str,
        name: str | None = None,
        credentials: dict[str, Any] | None = None,
        meta_data: dict[str, Any] | None = None,
    ) -> None:
        """Update an existing credential.

        Args:
            key_id: Key ID of the credential to update
            name: New name (optional)
            credentials: New credentials (optional)
            meta_data: New metadata (optional)

        Raises:
            ValidationError: If key_id is empty or name is invalid
            KeyNotFoundError: If credential is not found
            EncryptionError: If encryption fails
        """
        # Guard against None key_id parameter
        if key_id is None:
            raise ValidationError("Key ID cannot be None")

        # Guard against empty key_id parameter
        if key_id == "":
            raise ValidationError("Key ID cannot be empty")

        # Guard against whitespace-only key_id parameter
        if key_id.strip() == "":
            raise ValidationError("Key ID cannot contain only whitespace")

        # Guard against None name parameter (if provided)
        if name is not None and name is None:
            raise ValidationError("Credential name cannot be None")

        # Guard against empty name parameter (if provided)
        if name is not None and name == "":
            raise ValidationError("Credential name cannot be empty")

        # Guard against whitespace-only name parameter (if provided)
        if name is not None and name.strip() == "":
            raise ValidationError("Credential name cannot contain only whitespace")

        # Guard against None credentials parameter (if provided)
        if credentials is not None and credentials is None:
            raise ValidationError("Credentials cannot be None")

        # Guard against empty credentials parameter (if provided)
        if credentials is not None and credentials == {}:
            raise ValidationError("Credentials cannot be empty")

        # Read existing credential file and data
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found")
            
        existing_data = self.read_credential(key_id)
        current_name = credential_file.name

        # Update fields if provided
        if name is not None:
            self._check_name_uniqueness(name, exclude_key_id=key_id)
            current_name = name

        if credentials is not None:
            existing_data["credentials"] = credentials

        if meta_data is not None:
            existing_data["meta_data"] = meta_data

        # Re-encrypt and save
        credential_key = CryptoUtils.generate_random_key()
        
        # Use iterations from master key data if available, otherwise use default
        # This ensures backward compatibility with existing master keys
        iterations = self._current_master_key.iterations or self._iterations or Constants.DEFAULT_ITERATIONS()
        
        # Derive the master key from the password
        derived_master_key = CryptoUtils.derive_key_from_password(
            self._master_password, 
            Base58.decode(self._current_master_key.salt),
            iterations=iterations
        )
        
        encrypted_key, salt = CryptoUtils.encrypt_key_with_master(
            credential_key, 
            derived_master_key
        )

        encrypted_data = CryptoUtils.encrypt_with_fernet(
            credential_key, 
            json.dumps(existing_data).encode("utf-8")
        )

        # Combine encrypted key and data
        combined_data = {
            "encrypted_key": Base58.encode(encrypted_key),
            "encrypted_data": Base58.encode(encrypted_data),
        }

        # Create updated credential file
        credential_file = CredentialFile(
            key_id=key_id,
            name=current_name,
            salt=Base58.encode(salt),
            data=Base58.encode(json.dumps(combined_data).encode("utf-8")),
        )

        # Save updated credential file
        self._file_manager.save_credential_file(key_id, credential_file)

        # Update index if name changed
        if name is not None and self._credentials_index:
            self._credentials_index.update_credential_name(key_id, name)
            self._file_manager.save_credentials_index(self._credentials_index)

    def delete_credential(self, key_id: str) -> None:
        """Delete a credential.

        Args:
            key_id: Key ID of the credential to delete

        Raises:
            ValidationError: If key_id is empty
            KeyNotFoundError: If credential is not found
        """
        # Guard against None key_id parameter
        if key_id is None:
            raise ValidationError("Key ID cannot be None")

        # Guard against empty key_id parameter
        if key_id == "":
            raise ValidationError("Key ID cannot be empty")

        # Guard against whitespace-only key_id parameter
        if key_id.strip() == "":
            raise ValidationError("Key ID cannot contain only whitespace")

        # Check if credential exists
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            raise KeyNotFoundError(f"Credential with key ID '{key_id}' not found")

        # Delete credential file
        self._file_manager.delete_credential_file(key_id)

        # Update index
        if self._credentials_index:
            self._credentials_index.remove_credential(key_id)
            self._file_manager.save_credentials_index(self._credentials_index)

    def find_credential_by_name(self, name: str) -> dict[str, Any] | None:
        """Find a credential by name.

        Args:
            name: Name of the credential

        Returns:
            Credential info dictionary with key_id and name, or None if not found

        Raises:
            ValidationError: If name is empty
            KeyNotFoundError: If no credentials index is available
        """
        # Guard against None name parameter
        if name is None:
            raise ValidationError("Name cannot be None")

        # Guard against empty name parameter
        if name == "":
            raise ValidationError("Name cannot be empty")

        # Guard against whitespace-only name parameter
        if name.strip() == "":
            raise ValidationError("Name cannot contain only whitespace")

        if not self._credentials_index:
            raise KeyNotFoundError("No credentials index available")

        key_id = self._credentials_index.get_key_id(name)
        if not key_id:
            return None

        return {"key_id": key_id, "name": name}

    def list_credentials(self) -> list[dict[str, Any]]:
        """List all credentials.

        Returns:
            List of credential info dictionaries
        """
        if not self._credentials_index:
            return []

        credentials = []
        for key_id, name in self._credentials_index.credentials.items():
            credentials.append({"key_id": key_id, "name": name})

        return credentials

    def rebuild_index(self) -> None:
        """Manually rebuild the credentials index from files."""
        self._rebuild_index_from_files()

    def backup_credentials(self, backup_dir: str) -> None:
        """Backup all credentials to a directory.

        Args:
            backup_dir: Directory to backup to

        Raises:
            ValidationError: If backup_dir is empty
            FileOperationError: If backup fails
        """
        # Guard against None backup_dir parameter
        if backup_dir is None:
            raise ValidationError("Backup directory cannot be None")

        # Guard against empty backup_dir parameter
        if backup_dir == "":
            raise ValidationError("Backup directory cannot be empty")

        # Guard against whitespace-only backup_dir parameter
        if backup_dir.strip() == "":
            raise ValidationError("Backup directory cannot contain only whitespace")

        # Guard against missing data directory
        if not self._data_dir:
            raise ValidationError("Data directory is not set")

        try:
            backup_path = Path(backup_dir)
            backup_path.mkdir(parents=True, exist_ok=True)

            # Copy all files
            shutil.copytree(
                self._data_dir, 
                backup_path, 
                dirs_exist_ok=True
            )

        except Exception as e:
            raise ValidationError(f"Backup failed: {e}") from e

    def rotate_master_key(
        self,
        *,
        new_iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None
    ) -> str:
        """Rotate the master key by generating a new encryption key from the same password.

        This operation re-encrypts all credentials with a new master key derived
        from the same master password but with a new salt.

        Args:
            new_iterations: New iterations for key derivation (optional, defaults to current or 1,000,000)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional, defaults to 30)

        Returns:
            Rotation ID for tracking the operation

        Raises:
            KeyRotationError: If rotation fails
            ValidationError: If parameters are invalid
        """
        return self._rotation_manager.rotate_master_key(
            master_password=self._master_password,
            new_iterations=new_iterations,
            create_backup=create_backup,
            backup_retention_days=backup_retention_days
        )

    def change_master_password(
        self,
        *,
        new_master_password: str,
        new_iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None
    ) -> str:
        """Change the master password and rotate the master key.

        This operation re-encrypts all credentials with a new master key derived
        from the new master password.

        Args:
            new_master_password: New master password
            new_iterations: New iterations for key derivation (optional, defaults to current or 1,000,000)
            create_backup: Whether to create a backup before rotation
            backup_retention_days: Days to retain backup (optional, defaults to 30)

        Returns:
            Rotation ID for tracking the operation

        Raises:
            KeyRotationError: If rotation fails
            ValidationError: If parameters are invalid
        """
        return self._rotation_manager.change_master_password(
            old_master_password=self._master_password,
            new_master_password=new_master_password,
            old_iterations=self._iterations,
            new_iterations=new_iterations,
            create_backup=create_backup,
            backup_retention_days=backup_retention_days
        )

    def rotate_all_credentials(
        self,
        *,
        iterations: int | None = None,
        create_backup: bool = True,
        backup_retention_days: int | None = None,
        batch_size: int | None = None
    ) -> str:
        """Rotate encryption keys for all credentials.

        This operation re-encrypts all credentials with new individual keys while
        keeping the same master key.

        Args:
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
        return self._rotation_manager.rotate_all_credentials(
            master_password=self._master_password,
            iterations=iterations,
            create_backup=create_backup,
            backup_retention_days=backup_retention_days,
            batch_size=batch_size
        )

    def rollback_rotation(
        self,
        *,
        rotation_id: str
    ) -> None:
        """Rollback a key rotation operation using backup data.

        Args:
            rotation_id: ID of the rotation to rollback

        Raises:
            RotationRollbackError: If rollback fails
            ValidationError: If parameters are invalid
        """
        self._rotation_manager.rollback_rotation(
            rotation_id=rotation_id,
            master_password=self._master_password
        )

    def get_rotation_history(
        self,
        *,
        limit: int | None = None
    ) -> list[RotationHistory]:
        """Get rotation history.

        Args:
            limit: Maximum number of history entries to return (optional)

        Returns:
            List of rotation history entries

        Raises:
            RotationHistoryError: If history retrieval fails
        """
        return self._rotation_manager.get_rotation_history(limit=limit)

    def cleanup_expired_backups(self) -> int:
        """Clean up expired rotation backups.

        Returns:
            Number of backups cleaned up
        """
        return self._rotation_manager.cleanup_expired_backups()

    @property
    def data_directory(self) -> str:
        """Get the data directory."""
        return self._data_dir

    @property
    def master_key_id(self) -> str:
        """Get the master key ID."""
        return self._current_master_key.key_id if self._current_master_key else ""

    @property
    def credential_count(self) -> int:
        """Get the number of credentials."""
        if not self._credentials_index:
            return 0
        return len(self._credentials_index.credentials)

    @property
    def iterations(self) -> int | None:
        """Get the iterations value used for key derivation.
        
        Returns:
            The iterations value, or None if using default iterations
        """
        return self._iterations

    def __enter__(self) -> "KeyCustodian":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        self.cleanup()

    def cleanup(self) -> None:
        """Clean up sensitive data from memory."""
        # Clear sensitive data
        if hasattr(self, '_master_password'):
            CryptoUtils.secure_zero_string(self._master_password)
            self._master_password = None
        # No caches or rate limiting state to clear
