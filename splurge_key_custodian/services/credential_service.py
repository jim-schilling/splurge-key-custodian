"""Credential service for managing credential operations."""

import json
import logging
import uuid
from typing import Any, Dict

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import (
    FileOperationError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import CredentialFile
from splurge_key_custodian.validation_utils import validate_credential_name

logger = logging.getLogger(__name__)


class CredentialService:
    """Service for managing credential operations."""

    def __init__(self, file_manager: FileManager):
        """Initialize the credential service.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager

    def create_credential(
        self,
        name: str,
        credentials: Dict[str, Any],
        master_password: str,
        iterations: int | None = None,
        meta_data: Dict[str, Any] | None = None
    ) -> str:
        """Create a new credential.
        
        Args:
            name: Name of the credential
            credentials: Dictionary containing credential data
            master_password: Master password for encryption
            iterations: Iterations for key derivation (optional)
            
        Returns:
            Key ID of the created credential
            
        Raises:
            ValidationError: If name or credentials are invalid
            FileOperationError: If file operations fail
        """
        # Validate credential name
        validate_credential_name(name)
        
        # Validate credentials data
        if credentials is None:
            raise ValidationError("Credentials cannot be None")
        
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")
        
        if not credentials:
            raise ValidationError("Credentials cannot be empty")
        
        # Check for duplicate name
        existing_credentials = self._file_manager.list_credential_files()
        for existing_key_id in existing_credentials:
            existing_file = self._file_manager.read_credential_file(existing_key_id)
            if existing_file and existing_file.name == name:
                raise ValidationError(f"Credential name '{name}' already exists")
        
        # Generate unique key ID
        key_id = str(uuid.uuid4())
        
        # Load master key for encryption
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            raise FileOperationError("No master key found")
        
        master_key_data = master_keys_data["master_keys"][0]
        salt = Base58.decode(master_key_data["salt"])
        master_iterations = master_key_data.get("iterations", Constants.DEFAULT_ITERATIONS())
        
        # Derive master key from password
        # Always use the iterations from the master key file to ensure compatibility after rotation
        master_key = CryptoUtils.derive_key_from_password(
            master_password,
            salt,
            iterations=master_iterations
        )
        
        # Generate credential-specific encryption key
        credential_key = CryptoUtils.generate_random_key()
        
        # Create credential data structure
        credential_data = {
            "credentials": credentials,
            "meta_data": meta_data or {}
        }
        
        # Encrypt credential data with credential key
        credential_json = json.dumps(credential_data, ensure_ascii=False)
        encrypted_data = CryptoUtils.encrypt_with_fernet(
            credential_key,
            credential_json.encode("utf-8")
        )
        
        # Encrypt credential key with master key
        encrypted_key, key_salt = CryptoUtils.encrypt_key_with_master(
            credential_key,
            master_key
        )
        
        # Combine encrypted key and data
        combined_data = {
            "encrypted_key": Base58.encode(encrypted_key),
            "encrypted_data": Base58.encode(encrypted_data)
        }
        
        # Create credential file
        credential_file = CredentialFile(
            key_id=key_id,
            name=name,
            salt=Base58.encode(key_salt),
            data=Base58.encode(json.dumps(combined_data).encode("utf-8")),
            rotation_version=0
        )
        
        # Save credential file
        self._file_manager.save_credential_file(key_id, credential_file)
        
        logger.info("Credential created successfully", extra={
            "key_id": key_id,
            "name": name,
            "event": "credential_created"
        })
        
        return key_id

    def read_credential(
        self,
        key_id: str,
        master_password: str,
        iterations: int | None = None
    ) -> Dict[str, Any]:
        """Read a credential by key ID.
        
        Args:
            key_id: Key ID of the credential to read
            master_password: Master password for decryption
            iterations: Iterations for key derivation (optional)
            
        Returns:
            Dictionary containing credential data
            
        Raises:
            FileOperationError: If credential not found or file operations fail
            ValidationError: If decryption fails
        """
        # Validate key_id
        if key_id is None:
            raise ValidationError("Key ID cannot be None")
        
        if not key_id:
            raise ValidationError("Key ID cannot be empty")
        
        if not key_id.strip():
            raise ValidationError("Key ID cannot contain only whitespace")
        
        # Load credential file
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            raise FileOperationError(f"Credential {key_id} not found")
        
        # Load master key for decryption
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            raise FileOperationError("No master key found")
        
        master_key_data = master_keys_data["master_keys"][0]
        salt = Base58.decode(master_key_data["salt"])
        master_iterations = master_key_data.get("iterations", Constants.DEFAULT_ITERATIONS())
        
        # Derive master key from password
        # Always use the iterations from the master key file to ensure compatibility after rotation
        master_key = CryptoUtils.derive_key_from_password(
            master_password,
            salt,
            iterations=master_iterations
        )
        
        # Decrypt credential data
        combined_data = json.loads(Base58.decode(credential_file.data).decode("utf-8"))
        
        # Decrypt credential key using master key
        encrypted_key = Base58.decode(combined_data["encrypted_key"])
        credential_key = CryptoUtils.decrypt_key_with_master(
            encrypted_key,
            master_key,
            Base58.decode(credential_file.salt)
        )
        
        # Decrypt credential data using credential key
        encrypted_data = Base58.decode(combined_data["encrypted_data"])
        decrypted_data = CryptoUtils.decrypt_with_fernet(
            credential_key,
            encrypted_data
        )
        
        # Parse credential data
        credential_data = json.loads(decrypted_data.decode("utf-8"))
        
        logger.debug("Credential read successfully", extra={
            "key_id": key_id,
            "name": credential_file.name,
            "event": "credential_read"
        })
        
        # Return in the expected format for backward compatibility
        return credential_data

    def update_credential(
        self,
        key_id: str,
        master_password: str,
        *,
        name: str | None = None,
        credentials: Dict[str, Any] | None = None,
        meta_data: Dict[str, Any] | None = None,
        iterations: int | None = None
    ) -> None:
        """Update a credential.
        
        Args:
            key_id: Key ID of the credential to update
            name: New name for the credential (optional)
            credentials: New credential data (optional)
            master_password: Master password for encryption
            iterations: Iterations for key derivation (optional)
            
        Raises:
            FileOperationError: If credential not found or file operations fail
            ValidationError: If data is invalid
        """
        # Validate key_id
        if key_id is None:
            raise ValidationError("Key ID cannot be None")
        
        if not key_id:
            raise ValidationError("Key ID cannot be empty")
        
        if not key_id.strip():
            raise ValidationError("Key ID cannot contain only whitespace")
        
        # Load existing credential file
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            raise FileOperationError(f"Credential {key_id} not found")
        
        # Update name if provided
        if name is not None:
            validate_credential_name(name)
            credential_file.name = name
        
        # Update credentials and/or metadata if provided
        if credentials is not None or meta_data is not None:
            # Load master key for encryption
            master_keys_data = self._file_manager.read_master_keys()
            if not master_keys_data or not master_keys_data.get("master_keys"):
                raise FileOperationError("No master key found")
            
            master_key_data = master_keys_data["master_keys"][0]
            salt = Base58.decode(master_key_data["salt"])
            master_iterations = master_key_data.get("iterations", Constants.DEFAULT_ITERATIONS())
            
            # Derive master key from password
            # Always use the iterations from the master key file to ensure compatibility after rotation
            master_key = CryptoUtils.derive_key_from_password(
                master_password,
                salt,
                iterations=master_iterations
            )
            
            # Load existing credential data to preserve unchanged fields
            existing_credential_data = {}
            try:
                # Decrypt existing credential data to get current data
                combined_data = json.loads(Base58.decode(credential_file.data).decode("utf-8"))
                encrypted_key = Base58.decode(combined_data["encrypted_key"])
                credential_key = CryptoUtils.decrypt_key_with_master(
                    encrypted_key,
                    master_key,
                    Base58.decode(credential_file.salt)
                )
                encrypted_data = Base58.decode(combined_data["encrypted_data"])
                decrypted_data = CryptoUtils.decrypt_with_fernet(
                    credential_key,
                    encrypted_data
                )
                existing_credential_data = json.loads(decrypted_data.decode("utf-8"))
            except Exception:
                # If decryption fails, use empty data
                existing_credential_data = {"credentials": {}, "meta_data": {}}
            
            # Validate credentials if provided
            if credentials is not None:
                if not isinstance(credentials, dict):
                    raise ValidationError("Credentials must be a dictionary")
                
                if not credentials:
                    raise ValidationError("Credentials cannot be empty")
            
            # Generate new credential-specific encryption key
            credential_key = CryptoUtils.generate_random_key()
            
            # Create credential data structure, preserving existing data for unchanged fields
            credential_data = {
                "credentials": credentials if credentials is not None else existing_credential_data.get("credentials", {}),
                "meta_data": meta_data if meta_data is not None else existing_credential_data.get("meta_data", {})
            }
            
            # Encrypt new credential data
            credential_json = json.dumps(credential_data, ensure_ascii=False)
            encrypted_data = CryptoUtils.encrypt_with_fernet(
                credential_key,
                credential_json.encode("utf-8")
            )
            
            # Encrypt new credential key with master key
            encrypted_key, key_salt = CryptoUtils.encrypt_key_with_master(
                credential_key,
                master_key
            )
            
            # Update combined data
            combined_data = {
                "encrypted_key": Base58.encode(encrypted_key),
                "encrypted_data": Base58.encode(encrypted_data)
            }
            
            # Update credential file
            credential_file.data = Base58.encode(json.dumps(combined_data).encode("utf-8"))
            credential_file.salt = Base58.encode(key_salt)
            credential_file.rotation_version += 1
        
        # Save updated credential file
        self._file_manager.save_credential_file(key_id, credential_file)
        
        logger.info("Credential updated successfully", extra={
            "key_id": key_id,
            "name": credential_file.name,
            "event": "credential_updated"
        })

    def delete_credential(self, key_id: str) -> None:
        """Delete a credential.
        
        Args:
            key_id: Key ID of the credential to delete
            
        Raises:
            FileOperationError: If credential not found or file operations fail
        """
        # Validate key_id
        if key_id is None:
            raise ValidationError("Key ID cannot be None")
        
        if not key_id:
            raise ValidationError("Key ID cannot be empty")
        
        if not key_id.strip():
            raise ValidationError("Key ID cannot contain only whitespace")
        
        # Check if credential exists
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            raise FileOperationError(f"Credential {key_id} not found")
        
        # Delete credential file
        self._file_manager.delete_credential_file(key_id)
        
        logger.info("Credential deleted successfully", extra={
            "key_id": key_id,
            "name": credential_file.name,
            "event": "credential_deleted"
        })

    def list_credentials(self) -> list[Dict[str, Any]]:
        """List all credentials.
        
        Returns:
            List of credential metadata dictionaries
        """
        credential_files = self._file_manager.list_credential_files()
        credentials = []
        
        for key_id in credential_files:
            credential_file = self._file_manager.read_credential_file(key_id)
            if credential_file:
                credentials.append({
                    "key_id": credential_file.key_id,
                    "name": credential_file.name,
                    "rotation_version": credential_file.rotation_version
                })
        
        return credentials

    def get_credential_metadata(self, key_id: str) -> Dict[str, Any] | None:
        """Get metadata for a credential.
        
        Args:
            key_id: Key ID of the credential
            
        Returns:
            Dictionary with credential metadata or None if not found
        """
        credential_file = self._file_manager.read_credential_file(key_id)
        if not credential_file:
            return None
        
        return {
            "key_id": credential_file.key_id,
            "name": credential_file.name,
            "rotation_version": credential_file.rotation_version,
            "salt_length": len(Base58.decode(credential_file.salt)),
            "data_length": len(credential_file.data),
        }

    def find_credential_by_name(self, name: str) -> Dict[str, Any] | None:
        """Find a credential by name.
        
        Args:
            name: Name of the credential to find
            
        Returns:
            Dictionary with key_id and name if found, None otherwise
            
        Raises:
            ValidationError: If name is None, empty, or contains only whitespace
        """
        # Validate name
        if name is None:
            raise ValidationError("Name cannot be None")

        if not name:
            raise ValidationError("Name cannot be empty")
        
        if not name.strip():
            raise ValidationError("Name cannot contain only whitespace")

        # Search through all credential files
        credential_files = self._file_manager.list_credential_files()
        
        for key_id in credential_files:
            credential_file = self._file_manager.read_credential_file(key_id)
            if credential_file and credential_file.name == name:
                return {
                    "key_id": credential_file.key_id,
                    "name": credential_file.name
                }
        
        return None
