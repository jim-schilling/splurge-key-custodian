"""Master key service for managing master key lifecycle."""

import logging
import uuid
from typing import Any

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import (
    FileOperationError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import MasterKey
from splurge_key_custodian.validation_utils import validate_master_password_complexity

logger = logging.getLogger(__name__)


class MasterKeyService:
    """Service for managing master key lifecycle operations."""

    def __init__(self, file_manager: FileManager):
        """Initialize the master key service.
        
        Args:
            file_manager: File manager instance
        """
        self._file_manager = file_manager

    def initialize_master_key(
        self,
        master_password: str,
        iterations: int | None = None
    ) -> MasterKey:
        """Initialize a new master key.
        
        Args:
            master_password: Master password for key derivation
            iterations: Iterations for key derivation (optional)
            
        Returns:
            Created MasterKey object
            
        Raises:
            ValidationError: If password is invalid
            FileOperationError: If file operations fail
        """
        # Validate password complexity
        validate_master_password_complexity(master_password)
        
        # Check if master key already exists
        existing_master_keys = self._file_manager.read_master_keys()
        if existing_master_keys and existing_master_keys.get("master_keys"):
            raise ValidationError("Master key already exists")
        
        # Generate new master key
        key_id = str(uuid.uuid4())
        salt = CryptoUtils.generate_salt()
        iterations = iterations or Constants.DEFAULT_ITERATIONS()
        
        # Derive master key from password
        derived_key = CryptoUtils.derive_key_from_password(
            master_password,
            salt,
            iterations=iterations
        )
        
        # Create placeholder credential for master key
        placeholder_data = b"\x00"
        encrypted_placeholder = CryptoUtils.encrypt_with_fernet(
            derived_key,
            placeholder_data
        )
        
        # Create master key object
        master_key = MasterKey(
            key_id=key_id,
            credentials=Base58.encode(encrypted_placeholder),
            salt=Base58.encode(salt),
        )
        
        # Save master key
        self._file_manager.save_master_keys([master_key.to_dict()])
        
        logger.info("Master key initialized successfully", extra={
            "key_id": key_id,
            "iterations": iterations,
            "event": "master_key_initialized"
        })
        
        return master_key

    def load_master_key(self) -> MasterKey | None:
        """Load the current master key.
        
        Returns:
            MasterKey object if found, None otherwise
        """
        master_keys_data = self._file_manager.read_master_keys()
        if not master_keys_data or not master_keys_data.get("master_keys"):
            return None
        
        master_key_data = master_keys_data["master_keys"][0]
        return MasterKey.from_dict(master_key_data)

    def validate_master_password(
        self,
        master_password: str,
        iterations: int | None = None
    ) -> bool:
        """Validate master password against stored master key.
        
        Args:
            master_password: Master password to validate
            iterations: Iterations for key derivation (optional)
            
        Returns:
            True if password is valid, False otherwise
        """
        master_key = self.load_master_key()
        if not master_key:
            return False
        
        try:
            # Derive key from password
            salt = Base58.decode(master_key.salt)
            derived_key = CryptoUtils.derive_key_from_password(
                master_password,
                salt,
                iterations=iterations or Constants.DEFAULT_ITERATIONS()
            )
            
            # Try to decrypt placeholder credential
            encrypted_placeholder = Base58.decode(master_key.credentials)
            decrypted_data = CryptoUtils.decrypt_with_fernet(
                derived_key,
                encrypted_placeholder
            )
            
            # Check if decrypted data matches expected placeholder
            return decrypted_data == b"\x00"
            
        except Exception as e:
            logger.debug(f"Master password validation failed: {e}")
            return False

    def change_master_password(
        self,
        old_master_password: str,
        new_master_password: str,
        old_iterations: int | None = None,
        new_iterations: int | None = None
    ) -> MasterKey:
        """Change the master password.
        
        Args:
            old_master_password: Current master password
            new_master_password: New master password
            old_iterations: Current iterations for key derivation (optional)
            new_iterations: New iterations for key derivation (optional)
            
        Returns:
            Updated MasterKey object
            
        Raises:
            ValidationError: If passwords are invalid
            FileOperationError: If file operations fail
        """
        # Validate new password complexity
        validate_master_password_complexity(new_master_password)
        
        # Validate old password
        if not self.validate_master_password(old_master_password, old_iterations):
            raise ValidationError("Invalid current master password")
        
        # Load current master key
        current_master_key = self.load_master_key()
        if not current_master_key:
            raise FileOperationError("No master key found")
        
        # Generate new master key with new password
        new_key_id = str(uuid.uuid4())
        new_salt = CryptoUtils.generate_salt()
        new_iterations = new_iterations or Constants.DEFAULT_ITERATIONS()
        
        # Derive new master key from new password
        new_derived_key = CryptoUtils.derive_key_from_password(
            new_master_password,
            new_salt,
            iterations=new_iterations
        )
        
        # Create new placeholder credential
        placeholder_data = b"\x00"
        new_encrypted_placeholder = CryptoUtils.encrypt_with_fernet(
            new_derived_key,
            placeholder_data
        )
        
        # Create new master key object
        new_master_key = MasterKey(
            key_id=new_key_id,
            credentials=Base58.encode(new_encrypted_placeholder),
            salt=Base58.encode(new_salt),
        )
        
        # Save new master key
        self._file_manager.save_master_keys([new_master_key.to_dict()])
        
        logger.info("Master password changed successfully", extra={
            "old_key_id": current_master_key.key_id,
            "new_key_id": new_key_id,
            "new_iterations": new_iterations,
            "event": "master_password_changed"
        })
        
        return new_master_key

    def get_master_key_info(self) -> dict[str, Any] | None:
        """Get information about the current master key.
        
        Returns:
            Dictionary with master key information or None if not found
        """
        master_key = self.load_master_key()
        if not master_key:
            return None
        
        return {
            "key_id": master_key.key_id,
            "salt_length": len(Base58.decode(master_key.salt)),
            "credentials_length": len(master_key.credentials),
        }
