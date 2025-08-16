"""Stateless rotation operations for re-encrypting credentials."""

import json
import logging
from typing import Any

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import KeyRotationError
from splurge_key_custodian.file_manager import FileManager
from splurge_key_custodian.models import CredentialFile, MasterKey

logger = logging.getLogger(__name__)


def re_encrypt_with_new_master(
    key_id: str,
    master_password: str,
    new_master_key: MasterKey,
    file_manager: FileManager,
    new_iterations: int | None = None
) -> None:
    """Re-encrypt a credential with a new master key.

    Args:
        key_id: Key ID of the credential to re-encrypt
        master_password: Master password for decryption
        new_master_key: New master key to use for encryption
        file_manager: File manager instance
        new_iterations: New iterations for key derivation (optional)
    """
    # Read current credential
    credential_data = file_manager.read_credential_file(key_id)
    if not credential_data:
        raise KeyRotationError(f"Credential {key_id} not found")

    # Read current master key for decryption
    master_keys_data = file_manager.read_master_keys()
    if not master_keys_data or not master_keys_data.get("master_keys"):
        raise KeyRotationError("No master keys found")

    current_master_key_data = master_keys_data["master_keys"][0]
    current_salt = Base58.decode(current_master_key_data["salt"])
    current_iterations = current_master_key_data.get("iterations", Constants.DEFAULT_ITERATIONS())

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
    file_manager.save_credential_file(key_id, credential_data)


def re_encrypt_for_password_change(
    key_id: str,
    current_master_password: str,
    new_master_password: str,
    new_master_salt: bytes,
    file_manager: FileManager,
    current_iterations: int | None = None,
    new_iterations: int | None = None
) -> None:
    """Re-encrypt a credential for master password change.

    Args:
        key_id: Key ID of the credential to re-encrypt
        current_master_password: Current master password for decryption
        new_master_password: New master password for encryption
        new_master_salt: New master salt for key derivation
        file_manager: File manager instance
        current_iterations: Current iterations for key derivation (optional)
        new_iterations: New iterations for key derivation (optional)
    """
    # Read current credential
    credential_data = file_manager.read_credential_file(key_id)
    if not credential_data:
        raise KeyRotationError(f"Credential {key_id} not found")

    # Read current master key for decryption
    master_keys_data = file_manager.read_master_keys()
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
    file_manager.save_credential_file(key_id, credential_data)


def re_encrypt_with_new_key(
    key_id: str,
    master_password: str,
    file_manager: FileManager,
    iterations: int | None = None
) -> None:
    """Re-encrypt a credential with a new individual key.

    Args:
        key_id: Key ID of the credential to re-encrypt
        master_password: Master password for decryption/encryption
        file_manager: File manager instance
        iterations: Iterations for key derivation (optional)
    """
    # Read current credential
    credential_data = file_manager.read_credential_file(key_id)
    if not credential_data:
        raise KeyRotationError(f"Credential {key_id} not found")

    # Read current master key
    master_keys_data = file_manager.read_master_keys()
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
    file_manager.save_credential_file(key_id, credential_data)
