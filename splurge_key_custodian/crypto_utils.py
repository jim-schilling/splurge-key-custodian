"""Cryptographic utilities for the Splurge Key Custodian File system."""

import base64
import hmac
import secrets

from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.exceptions import EncryptionError
from splurge_key_custodian.exceptions import ValidationError


class CryptoUtils:
    """Cryptographic utilities for key operations."""

    _KEY_SIZE = 256  # Fixed 256-bit key size
    _KEY_SIZE_BYTES = 32  # 256 bits = 32 bytes
    _DEFAULT_ITERATIONS = 1000000  # 1,000,000 iterations
    _MIN_ITERATIONS = 500000  # Minimum iterations for security
    _SALT_SIZE = 64  # 64-byte salt
    _MIN_SALT_SIZE = 32  # Minimum salt size for security
    _B58_ALPHANUMERIC = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    _SPECIAL = '!@#$%^&*()_+-='
    _B58_NUMERIC = '123456789'    

    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Perform constant-time comparison of two byte strings.
        
        Args:
            a: First byte string
            b: Second byte string
            
        Returns:
            True if strings are equal, False otherwise
        """
        return hmac.compare_digest(a, b)

    @classmethod
    def generate_base58_like_random_string(cls) -> str:
        """Generate a random Base58-like string.

        Returns:
            Random Base58-like string
        """
        result = ''.join(secrets.choice(cls._B58_ALPHANUMERIC) for _ in range(54))
        result += ''.join(secrets.choice(cls._SPECIAL) for _ in range(4))
        result += ''.join(secrets.choice(cls._B58_NUMERIC) for _ in range(6))
        
        # Use cryptographically secure Fisher-Yates shuffle
        result_list = list(result)
        for i in range(len(result_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            result_list[i], result_list[j] = result_list[j], result_list[i]
        
        return ''.join(result_list)

    @classmethod
    def generate_random_key(cls) -> bytes:
        """Generate a random 256-bit key.

        Returns:
            Random 256-bit key as bytes
        """
        return secrets.token_bytes(cls._KEY_SIZE_BYTES)

    @classmethod
    def generate_salt(cls) -> bytes:
        """Generate a random salt.

        Returns:
            Random salt as bytes
        """
        return secrets.token_bytes(cls._SALT_SIZE)

    @classmethod
    def derive_key_from_password(
        cls, 
        password: str, 
        salt: bytes,
        *, 
        iterations: Optional[int] = None
    ) -> bytes:
        """Derive a key from a password using PBKDF2.

        Args:
            password: Password to derive key from
            salt: Salt for key derivation
            iterations: Number of iterations (default: 1,000,000)

        Returns:
            Derived key as bytes

        Raises:
            EncryptionError: If key derivation fails
            ValidationError: If parameters are invalid
        """
        # Validate password
        if not password or not isinstance(password, str):
            raise ValidationError("Password must be a non-empty string")
        
        # Validate salt
        if not salt or len(salt) < cls._MIN_SALT_SIZE:
            raise ValidationError(f"Salt must be at least {cls._MIN_SALT_SIZE} bytes")
        
        # Validate iterations
        if iterations is None:
            iterations = cls._DEFAULT_ITERATIONS
        elif iterations < cls._MIN_ITERATIONS:
            raise ValidationError(f"Iterations must be at least {cls._MIN_ITERATIONS}")

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=cls._KEY_SIZE_BYTES,
                salt=salt,
                iterations=iterations,
            )
            return kdf.derive(password.encode("utf-8"))
        except Exception as e:
            raise EncryptionError(f"Key derivation failed: {e}") from e

    @classmethod
    def derive_key_from_master_key(
        cls, 
        master_key: bytes, 
        salt: bytes, 
        *, 
        iterations: Optional[int] = None
    ) -> bytes:
        """Derive a key from a master key using PBKDF2.

        Args:
            master_key: Master key to derive from
            salt: Salt for key derivation
            iterations: Number of iterations (default: 1,000,000)

        Returns:
            Derived key as bytes

        Raises:
            EncryptionError: If key derivation fails
        """
        if iterations is None:
            iterations = cls._DEFAULT_ITERATIONS

        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=cls._KEY_SIZE_BYTES,
                salt=salt,
                iterations=iterations,
            )
            return kdf.derive(master_key)
        except Exception as e:
            raise EncryptionError(f"Key derivation failed: {e}") from e

    @staticmethod
    def encrypt_with_fernet(key: bytes, data: bytes) -> bytes:
        """Encrypt data using Fernet (AES-128-CBC with HMAC-SHA256).

        Args:
            key: Encryption key (32 bytes)
            data: Data to encrypt

        Returns:
            Encrypted data as bytes

        Raises:
            EncryptionError: If encryption fails
            ValidationError: If key size is invalid
        """
        # Validate key size
        if len(key) != CryptoUtils._KEY_SIZE_BYTES:
            raise ValidationError(f"Key must be exactly {CryptoUtils._KEY_SIZE_BYTES} bytes")
        
        # Validate data
        if not data:
            raise ValidationError("Data cannot be empty")

        try:
            fernet = Fernet(base64.urlsafe_b64encode(key))
            return fernet.encrypt(data)
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e

    @staticmethod
    def decrypt_with_fernet(
        key: bytes, 
        encrypted_data: bytes
    ) -> bytes:
        """Decrypt data using Fernet (AES-128-CBC with HMAC-SHA256).

        Args:
            key: Decryption key (32 bytes)
            encrypted_data: Data to decrypt

        Returns:
            Decrypted data as bytes

        Raises:
            EncryptionError: If decryption fails
            ValidationError: If key size is invalid
        """
        # Validate key size
        if len(key) != CryptoUtils._KEY_SIZE_BYTES:
            raise ValidationError(f"Key must be exactly {CryptoUtils._KEY_SIZE_BYTES} bytes")
        
        # Validate encrypted data
        if not encrypted_data:
            raise ValidationError("Encrypted data cannot be empty")

        try:
            fernet = Fernet(base64.urlsafe_b64encode(key))
            return fernet.decrypt(encrypted_data)
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {e}") from e

    @classmethod
    def encrypt_key_with_master(
        cls, 
        key: bytes, 
        master_key: bytes, 
        salt: Optional[bytes] = None
    ) -> tuple[bytes, bytes]:
        """Encrypt a key using a master key.

        Args:
            key: Key to encrypt
            master_key: Master key for encryption
            salt: Salt for key derivation (generated if not provided)

        Returns:
            Tuple of (encrypted_key, salt)

        Raises:
            EncryptionError: If encryption fails
        """
        if salt is None:
            salt = cls.generate_salt()

        try:
            # Derive a key from the master key using the salt
            derived_key = cls.derive_key_from_master_key(master_key, salt)

            # Encrypt the key using the derived key
            encrypted_key = cls.encrypt_with_fernet(derived_key, key)

            return encrypted_key, salt

        except Exception as e:
            raise EncryptionError(f"Key encryption failed: {e}") from e

    @classmethod
    def decrypt_key_with_master(
        cls, 
        encrypted_key: bytes, 
        master_key: bytes, 
        salt: bytes
    ) -> bytes:
        """Decrypt a key using a master key.

        Args:
            encrypted_key: Encrypted key
            master_key: Master key for decryption
            salt: Salt used for key derivation

        Returns:
            Decrypted key as bytes

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            derived_key = cls.derive_key_from_master_key(master_key, salt)
            return cls.decrypt_with_fernet(derived_key, encrypted_key)
        except Exception as e:
            raise EncryptionError(f"Key decryption failed: {e}") from e

    @staticmethod
    def secure_zero(data: bytearray) -> None:
        """Securely zero sensitive data from memory.
        
        Args:
            data: Data to zero (must be bytearray for in-place modification)
        """
        if data:
            # Zero the data in place
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def secure_zero_string(data: str) -> None:
        """Securely zero sensitive string data from memory.
        
        Args:
            data: String data to zero
        """
        if data:
            # Convert to bytearray and zero
            data_bytes = bytearray(data.encode('utf-8'))
            CryptoUtils.secure_zero(data_bytes)
