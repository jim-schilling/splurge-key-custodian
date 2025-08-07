"""Base-58 encoding and decoding utilities."""

import string
from typing import Any

from splurge_key_custodian.exceptions import ValidationError


class Base58ValidationError(ValidationError):
    """Raised when base-58 validation fails."""


class Base58:
    """
    A class for base-58 encoding and decoding operations.

    Base-58 is a binary-to-text encoding scheme that uses 58 characters
    to represent binary data. It's commonly used in cryptocurrency
    applications and other systems where binary data needs to be
    represented in a human-readable format.

    This implementation uses the Bitcoin alphabet:
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    """

    _ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    _BASE = len(_ALPHABET)

    @classmethod
    def encode(cls, data: bytes) -> str:
        """
        Encode binary data to base-58 string.

        Args:
            data: Binary data to encode

        Returns:
            Base-58 encoded string

        Raises:
            ValidationError: If input data is empty or invalid
        """
        if not data:
            if data is None:
                raise Base58ValidationError("Input cannot be None")
            raise Base58ValidationError("Cannot encode empty data")

        # Convert bytes to integer
        num = int.from_bytes(data, byteorder="big")

        # Handle zero case
        if num == 0:
            return cls._ALPHABET[0] * len(data)

        # Convert to base-58
        result = ""
        while num > 0:
            num, remainder = divmod(num, cls._BASE)
            result = cls._ALPHABET[remainder] + result

        # Add leading zeros for each leading zero byte in original data
        for byte in data:
            if byte == 0:
                result = cls._ALPHABET[0] + result
            else:
                break

        return result

    @classmethod
    def decode(cls, base58_data: str) -> bytes:
        """
        Decode base-58 string to binary data.

        Args:
            base58_data: Base-58 encoded string

        Returns:
            Decoded binary data

        Raises:
            TypeError: If input is not a string
            ValidationError: If input string is empty or contains invalid characters
        """
        if not isinstance(base58_data, str):
            if base58_data is None:
                raise Base58ValidationError("Input cannot be None")
            raise TypeError("Input must be a string")

        if not base58_data:
            raise Base58ValidationError("Cannot decode empty string")

        if not cls.is_valid(base58_data):
            raise Base58ValidationError("Invalid base-58 string")

        # Count leading '1' characters
        leading_ones = 0
        for char in base58_data:
            if char == cls._ALPHABET[0]:
                leading_ones += 1
            else:
                break

        # If all characters are '1', return the appropriate number of zero bytes
        if leading_ones == len(base58_data):
            return b"\x00" * leading_ones

        # Convert base-58 to integer (skip leading ones)
        num = 0
        for char in base58_data[leading_ones:]:
            num = num * cls._BASE + cls._ALPHABET.index(char)

        # Convert integer to bytes
        if num == 0:
            return b"\x00" * leading_ones

        # Calculate minimum byte length
        byte_length = (num.bit_length() + 7) // 8
        result = num.to_bytes(byte_length, byteorder="big")

        # Add leading zeros for each leading '1' character
        return b"\x00" * leading_ones + result

    @classmethod
    def is_valid(cls, base58_data: str) -> bool:
        """
        Check if a string is valid base-58.

        Args:
            base58_data: String to validate

        Returns:
            True if valid base-58, False otherwise
        """
        if not isinstance(base58_data, str):
            return False

        if not base58_data:
            return False

        try:
            return all(char in cls._ALPHABET for char in base58_data)
        except Exception:
            return False

    @classmethod
    def is_valid_base58(cls, base58_data: str) -> bool:
        """
        Check if a string is valid base-58 (alias for is_valid).

        Args:
            base58_data: String to validate

        Returns:
            True if valid base-58, False otherwise
        """
        return cls.is_valid(base58_data)
