"""Library-wide constants.

These constants centralize tunable values used across modules to keep
behavior consistent and avoid duplication.
"""

class Constants:

    # Password policy  
    _MIN_PASSWORD_LENGTH: int = 32
    _MAX_PASSWORD_LENGTH: int = 512
    _MIN_ITERATIONS: int = 100_000
    _DEFAULT_ITERATIONS: int = 1_000_000
    _DEFAULT_SALT_SIZE: int = 64
    _MIN_SALT_SIZE: int = 32
    _KEY_SIZE: int = 256
    _KEY_SIZE_BYTES: int = 32

    # Key rotation policy
    _MAX_ROTATION_HISTORY: int = 10  # Maximum number of rotation history entries to keep
    _BACKUP_RETENTION_DAYS: int = 30  # Days to keep rotation backups
    _MAX_BACKUP_SIZE_MB: int = 100  # Maximum backup size in MB
    _ROTATION_BATCH_SIZE: int = 50  # Number of credentials to rotate in a batch

    @classmethod
    def MIN_PASSWORD_LENGTH(cls) -> int:
        return cls._MIN_PASSWORD_LENGTH

    @classmethod
    def MAX_PASSWORD_LENGTH(cls) -> int:
        return cls._MAX_PASSWORD_LENGTH

    # Iterations policy
    @classmethod
    def MIN_ITERATIONS(cls) -> int:
        return cls._MIN_ITERATIONS

    # Default iterations
    @classmethod
    def DEFAULT_ITERATIONS(cls) -> int:
        return cls._DEFAULT_ITERATIONS

    # Salt size
    @classmethod
    def DEFAULT_SALT_SIZE(cls) -> int:
        return cls._DEFAULT_SALT_SIZE

    # Minimum salt size
    @classmethod
    def MIN_SALT_SIZE(cls) -> int:
        return cls._MIN_SALT_SIZE

    # Key size
    @classmethod
    def KEY_SIZE(cls) -> int:
        return cls._KEY_SIZE

    # Key size in bytes
    @classmethod
    def KEY_SIZE_BYTES(cls) -> int:
        return cls._KEY_SIZE_BYTES

    # Key rotation policy
    @classmethod
    def MAX_ROTATION_HISTORY(cls) -> int:
        return cls._MAX_ROTATION_HISTORY

    @classmethod
    def BACKUP_RETENTION_DAYS(cls) -> int:
        return cls._BACKUP_RETENTION_DAYS

    @classmethod
    def MAX_BACKUP_SIZE_MB(cls) -> int:
        return cls._MAX_BACKUP_SIZE_MB

    @classmethod
    def ROTATION_BATCH_SIZE(cls) -> int:
        return cls._ROTATION_BATCH_SIZE
