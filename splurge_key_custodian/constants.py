"""Library-wide constants.

These constants centralize tunable values used across modules to keep
behavior consistent and avoid duplication.
"""



class Constants:

    # Password policy  
    _MIN_PASSWORD_LENGTH: int = 32
    _MAX_PASSWORD_LENGTH: int = 512
    _MIN_ITERATIONS: int = 10_000
    _DEFAULT_ITERATIONS: int = 1_000_000
    _DEFAULT_SALT_SIZE: int = 64
    _MIN_SALT_SIZE: int = 32
    _KEY_SIZE: int = 256
    _KEY_SIZE_BYTES: int = 32
    _ALLOWABLE_ALPHA_UPPER: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    _ALLOWABLE_ALPHA_LOWER: str = "abcdefghijklmnopqrstuvwxyz"
    _ALLOWABLE_DIGITS: str = "0123456789"
    _ALLOWABLE_SPECIAL: str = '!@#$%^&*_+-=[],.?;'
    _MAX_CREDENTIAL_NAME_LENGTH: int = 256

    # Key rotation policy
    _MAX_ROTATION_HISTORY: int = 10  # Maximum number of rotation history entries to keep
    _BACKUP_RETENTION_DAYS: int = 30  # Days to keep rotation backups
    _ROTATION_BATCH_SIZE: int = 50  # Number of credentials to rotate in a batch

    @classmethod
    def MAX_CREDENTIAL_NAME_LENGTH(cls) -> int:
        return cls._MAX_CREDENTIAL_NAME_LENGTH

    @classmethod
    def ALLOWABLE_ALPHA_UPPER(cls) -> str:
        return cls._ALLOWABLE_ALPHA_UPPER

    @classmethod
    def ALLOWABLE_ALPHA_LOWER(cls) -> str:
        return cls._ALLOWABLE_ALPHA_LOWER
    
    @classmethod
    def ALLOWABLE_DIGITS(cls) -> str:
        return cls._ALLOWABLE_DIGITS
    
    @classmethod
    def ALLOWABLE_SPECIAL(cls) -> str:
        return cls._ALLOWABLE_SPECIAL
    
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
    def ROTATION_BATCH_SIZE(cls) -> int:
        return cls._ROTATION_BATCH_SIZE
