"""Data models for the Splurge Key Custodian File system."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class CredentialData:
    """Encrypted credential data structure."""

    credentials: dict[str, Any] = field(default_factory=dict)
    meta_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "credentials": self.credentials,
            "meta_data": self.meta_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CredentialData":
        """Create CredentialData from dictionary."""
        return cls(
            credentials=data.get("credentials", {}),
            meta_data=data.get("meta_data", {}),
        )


@dataclass
class CredentialFile:
    """Individual credential file structure for hybrid approach."""

    key_id: str
    name: str  # Credential name (stored unencrypted for index rebuilding)
    salt: str  # Base58 encoded salt
    data: str  # Base58 encoded encrypted credential data
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rotation_version: int = field(default=1)  # Track key rotation version

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.key_id:
            raise ValueError("key_id cannot be empty")
        if not self.name:
            raise ValueError("name cannot be empty")
        if not self.salt:
            raise ValueError("salt cannot be empty")
        if not self.data:
            raise ValueError("data cannot be empty")

        # Parse datetime string if provided
        if isinstance(self.created_at, str):
            self.created_at = self._parse_datetime(self.created_at)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper datetime serialization."""
        return {
            "key_id": self.key_id,
            "name": self.name,
            "salt": self.salt,
            "data": self.data,
            "created_at": self.created_at.isoformat(),
            "rotation_version": self.rotation_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CredentialFile":
        """Create CredentialFile from dictionary."""
        return cls(
            key_id=data["key_id"],
            name=data["name"],
            salt=data["salt"],
            data=data["data"],
            created_at=data.get("created_at"),
            rotation_version=data.get("rotation_version", 1),
        )


@dataclass
class CredentialsIndex:
    """Credentials index file structure for hybrid approach."""

    credentials: dict[str, str] = field(default_factory=dict)  # key_id -> name mapping
    _name_to_key_id: dict[str, str] = field(default_factory=dict, init=False)  # name -> key_id mapping for O(1) lookup
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        # Parse datetime string if provided
        if isinstance(self.last_updated, str):
            self.last_updated = self._parse_datetime(self.last_updated)
        
        # Build reverse mapping for O(1) name lookup
        self._build_name_mapping()

    def _build_name_mapping(self) -> None:
        """Build the reverse mapping from name to key_id."""
        self._name_to_key_id.clear()
        for key_id, name in self.credentials.items():
            self._name_to_key_id[name] = key_id

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper serialization."""
        return {
            "credentials": self.credentials,
            "last_updated": self.last_updated.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CredentialsIndex":
        """Create CredentialsIndex from dictionary."""
        return cls(
            credentials=data.get("credentials", {}),
            last_updated=data.get("last_updated") or datetime.now(timezone.utc),
        )

    def add_credential(
        self, 
        key_id: str, 
        name: str
    ) -> None:
        """Add a credential to the index."""
        self.credentials[key_id] = name
        self._name_to_key_id[name] = key_id
        self.last_updated = datetime.now(timezone.utc)

    def remove_credential(self, key_id: str) -> None:
        """Remove a credential from the index."""
        if key_id in self.credentials:
            name = self.credentials[key_id]
            del self.credentials[key_id]
            if name in self._name_to_key_id:
                del self._name_to_key_id[name]
            self.last_updated = datetime.now(timezone.utc)

    def get_name(self, key_id: str) -> str | None:
        """Get credential name by key_id."""
        return self.credentials.get(key_id)

    def get_key_id(self, name: str) -> str | None:
        """Get key_id by credential name."""
        return self._name_to_key_id.get(name)

    def has_name(self, name: str) -> bool:
        """Check if a credential name exists."""
        return name in self._name_to_key_id

    def update_credential_name(
        self, 
        key_id: str, 
        new_name: str
    ) -> None:
        """Update the name of an existing credential."""
        if key_id in self.credentials:
            old_name = self.credentials[key_id]
            self.credentials[key_id] = new_name
            # Update reverse mapping
            if old_name in self._name_to_key_id:
                del self._name_to_key_id[old_name]
            self._name_to_key_id[new_name] = key_id
            self.last_updated = datetime.now(timezone.utc)


@dataclass
class RotationHistory:
    """Track key rotation history for audit and rollback purposes."""

    rotation_id: str
    rotation_type: str  # "master", "bulk"
    target_key_id: str | None = None  # For future use
    old_master_key_id: str | None = None  # For master key rotations
    new_master_key_id: str | None = None  # For master key rotations
    affected_credentials: list[str] = field(default_factory=list)  # List of affected key_ids
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.rotation_id:
            raise ValueError("rotation_id cannot be empty")
        if not self.rotation_type:
            raise ValueError("rotation_type cannot be empty")
        if self.rotation_type not in ["master", "bulk"]:
            raise ValueError("rotation_type must be one of: master, bulk")

        # Parse datetime string if provided
        if isinstance(self.created_at, str):
            self.created_at = self._parse_datetime(self.created_at)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper serialization."""
        return {
            "rotation_id": self.rotation_id,
            "rotation_type": self.rotation_type,
            "target_key_id": self.target_key_id,
            "old_master_key_id": self.old_master_key_id,
            "new_master_key_id": self.new_master_key_id,
            "affected_credentials": self.affected_credentials,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RotationHistory":
        """Create RotationHistory from dictionary."""
        return cls(
            rotation_id=data["rotation_id"],
            rotation_type=data["rotation_type"],
            target_key_id=data.get("target_key_id"),
            old_master_key_id=data.get("old_master_key_id"),
            new_master_key_id=data.get("new_master_key_id"),
            affected_credentials=data.get("affected_credentials", []),
            created_at=data.get("created_at"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RotationBackup:
    """Backup data for key rotation operations."""

    backup_id: str
    rotation_id: str
    backup_type: str  # "master", "bulk"
    original_data: dict[str, Any]  # Original encrypted data before rotation
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None  # Optional expiration for automatic cleanup

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.backup_id:
            raise ValueError("backup_id cannot be empty")
        if not self.rotation_id:
            raise ValueError("rotation_id cannot be empty")
        if not self.backup_type:
            raise ValueError("backup_type cannot be empty")
        if self.backup_type not in ["master", "bulk"]:
            raise ValueError("backup_type must be one of: master, bulk")

        # Parse datetime strings if provided
        if isinstance(self.created_at, str):
            self.created_at = self._parse_datetime(self.created_at)
        if isinstance(self.expires_at, str):
            self.expires_at = self._parse_datetime(self.expires_at)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper serialization."""
        result = {
            "backup_id": self.backup_id,
            "rotation_id": self.rotation_id,
            "backup_type": self.backup_type,
            "original_data": self.original_data,
            "created_at": self.created_at.isoformat(),
        }
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RotationBackup":
        """Create RotationBackup from dictionary."""
        return cls(
            backup_id=data["backup_id"],
            rotation_id=data["rotation_id"],
            backup_type=data["backup_type"],
            original_data=data["original_data"],
            created_at=data.get("created_at"),
            expires_at=data.get("expires_at"),
        )

    def is_expired(self) -> bool:
        """Check if the backup has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class Credential:
    """Credential entry in the key custodian data."""

    key_id: str
    name: str
    salt: str
    data: str  # Encrypted CredentialData as base58 string
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.key_id:
            raise ValueError("key_id cannot be empty")
        if not self.name:
            raise ValueError("name cannot be empty")
        if not self.salt:
            raise ValueError("salt cannot be empty")
        if not self.data:
            raise ValueError("data cannot be empty")

        # Parse datetime string if provided
        if isinstance(self.created_at, str):
            self.created_at = self._parse_datetime(self.created_at)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper datetime serialization."""
        return {
            "key_id": self.key_id,
            "name": self.name,
            "salt": self.salt,
            "data": self.data,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Credential":
        """Create Credential from dictionary."""
        return cls(
            key_id=data["key_id"],
            name=data["name"],
            salt=data["salt"],
            data=data["data"],
            created_at=data.get("created_at"),
        )


@dataclass
class KeyCustodianData:
    """Key custodian data structure with master key reference and credentials."""

    master_key_id: str
    credentials: list["Credential"] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "2.0"

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.master_key_id:
            raise ValueError("master_key_id cannot be empty")

        # Parse datetime string if provided
        if isinstance(self.last_updated, str):
            self.last_updated = self._parse_datetime(self.last_updated)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper serialization."""
        return {
            "master_key_id": self.master_key_id,
            "credentials": [cred.to_dict() for cred in self.credentials],
            "last_updated": self.last_updated.isoformat(),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyCustodianData":
        """Create KeyCustodianData from dictionary."""
        # Parse credentials
        credentials = []
        for cred_data in data.get("credentials", []):
            credential = Credential.from_dict(cred_data)
            credentials.append(credential)

        return cls(
            master_key_id=data["master_key_id"],
            credentials=credentials,
            last_updated=data.get("last_updated") or datetime.now(timezone.utc),
            version=data.get("version", "2.0"),
        )


@dataclass
class MasterKey:
    """Master key for encrypting/decrypting other keys."""

    key_id: str
    credentials: str
    salt: str
    iterations: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate and process fields after initialization."""
        if not self.key_id:
            raise ValueError("key_id cannot be empty")
        if not self.credentials:
            raise ValueError("credentials cannot be empty")
        if not self.salt:
            raise ValueError("salt cannot be empty")

        # Parse datetime string if provided
        if isinstance(self.created_at, str):
            self.created_at = self._parse_datetime(self.created_at)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        """Parse datetime string to datetime object."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary with proper datetime serialization."""
        return {
            "key_id": self.key_id,
            "created_at": self.created_at.isoformat(),
            "credentials": self.credentials,
            "salt": self.salt,
            "iterations": self.iterations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MasterKey":
        """Create MasterKey from dictionary.
        
        Args:
            data: Dictionary containing master key data
            
        Returns:
            MasterKey instance
            
        Note:
            For backward compatibility, if 'iterations' is not present in the data,
            it defaults to None, which will use the system default when needed.
        """
        return cls(
            key_id=data["key_id"],
            credentials=data["credentials"],
            salt=data["salt"],
            iterations=data.get("iterations"),  # None if not present (backward compatible)
            created_at=data.get("created_at"),
        )
