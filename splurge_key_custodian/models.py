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
    def from_dict(cls, data: dict[str, Any]) -> "CredentialFile":
        """Create CredentialFile from dictionary."""
        return cls(
            key_id=data["key_id"],
            name=data["name"],
            salt=data["salt"],
            data=data["data"],
            created_at=data.get("created_at"),
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

    def get_name(self, key_id: str) -> Optional[str]:
        """Get credential name by key_id."""
        return self.credentials.get(key_id)

    def get_key_id(self, name: str) -> Optional[str]:
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
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MasterKey":
        """Create MasterKey from dictionary."""
        return cls(
            key_id=data["key_id"],
            credentials=data["credentials"],
            salt=data["salt"],
            created_at=data.get("created_at"),
        )
