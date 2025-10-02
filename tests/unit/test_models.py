"""Tests for the models module."""

from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from splurge_key_custodian.models import (
    Credential,
    CredentialData,
    CredentialFile,
    CredentialsIndex,
    KeyCustodianData,
    MasterKey,
)


class TestCredentialData:
    """Test cases for the CredentialData class."""

    def test_credential_data_creation(self):
        """Test CredentialData creation with default values."""
        data = CredentialData()

        assert data.credentials == {}
        assert data.meta_data == {}

    def test_credential_data_with_data(self):
        """Test CredentialData creation with data."""
        credentials = {"username": "test", "password": "secret"}
        meta_data = {"service": "test-service"}

        data = CredentialData(credentials=credentials, meta_data=meta_data)

        assert data.credentials == credentials
        assert data.meta_data == meta_data

    def test_credential_data_to_dict(self):
        """Test CredentialData to_dict method."""
        credentials = {"username": "test", "password": "secret"}
        meta_data = {"service": "test-service"}

        data = CredentialData(credentials=credentials, meta_data=meta_data)
        result = data.to_dict()

        assert result["credentials"] == credentials
        assert result["meta_data"] == meta_data

    def test_credential_data_from_dict(self):
        """Test CredentialData from_dict method."""
        input_data = {
            "credentials": {"username": "test", "password": "secret"},
            "meta_data": {"service": "test-service"},
        }

        data = CredentialData.from_dict(input_data)

        assert data.credentials == input_data["credentials"]
        assert data.meta_data == input_data["meta_data"]


class TestCredential:
    """Test cases for the Credential class."""

    def test_credential_creation(self):
        """Test Credential creation with required fields."""
        credential = Credential(
            key_id="test-key-123",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
        )

        assert credential.key_id == "test-key-123"
        assert credential.name == "Test Credential"
        assert credential.salt == "test-salt"
        assert credential.data == "encrypted-data"
        assert isinstance(credential.created_at, datetime)

    def test_credential_with_datetime(self):
        """Test Credential creation with specific datetime."""
        created_at = datetime.now(timezone.utc)
        credential = Credential(
            key_id="test-key-456",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at=created_at,
        )

        assert credential.created_at == created_at

    def test_credential_datetime_parsing(self):
        """Test datetime string parsing in Credential."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at="2023-01-01T12:00:00+00:00",
        )

        assert isinstance(credential.created_at, datetime)
        assert credential.created_at.year == 2023

    def test_credential_validation(self):
        """Test Credential validation."""
        # Test empty key_id
        with pytest.raises(ValueError):
            Credential(key_id="", name="Test", salt="salt", data="data")

        # Test empty name
        with pytest.raises(ValueError):
            Credential(key_id="test", name="", salt="salt", data="data")

        # Test empty salt
        with pytest.raises(ValueError):
            Credential(key_id="test", name="Test", salt="", data="data")

        # Test empty data
        with pytest.raises(ValueError):
            Credential(key_id="test", name="Test", salt="salt", data="")

    def test_credential_to_dict(self):
        """Test Credential to_dict method."""
        created_at = datetime.now(timezone.utc)
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at=created_at,
        )

        result = credential.to_dict()

        assert result["key_id"] == "test-key"
        assert result["name"] == "Test Credential"
        assert result["salt"] == "test-salt"
        assert result["data"] == "encrypted-data"
        assert result["created_at"] == created_at.isoformat()

    def test_credential_from_dict(self):
        """Test Credential from_dict method."""
        input_data = {
            "key_id": "test-key",
            "name": "Test Credential",
            "salt": "test-salt",
            "data": "encrypted-data",
            "created_at": "2023-01-01T12:00:00+00:00",
        }

        credential = Credential.from_dict(input_data)

        assert credential.key_id == "test-key"
        assert credential.name == "Test Credential"
        assert credential.salt == "test-salt"
        assert credential.data == "encrypted-data"
        assert isinstance(credential.created_at, datetime)


class TestKeyCustodianData:
    """Test cases for the KeyCustodianData class."""

    def test_key_custodian_data_creation(self):
        """Test KeyCustodianData creation with required fields."""
        data = KeyCustodianData(master_key_id="master-key-123")

        assert data.master_key_id == "master-key-123"
        assert data.credentials == []
        assert isinstance(data.last_updated, datetime)
        assert data.version == "2.0"

    def test_key_custodian_data_with_credentials(self):
        """Test KeyCustodianData creation with credentials."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
        )

        data = KeyCustodianData(
            master_key_id="master-key-123", credentials=[credential]
        )

        assert len(data.credentials) == 1
        assert data.credentials[0] == credential

    def test_key_custodian_data_validation(self):
        """Test KeyCustodianData validation."""
        with pytest.raises(ValueError):
            KeyCustodianData(master_key_id="")

    def test_key_custodian_data_to_dict(self):
        """Test KeyCustodianData to_dict method."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
        )

        data = KeyCustodianData(
            master_key_id="master-key-123", credentials=[credential]
        )

        result = data.to_dict()

        assert result["master_key_id"] == "master-key-123"
        assert len(result["credentials"]) == 1
        assert result["credentials"][0]["key_id"] == "test-key"
        assert result["version"] == "2.0"

    def test_key_custodian_data_from_dict(self):
        """Test KeyCustodianData from_dict method."""
        input_data = {
            "master_key_id": "master-key-123",
            "credentials": [
                {
                    "key_id": "test-key",
                    "name": "Test Credential",
                    "salt": "test-salt",
                    "data": "encrypted-data",
                    "created_at": "2023-01-01T12:00:00+00:00",
                }
            ],
            "version": "2.0",
        }

        data = KeyCustodianData.from_dict(input_data)

        assert data.master_key_id == "master-key-123"
        assert len(data.credentials) == 1
        assert data.credentials[0].key_id == "test-key"
        assert data.version == "2.0"

    def test_key_custodian_data_datetime_parsing(self):
        """Test datetime string parsing in KeyCustodianData."""
        data = KeyCustodianData(
            master_key_id="master-key-123", last_updated="2023-01-01T12:00:00+00:00"
        )

        assert isinstance(data.last_updated, datetime)
        assert data.last_updated.year == 2023


class TestMasterKey:
    """Test cases for the MasterKey class."""

    def test_master_key_creation(self):
        """Test MasterKey creation with required fields."""
        master_key = MasterKey(
            key_id="master-key-123",
            credentials="encrypted-credentials",
            salt="master-salt",
            iterations=100000,
        )

        assert master_key.key_id == "master-key-123"
        assert master_key.credentials == "encrypted-credentials"
        assert master_key.salt == "master-salt"
        assert master_key.iterations == 100000
        assert isinstance(master_key.created_at, datetime)

    def test_master_key_with_datetime(self):
        """Test MasterKey creation with specific datetime."""
        created_at = datetime.now(timezone.utc)
        master_key = MasterKey(
            key_id="master-key-456",
            credentials="encrypted-credentials",
            salt="master-salt",
            iterations=200000,
            created_at=created_at,
        )

        assert master_key.created_at == created_at

    def test_master_key_datetime_parsing(self):
        """Test datetime string parsing in MasterKey."""
        master_key = MasterKey(
            key_id="master-key",
            credentials="encrypted-credentials",
            salt="master-salt",
            iterations=150000,
            created_at="2023-01-01T12:00:00+00:00",
        )

        assert isinstance(master_key.created_at, datetime)
        assert master_key.created_at.year == 2023

    def test_master_key_validation(self):
        """Test MasterKey validation."""
        # Test empty key_id
        with pytest.raises(ValueError):
            MasterKey(key_id="", credentials="creds", salt="salt", iterations=100000)

        # Test empty credentials
        with pytest.raises(ValueError):
            MasterKey(key_id="test", credentials="", salt="salt", iterations=100000)

        # Test empty salt
        with pytest.raises(ValueError):
            MasterKey(key_id="test", credentials="creds", salt="", iterations=100000)

    def test_master_key_to_dict(self):
        """Test MasterKey to_dict method."""
        created_at = datetime.now(timezone.utc)
        master_key = MasterKey(
            key_id="master-key",
            credentials="encrypted-credentials",
            salt="master-salt",
            iterations=300000,
            created_at=created_at,
        )

        result = master_key.to_dict()

        assert result["key_id"] == "master-key"
        assert result["credentials"] == "encrypted-credentials"
        assert result["salt"] == "master-salt"
        assert result["iterations"] == 300000
        assert result["created_at"] == created_at.isoformat()

    def test_master_key_from_dict(self):
        """Test MasterKey from_dict method."""
        # Test with all fields including iterations
        data = {
            "key_id": "test-key",
            "credentials": "encrypted-creds",
            "salt": "test-salt",
            "iterations": 500000,
            "created_at": "2023-01-01T12:00:00+00:00",
        }

        master_key = MasterKey.from_dict(data)

        assert master_key.key_id == "test-key"
        assert master_key.credentials == "encrypted-creds"
        assert master_key.salt == "test-salt"
        assert master_key.iterations == 500000
        assert isinstance(master_key.created_at, datetime)

    def test_master_key_from_dict_backward_compatibility(self):
        """Test MasterKey from_dict method with backward compatibility (no iterations field)."""
        # Test with data missing iterations field (backward compatibility)
        data = {
            "key_id": "test-key",
            "credentials": "encrypted-creds",
            "salt": "test-salt",
            "created_at": "2023-01-01T12:00:00+00:00",
        }

        master_key = MasterKey.from_dict(data)

        assert master_key.key_id == "test-key"
        assert master_key.credentials == "encrypted-creds"
        assert master_key.salt == "test-salt"
        assert (
            master_key.iterations is None
        )  # Should be None for backward compatibility
        assert isinstance(master_key.created_at, datetime)


class TestCredentialFile:
    """Test cases for the CredentialFile class."""

    def test_credential_file_creation(self):
        """Test CredentialFile creation."""
        cred_file = CredentialFile(
            key_id="test-id", name="test-name", salt="test-salt", data="test-data"
        )

        assert cred_file.key_id == "test-id"
        assert cred_file.name == "test-name"
        assert cred_file.salt == "test-salt"
        assert cred_file.data == "test-data"
        assert isinstance(cred_file.created_at, datetime)

    def test_credential_file_validation_errors(self):
        """Test CredentialFile validation errors."""
        # Test empty key_id
        with pytest.raises(ValueError) as cm:
            CredentialFile(
                key_id="", name="test-name", salt="test-salt", data="test-data"
            )
        assert "key_id cannot be empty" in str(cm.value)

        # Test empty name
        with pytest.raises(ValueError) as cm:
            CredentialFile(
                key_id="test-id", name="", salt="test-salt", data="test-data"
            )
        assert "name cannot be empty" in str(cm.value)

        # Test empty salt
        with pytest.raises(ValueError) as cm:
            CredentialFile(
                key_id="test-id", name="test-name", salt="", data="test-data"
            )
        assert "salt cannot be empty" in str(cm.value)

        # Test empty data
        with pytest.raises(ValueError) as cm:
            CredentialFile(
                key_id="test-id", name="test-name", salt="test-salt", data=""
            )
        assert "data cannot be empty" in str(cm.value)

    def test_credential_file_to_dict(self):
        """Test CredentialFile to_dict method."""
        cred_file = CredentialFile(
            key_id="test-id", name="test-name", salt="test-salt", data="test-data"
        )

        result = cred_file.to_dict()

        assert result["key_id"] == "test-id"
        assert result["name"] == "test-name"
        assert result["salt"] == "test-salt"
        assert result["data"] == "test-data"
        assert "created_at" in result

    def test_credential_file_from_dict(self):
        """Test CredentialFile from_dict method."""
        data = {
            "key_id": "test-id",
            "name": "test-name",
            "salt": "test-salt",
            "data": "test-data",
            "created_at": "2023-01-01T12:00:00+00:00",
        }

        cred_file = CredentialFile.from_dict(data)

        assert cred_file.key_id == "test-id"
        assert cred_file.name == "test-name"
        assert cred_file.salt == "test-salt"
        assert cred_file.data == "test-data"
        assert isinstance(cred_file.created_at, datetime)


class TestCredentialsIndex:
    """Test cases for the CredentialsIndex class."""

    def test_credentials_index_creation(self):
        """Test CredentialsIndex creation."""
        index = CredentialsIndex()

        assert index.credentials == {}
        assert isinstance(index.last_updated, datetime)

    def test_credentials_index_methods(self):
        """Test CredentialsIndex methods."""
        index = CredentialsIndex()

        # Test add_credential
        index.add_credential("key1", "name1")
        assert index.credentials["key1"] == "name1"

        # Test remove_credential
        index.remove_credential("key1")
        assert "key1" not in index.credentials

        # Test remove_credential with non-existent key
        index.remove_credential("non-existent")
        # Should not raise an error

        # Test get_name
        index.add_credential("key2", "name2")
        assert index.get_name("key2") == "name2"
        assert index.get_name("non-existent") is None

        # Test get_key_id
        assert index.get_key_id("name2") == "key2"
        assert index.get_key_id("non-existent") is None

        # Test has_name
        assert index.has_name("name2")
        assert not index.has_name("non-existent")

    def test_credentials_index_to_dict(self):
        """Test CredentialsIndex to_dict method."""
        index = CredentialsIndex()
        index.add_credential("key1", "name1")

        result = index.to_dict()

        assert result["credentials"] == {"key1": "name1"}
        assert "last_updated" in result

    def test_credentials_index_from_dict_with_defaults(self):
        """Test CredentialsIndex from_dict with default values."""
        # Test with minimal data
        data = {}
        index = CredentialsIndex.from_dict(data)
        assert index.credentials == {}
        assert isinstance(index.last_updated, datetime)

    def test_credentials_index_from_dict_with_data(self):
        """Test CredentialsIndex from_dict with data."""
        data = {
            "credentials": {"key1": "name1", "key2": "name2"},
            "last_updated": "2023-01-01T12:00:00+00:00",
        }

        index = CredentialsIndex.from_dict(data)

        assert index.credentials == {"key1": "name1", "key2": "name2"}
        assert isinstance(index.last_updated, datetime)

    def test_credentials_index_from_dict_rebuilds_name_mapping(self):
        """Test that CredentialsIndex from_dict properly rebuilds the _name_to_key_id mapping."""
        data = {
            "credentials": {"key1": "name1", "key2": "name2", "key3": "name3"},
            "last_updated": "2023-01-01T12:00:00+00:00",
        }

        index = CredentialsIndex.from_dict(data)

        # Verify the reverse mapping is properly built
        assert index.get_key_id("name1") == "key1"
        assert index.get_key_id("name2") == "key2"
        assert index.get_key_id("name3") == "key3"

        # Verify has_name works correctly
        assert index.has_name("name1")
        assert index.has_name("name2")
        assert index.has_name("name3")
        assert not index.has_name("non-existent")
