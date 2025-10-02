"""Tests for the Hybrid Key Custodian."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
from splurge_key_custodian import Base58, KeyCustodian
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import (
    EncryptionError,
    FileOperationError,
    KeyNotFoundError,
    MasterKeyError,
    ValidationError,
)
from splurge_key_custodian.file_manager import FileManager
from tests.test_utility import TestUtilities


class TestKeyCustodian:
    """Test cases for KeyCustodian."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = TestUtilities.create_temp_data_dir()
        self.master_password = "TestMasterPasswordWithComplexity123!@#"
        self.custodian = TestUtilities.create_test_custodian(
            self.temp_dir, self.master_password
        )
        self.sample_credential = TestUtilities.get_sample_credential()
        yield
        """Clean up test fixtures."""
        TestUtilities.cleanup_temp_dir(self.temp_dir)

    def test_initialization(self):
        """Test KeyCustodian initialization."""
        assert self.custodian.data_directory == self.temp_dir
        assert self.custodian.master_key_id is not None
        assert self.custodian.credential_count == 0

    def test_create_credential(self):
        """Test creating a credential."""
        key_id = self.custodian.create_credential(**self.sample_credential)

        assert key_id is not None
        assert self.custodian.credential_count == 1

    def test_read_credential(self):
        """Test reading a credential."""
        # Create credential
        key_id = self.custodian.create_credential(**self.sample_credential)

        # Read credential
        data = self.custodian.read_credential(key_id)

        assert data["credentials"]["username"] == "test_user"
        assert data["credentials"]["password"] == "test_pass"
        assert data["meta_data"]["service"] == "test_service"

    def test_list_credentials(self):
        """Test listing credentials."""
        # Create multiple credentials
        key_id1 = self.custodian.create_credential(
            name="Credential 1", credentials={"test": "data1"}
        )
        key_id2 = self.custodian.create_credential(
            name="Credential 2", credentials={"test": "data2"}
        )

        # List credentials
        credentials = self.custodian.list_credentials()

        assert len(credentials) == 2
        names = [cred["name"] for cred in credentials]
        assert "Credential 1" in names
        assert "Credential 2" in names

    def test_find_credential_by_name(self):
        """Test finding credential by name."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential", credentials={"test": "data"}
        )

        # Find by name
        found = self.custodian.find_credential_by_name("Test Credential")

        assert found is not None
        assert found["key_id"] == key_id
        assert found["name"] == "Test Credential"

    def test_delete_credential(self):
        """Test deleting a credential."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential", credentials={"test": "data"}
        )

        # Verify it exists
        assert self.custodian.credential_count == 1

        # Delete credential
        self.custodian.delete_credential(key_id)

        # Verify it's gone
        assert self.custodian.credential_count == 0
        with pytest.raises(KeyNotFoundError):
            self.custodian.read_credential(key_id)

    def test_update_credential(self):
        """Test updating a credential."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"username": "old_user", "password": "old_pass"},
            meta_data={"service": "old_service"},
        )

        # Update credential
        self.custodian.update_credential(
            key_id=key_id,
            name="Updated Credential",
            credentials={"username": "new_user", "password": "new_pass"},
            meta_data={"service": "new_service"},
        )

        # Read updated credential
        data = self.custodian.read_credential(key_id)

        # Check that name was updated in the index
        found = self.custodian.find_credential_by_name("Updated Credential")
        assert found is not None
        assert found["key_id"] == key_id

        assert data["credentials"]["username"] == "new_user"
        assert data["credentials"]["password"] == "new_pass"
        assert data["meta_data"]["service"] == "new_service"

    def test_name_uniqueness(self):
        """Test that credential names must be unique."""
        # Create first credential
        self.custodian.create_credential(
            name="Test Credential", credentials={"test": "data"}
        )

        # Try to create second credential with same name
        with pytest.raises(ValidationError):
            self.custodian.create_credential(
                name="Test Credential", credentials={"test": "data2"}
            )

    def test_file_structure(self):
        """Test that files are created in the correct structure."""
        # Create a credential
        key_id = self.custodian.create_credential(**self.sample_credential)

        # Check that files exist
        data_path = Path(self.temp_dir)
        assert (data_path / "key-custodian-master.json").exists()
        assert (data_path / "key-custodian-index.json").exists()
        assert (data_path / f"{key_id}.credential.json").exists()

    def test_from_env_master_password(self):
        """Test creating KeyCustodian from environment variable."""
        # Encode master password
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))

        with patch.dict(os.environ, {"SPLURGE_MASTER_PASSWORD": encoded_password}):
            custodian = KeyCustodian.init_from_environment(
                "SPLURGE_MASTER_PASSWORD", self.temp_dir
            )

            assert custodian.data_directory == self.temp_dir
            assert custodian.master_key_id is not None

    def test_from_env_master_password_none_env_var_name(self):
        """Test from_env_master_password with None environment variable name."""
        with pytest.raises(ValidationError) as context:
            KeyCustodian.init_from_environment(None, self.temp_dir)
        assert "cannot be None" in str(context.value)

    def test_from_env_master_password_empty_env_var_name(self):
        """Test from_env_master_password with empty environment variable name."""
        with pytest.raises(ValidationError) as context:
            KeyCustodian.init_from_environment("", self.temp_dir)
        assert "cannot be empty" in str(context.value)

    def test_from_env_master_password_whitespace_only_env_var_name(self):
        """Test from_env_master_password with whitespace-only environment variable name."""
        with pytest.raises(ValidationError) as context:
            KeyCustodian.init_from_environment("   \t\n  ", self.temp_dir)
        assert "cannot contain only whitespace" in str(context.value)

    def test_from_env_master_password_missing_env_var(self):
        """Test from_env_master_password with missing environment variable."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValidationError) as context:
                KeyCustodian.init_from_environment(
                    "SPLURGE_MASTER_PASSWORD", self.temp_dir
                )
            assert "not set" in str(context.value)

    def test_from_env_master_password_empty_string(self):
        """Test from_env_master_password with empty string environment variable."""
        with patch.dict(os.environ, {"SPLURGE_MASTER_PASSWORD": ""}):
            with pytest.raises(ValidationError) as context:
                KeyCustodian.init_from_environment(
                    "SPLURGE_MASTER_PASSWORD", self.temp_dir
                )
            assert "is empty" in str(context.value)

    def test_from_env_master_password_whitespace_only(self):
        """Test from_env_master_password with whitespace-only environment variable."""
        with patch.dict(os.environ, {"SPLURGE_MASTER_PASSWORD": "   \t\n  "}):
            with pytest.raises(ValidationError) as context:
                KeyCustodian.init_from_environment(
                    "SPLURGE_MASTER_PASSWORD", self.temp_dir
                )
            assert "contains only whitespace" in str(context.value)

    def test_from_env_master_password_invalid_base58(self):
        """Test from_env_master_password with invalid Base58."""
        with patch.dict(os.environ, {"SPLURGE_MASTER_PASSWORD": "invalid-base58!"}):
            with pytest.raises(ValidationError):
                KeyCustodian.init_from_environment(
                    "SPLURGE_MASTER_PASSWORD", self.temp_dir
                )

    def test_from_env_master_password_decode_error(self):
        """Test from_env_master_password with decode error."""
        # Use a valid Base58 string that can't be decoded as UTF-8
        invalid_utf8_bytes = b"\xff\xfe\xfd"
        encoded_invalid = Base58.encode(invalid_utf8_bytes)

        with patch.dict(os.environ, {"SPLURGE_MASTER_PASSWORD": encoded_invalid}):
            with pytest.raises(ValidationError):
                KeyCustodian.init_from_environment(
                    "SPLURGE_MASTER_PASSWORD", self.temp_dir
                )

    def test_from_env_master_password_custom_env_var(self):
        """Test from_env_master_password with custom environment variable name."""
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))

        with patch.dict(os.environ, {"CUSTOM_PASSWORD": encoded_password}):
            custodian = KeyCustodian.init_from_environment(
                "CUSTOM_PASSWORD", self.temp_dir
            )

            assert custodian.data_directory == self.temp_dir

    def test_init_empty_data_dir(self):
        """Test initialization with empty data directory."""
        with pytest.raises(ValidationError):
            KeyCustodian(self.master_password, "")

    def test_init_empty_master_password(self):
        """Test initialization with empty master password."""
        with pytest.raises(ValidationError):
            KeyCustodian("", self.temp_dir)

    def test_backup_credentials(self):
        """Test backing up credentials."""
        # Create a credential
        self.custodian.create_credential(**self.sample_credential)

        # Create backup
        backup_dir = os.path.join(self.temp_dir, "backup")
        self.custodian.backup_credentials(backup_dir)

        # Check backup files exist
        backup_path = Path(backup_dir)
        assert (backup_path / "key-custodian-master.json").exists()
        assert (backup_path / "key-custodian-index.json").exists()

    def test_rebuild_index_from_files(self):
        """Test rebuilding index from files."""
        # Create a credential
        key_id = self.custodian.create_credential(**self.sample_credential)

        # Manually delete the index file
        index_file = Path(self.temp_dir) / "key-custodian-index.json"
        index_file.unlink(missing_ok=True)

        # Create new custodian (should rebuild index)
        new_custodian = KeyCustodian(self.master_password, self.temp_dir)

        # Should find the credential
        assert new_custodian.credential_count == 1
        found = new_custodian.find_credential_by_name("Test Credential")
        assert found is not None

    def test_manual_rebuild_index(self):
        """Test manually rebuilding the index."""
        # Create a credential
        key_id = self.custodian.create_credential(**self.sample_credential)

        # Manually delete the index file
        index_file = Path(self.temp_dir) / "key-custodian-index.json"
        index_file.unlink(missing_ok=True)

        # Rebuild index
        self.custodian.rebuild_index()

        # Should find the credential
        assert self.custodian.credential_count == 1
        found = self.custodian.find_credential_by_name("Test Credential")
        assert found is not None

    def test_create_credential_empty_name(self):
        """Test creating credential with empty name."""
        with pytest.raises(ValidationError):
            self.custodian.create_credential(name="", credentials={"test": "data"})

    def test_create_credential_empty_credentials(self):
        """Test creating credential with empty credentials."""
        with pytest.raises(ValidationError):
            self.custodian.create_credential(name="Test", credentials={})

    def test_read_credential_empty_key_id(self):
        """Test reading credential with empty key ID."""
        with pytest.raises(ValidationError):
            self.custodian.read_credential("")

    def test_delete_credential_empty_key_id(self):
        """Test deleting credential with empty key ID."""
        with pytest.raises(ValidationError):
            self.custodian.delete_credential("")

    def test_update_credential_empty_key_id(self):
        """Test updating credential with empty key ID."""
        with pytest.raises(ValidationError):
            self.custodian.update_credential(key_id="", name="New Name")

    def test_update_credential_not_found(self):
        """Test updating non-existent credential."""
        with pytest.raises(KeyNotFoundError):
            self.custodian.update_credential(key_id="non-existent-key", name="New Name")

    def test_delete_credential_not_found(self):
        """Test deleting non-existent credential."""
        with pytest.raises(KeyNotFoundError):
            self.custodian.delete_credential("non-existent-key")

    def test_read_credential_not_found(self):
        """Test reading non-existent credential."""
        with pytest.raises(KeyNotFoundError):
            self.custodian.read_credential("non-existent-key")

    def test_rebuild_index_no_credential_files(self):
        """Test rebuilding index when no credential files exist."""
        # Create custodian (creates empty index)
        custodian = KeyCustodian(self.master_password, self.temp_dir)

        # Manually delete the index file
        index_file = Path(self.temp_dir) / "key-custodian-index.json"
        index_file.unlink(missing_ok=True)

        # Rebuild index
        custodian.rebuild_index()

        # Should have empty index
        assert custodian.credential_count == 0

    def test_update_credential_partial_update(self):
        """Test updating credential with partial data."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"username": "user", "password": "pass"},
            meta_data={"service": "service"},
        )

        # Update only name
        self.custodian.update_credential(key_id=key_id, name="Updated Name")

        # Read credential
        data = self.custodian.read_credential(key_id)

        # Check that name was updated in the index
        found = self.custodian.find_credential_by_name("Updated Name")
        assert found is not None
        assert found["key_id"] == key_id

        assert data["credentials"]["username"] == "user"  # Unchanged
        assert data["meta_data"]["service"] == "service"  # Unchanged

    def test_update_credential_partial_credentials(self):
        """Test updating credential with partial credentials."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"username": "user", "password": "pass"},
            meta_data={"service": "service"},
        )

        # Update only credentials
        self.custodian.update_credential(
            key_id=key_id, credentials={"username": "new_user", "password": "new_pass"}
        )

        # Read credential
        data = self.custodian.read_credential(key_id)

        # Check that name is unchanged in the index
        found = self.custodian.find_credential_by_name("Test Credential")
        assert found is not None
        assert found["key_id"] == key_id

        assert data["credentials"]["username"] == "new_user"
        assert data["credentials"]["password"] == "new_pass"
        assert data["meta_data"]["service"] == "service"  # Unchanged

    def test_update_credential_partial_meta_data(self):
        """Test updating credential with partial meta data."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"username": "user", "password": "pass"},
            meta_data={"service": "service"},
        )

        # Update only meta data
        self.custodian.update_credential(
            key_id=key_id, meta_data={"service": "new_service", "version": "2.0"}
        )

        # Read credential
        data = self.custodian.read_credential(key_id)

        # Check that name is unchanged in the index
        found = self.custodian.find_credential_by_name("Test Credential")
        assert found is not None
        assert found["key_id"] == key_id

        assert data["credentials"]["username"] == "user"  # Unchanged
        assert data["meta_data"]["service"] == "new_service"
        assert data["meta_data"]["version"] == "2.0"

    def test_find_credential_by_name_not_found(self):
        """Test finding credential by name when not found."""
        result = self.custodian.find_credential_by_name("Non-existent Credential")
        assert result is None

    def test_find_credential_by_name_case_sensitive(self):
        """Test that credential name search is case sensitive."""
        # Create credential
        self.custodian.create_credential(
            name="Test Credential", credentials={"test": "data"}
        )

        # Search with different case
        result = self.custodian.find_credential_by_name("test credential")
        assert result is None

    def test_create_credential_with_none_meta_data(self):
        """Test creating credential with None meta data."""
        key_id = self.custodian.create_credential(
            name="Test Credential", credentials={"test": "data"}, meta_data=None
        )

        # Read credential
        data = self.custodian.read_credential(key_id)

        assert data["credentials"]["test"] == "data"
        assert data["meta_data"] == {}  # Should be empty dict

    def test_update_credential_with_none_meta_data(self):
        """Test updating credential with None meta data."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"test": "data"},
            meta_data={"service": "service"},
        )

        # Update with None meta data
        self.custodian.update_credential(key_id=key_id, meta_data=None)

        # Read credential
        data = self.custodian.read_credential(key_id)

        # When meta_data is None, it should keep the existing meta_data
        assert data["meta_data"] == {"service": "service"}

    def test_create_credential_with_complex_data(self):
        """Test creating credential with complex nested data."""
        complex_credentials = {
            "user": {
                "username": "test_user",
                "email": "test@example.com",
                "roles": ["admin", "user"],
            },
            "api_keys": {"primary": "key123", "secondary": "key456"},
        }

        complex_meta_data = {
            "service": "test_service",
            "tags": ["production", "critical"],
            "settings": {"timeout": 30, "retries": 3, "enabled": True},
        }

        key_id = self.custodian.create_credential(
            name="Complex Credential",
            credentials=complex_credentials,
            meta_data=complex_meta_data,
        )

        # Read credential
        data = self.custodian.read_credential(key_id)

        assert data["credentials"] == complex_credentials
        assert data["meta_data"] == complex_meta_data

    def test_credential_count_property(self):
        """Test the credential_count property."""
        assert self.custodian.credential_count == 0

        # Create a credential
        self.custodian.create_credential(**self.sample_credential)
        assert self.custodian.credential_count == 1

        # Create another credential
        self.custodian.create_credential(
            name="Another Credential", credentials={"test": "data2"}
        )
        assert self.custodian.credential_count == 2

        # Delete a credential
        credentials = self.custodian.list_credentials()
        self.custodian.delete_credential(credentials[0]["key_id"])
        assert self.custodian.credential_count == 1

    def test_data_directory_property(self):
        """Test the data_directory property."""
        assert self.custodian.data_directory == self.temp_dir

    def test_master_key_id_property(self):
        """Test the master_key_id property."""
        master_key_id = self.custodian.master_key_id
        assert master_key_id is not None
        assert isinstance(master_key_id, str)
        assert len(master_key_id) > 0

    def test_create_credential_with_special_characters(self):
        """Test creating credential with special characters in name."""
        special_name = (
            "Test Credential with Special Chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        )

        key_id = self.custodian.create_credential(
            name=special_name, credentials={"test": "data"}
        )

        # Should be able to find it
        found = self.custodian.find_credential_by_name(special_name)
        assert found is not None
        assert found["name"] == special_name

    def test_create_credential_with_unicode(self):
        """Test creating credential with unicode characters."""
        unicode_name = "Test Credential with Unicode: 测试 テスト 테스트"

        key_id = self.custodian.create_credential(
            name=unicode_name, credentials={"test": "data"}
        )

        # Should be able to find it
        found = self.custodian.find_credential_by_name(unicode_name)
        assert found is not None
        assert found["name"] == unicode_name

    def test_create_credential_with_large_data(self):
        """Test creating credential with large data."""
        large_credentials = {
            "data": "x" * 10000,  # 10KB of data
            "array": list(range(1000)),
            "nested": {"deep": {"structure": {"with": "lots of data"}}},
        }

        key_id = self.custodian.create_credential(
            name="Large Credential", credentials=large_credentials
        )

        # Should be able to read it back
        data = self.custodian.read_credential(key_id)
        assert data["credentials"] == large_credentials

    def test_concurrent_credential_operations(self):
        """Test concurrent credential operations."""
        # Create multiple credentials quickly
        key_ids = []
        for i in range(10):
            key_id = self.custodian.create_credential(
                name=f"Credential {i}", credentials={"index": i, "data": f"data_{i}"}
            )
            key_ids.append(key_id)

        # Verify all were created
        assert self.custodian.credential_count == 10

        # Read all credentials
        for i, key_id in enumerate(key_ids):
            data = self.custodian.read_credential(key_id)
            assert data["credentials"]["index"] == i
            assert data["credentials"]["data"] == f"data_{i}"

    def test_file_manager_error_handling(self):
        """Test error handling when file manager operations fail."""
        # Mock file manager to raise an exception
        # We test error handling through the public interface rather than accessing private attributes
        with patch.object(
            FileManager,
            "save_credentials_index",
            side_effect=FileOperationError("Test error"),
        ):
            with pytest.raises(EncryptionError):
                self.custodian.create_credential(**self.sample_credential)

    def test_crypto_error_handling(self):
        """Test error handling when crypto operations fail."""
        # Mock crypto utils to raise an exception
        # We test error handling through the public interface rather than accessing private attributes
        with patch.object(
            FileManager,
            "save_credential_file",
            side_effect=EncryptionError("Test error"),
        ):
            with pytest.raises(EncryptionError):
                self.custodian.create_credential(**self.sample_credential)

    def test_master_key_error_handling(self):
        """Test error handling when master key operations fail."""
        # Mock crypto utils to raise an exception during key derivation
        with patch.object(
            CryptoUtils,
            "derive_key_from_master_key",
            side_effect=MasterKeyError("Test error"),
        ):
            with pytest.raises(EncryptionError):
                self.custodian.create_credential(**self.sample_credential)
