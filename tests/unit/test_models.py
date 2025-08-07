"""Tests for the models module."""

import unittest
from datetime import datetime, timezone
from typing import Dict, Any

from splurge_key_custodian.models import CredentialData, Credential, KeyCustodianData, MasterKey, CredentialFile, CredentialsIndex


class TestCredentialData(unittest.TestCase):
    """Test cases for the CredentialData class."""

    def test_credential_data_creation(self):
        """Test CredentialData creation with default values."""
        data = CredentialData()
        
        self.assertEqual(data.credentials, {})
        self.assertEqual(data.meta_data, {})

    def test_credential_data_with_data(self):
        """Test CredentialData creation with data."""
        credentials = {"username": "test", "password": "secret"}
        meta_data = {"service": "test-service"}
        
        data = CredentialData(credentials=credentials, meta_data=meta_data)
        
        self.assertEqual(data.credentials, credentials)
        self.assertEqual(data.meta_data, meta_data)

    def test_credential_data_to_dict(self):
        """Test CredentialData to_dict method."""
        credentials = {"username": "test", "password": "secret"}
        meta_data = {"service": "test-service"}
        
        data = CredentialData(credentials=credentials, meta_data=meta_data)
        result = data.to_dict()
        
        self.assertEqual(result["credentials"], credentials)
        self.assertEqual(result["meta_data"], meta_data)

    def test_credential_data_from_dict(self):
        """Test CredentialData from_dict method."""
        input_data = {
            "credentials": {"username": "test", "password": "secret"},
            "meta_data": {"service": "test-service"}
        }
        
        data = CredentialData.from_dict(input_data)
        
        self.assertEqual(data.credentials, input_data["credentials"])
        self.assertEqual(data.meta_data, input_data["meta_data"])


class TestCredential(unittest.TestCase):
    """Test cases for the Credential class."""

    def test_credential_creation(self):
        """Test Credential creation with required fields."""
        credential = Credential(
            key_id="test-key-123",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data"
        )
        
        self.assertEqual(credential.key_id, "test-key-123")
        self.assertEqual(credential.name, "Test Credential")
        self.assertEqual(credential.salt, "test-salt")
        self.assertEqual(credential.data, "encrypted-data")
        self.assertIsInstance(credential.created_at, datetime)

    def test_credential_with_datetime(self):
        """Test Credential creation with specific datetime."""
        created_at = datetime.now(timezone.utc)
        credential = Credential(
            key_id="test-key-456",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at=created_at
        )
        
        self.assertEqual(credential.created_at, created_at)

    def test_credential_datetime_parsing(self):
        """Test datetime string parsing in Credential."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at="2023-01-01T12:00:00+00:00"
        )
        
        self.assertIsInstance(credential.created_at, datetime)
        self.assertEqual(credential.created_at.year, 2023)

    def test_credential_validation(self):
        """Test Credential validation."""
        # Test empty key_id
        with self.assertRaises(ValueError):
            Credential(key_id="", name="Test", salt="salt", data="data")
        
        # Test empty name
        with self.assertRaises(ValueError):
            Credential(key_id="test", name="", salt="salt", data="data")
        
        # Test empty salt
        with self.assertRaises(ValueError):
            Credential(key_id="test", name="Test", salt="", data="data")
        
        # Test empty data
        with self.assertRaises(ValueError):
            Credential(key_id="test", name="Test", salt="salt", data="")

    def test_credential_to_dict(self):
        """Test Credential to_dict method."""
        created_at = datetime.now(timezone.utc)
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data",
            created_at=created_at
        )
        
        result = credential.to_dict()
        
        self.assertEqual(result["key_id"], "test-key")
        self.assertEqual(result["name"], "Test Credential")
        self.assertEqual(result["salt"], "test-salt")
        self.assertEqual(result["data"], "encrypted-data")
        self.assertEqual(result["created_at"], created_at.isoformat())

    def test_credential_from_dict(self):
        """Test Credential from_dict method."""
        input_data = {
            "key_id": "test-key",
            "name": "Test Credential",
            "salt": "test-salt",
            "data": "encrypted-data",
            "created_at": "2023-01-01T12:00:00+00:00"
        }
        
        credential = Credential.from_dict(input_data)
        
        self.assertEqual(credential.key_id, "test-key")
        self.assertEqual(credential.name, "Test Credential")
        self.assertEqual(credential.salt, "test-salt")
        self.assertEqual(credential.data, "encrypted-data")
        self.assertIsInstance(credential.created_at, datetime)


class TestKeyCustodianData(unittest.TestCase):
    """Test cases for the KeyCustodianData class."""

    def test_key_custodian_data_creation(self):
        """Test KeyCustodianData creation with required fields."""
        data = KeyCustodianData(master_key_id="master-key-123")
        
        self.assertEqual(data.master_key_id, "master-key-123")
        self.assertEqual(data.credentials, [])
        self.assertIsInstance(data.last_updated, datetime)
        self.assertEqual(data.version, "2.0")

    def test_key_custodian_data_with_credentials(self):
        """Test KeyCustodianData creation with credentials."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data"
        )
        
        data = KeyCustodianData(
            master_key_id="master-key-123",
            credentials=[credential]
        )
        
        self.assertEqual(len(data.credentials), 1)
        self.assertEqual(data.credentials[0], credential)

    def test_key_custodian_data_validation(self):
        """Test KeyCustodianData validation."""
        with self.assertRaises(ValueError):
            KeyCustodianData(master_key_id="")

    def test_key_custodian_data_to_dict(self):
        """Test KeyCustodianData to_dict method."""
        credential = Credential(
            key_id="test-key",
            name="Test Credential",
            salt="test-salt",
            data="encrypted-data"
        )
        
        data = KeyCustodianData(
            master_key_id="master-key-123",
            credentials=[credential]
        )
        
        result = data.to_dict()
        
        self.assertEqual(result["master_key_id"], "master-key-123")
        self.assertEqual(len(result["credentials"]), 1)
        self.assertEqual(result["credentials"][0]["key_id"], "test-key")
        self.assertEqual(result["version"], "2.0")

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
                    "created_at": "2023-01-01T12:00:00+00:00"
                }
            ],
            "version": "2.0"
        }
        
        data = KeyCustodianData.from_dict(input_data)
        
        self.assertEqual(data.master_key_id, "master-key-123")
        self.assertEqual(len(data.credentials), 1)
        self.assertEqual(data.credentials[0].key_id, "test-key")
        self.assertEqual(data.version, "2.0")

    def test_key_custodian_data_datetime_parsing(self):
        """Test datetime string parsing in KeyCustodianData."""
        data = KeyCustodianData(
            master_key_id="master-key-123",
            last_updated="2023-01-01T12:00:00+00:00"
        )
        
        self.assertIsInstance(data.last_updated, datetime)
        self.assertEqual(data.last_updated.year, 2023)


class TestMasterKey(unittest.TestCase):
    """Test cases for the MasterKey class."""

    def test_master_key_creation(self):
        """Test MasterKey creation with required fields."""
        master_key = MasterKey(
            key_id="master-key-123",
            credentials="encrypted-credentials",
            salt="master-salt"
        )
        
        self.assertEqual(master_key.key_id, "master-key-123")
        self.assertEqual(master_key.credentials, "encrypted-credentials")
        self.assertEqual(master_key.salt, "master-salt")
        self.assertIsInstance(master_key.created_at, datetime)

    def test_master_key_with_datetime(self):
        """Test MasterKey creation with specific datetime."""
        created_at = datetime.now(timezone.utc)
        master_key = MasterKey(
            key_id="master-key-456",
            credentials="encrypted-credentials",
            salt="master-salt",
            created_at=created_at
        )
        
        self.assertEqual(master_key.created_at, created_at)

    def test_master_key_datetime_parsing(self):
        """Test datetime string parsing in MasterKey."""
        master_key = MasterKey(
            key_id="master-key",
            credentials="encrypted-credentials",
            salt="master-salt",
            created_at="2023-01-01T12:00:00+00:00"
        )
        
        self.assertIsInstance(master_key.created_at, datetime)
        self.assertEqual(master_key.created_at.year, 2023)

    def test_master_key_validation(self):
        """Test MasterKey validation."""
        # Test empty key_id
        with self.assertRaises(ValueError):
            MasterKey(key_id="", credentials="creds", salt="salt")
        
        # Test empty credentials
        with self.assertRaises(ValueError):
            MasterKey(key_id="test", credentials="", salt="salt")
        
        # Test empty salt
        with self.assertRaises(ValueError):
            MasterKey(key_id="test", credentials="creds", salt="")

    def test_master_key_to_dict(self):
        """Test MasterKey to_dict method."""
        created_at = datetime.now(timezone.utc)
        master_key = MasterKey(
            key_id="master-key",
            credentials="encrypted-credentials",
            salt="master-salt",
            created_at=created_at
        )
        
        result = master_key.to_dict()
        
        self.assertEqual(result["key_id"], "master-key")
        self.assertEqual(result["credentials"], "encrypted-credentials")
        self.assertEqual(result["salt"], "master-salt")
        self.assertEqual(result["created_at"], created_at.isoformat())


class TestCredentialFile(unittest.TestCase):
    """Test cases for the CredentialFile class."""

    def test_credential_file_creation(self):
        """Test CredentialFile creation."""
        cred_file = CredentialFile(
            key_id="test-id",
            name="test-name",
            salt="test-salt",
            data="test-data"
        )
        
        self.assertEqual(cred_file.key_id, "test-id")
        self.assertEqual(cred_file.name, "test-name")
        self.assertEqual(cred_file.salt, "test-salt")
        self.assertEqual(cred_file.data, "test-data")
        self.assertIsInstance(cred_file.created_at, datetime)

    def test_credential_file_validation_errors(self):
        """Test CredentialFile validation errors."""
        # Test empty key_id
        with self.assertRaises(ValueError) as cm:
            CredentialFile(
                key_id="",
                name="test-name",
                salt="test-salt",
                data="test-data"
            )
        self.assertIn("key_id cannot be empty", str(cm.exception))
        
        # Test empty name
        with self.assertRaises(ValueError) as cm:
            CredentialFile(
                key_id="test-id",
                name="",
                salt="test-salt",
                data="test-data"
            )
        self.assertIn("name cannot be empty", str(cm.exception))
        
        # Test empty salt
        with self.assertRaises(ValueError) as cm:
            CredentialFile(
                key_id="test-id",
                name="test-name",
                salt="",
                data="test-data"
            )
        self.assertIn("salt cannot be empty", str(cm.exception))
        
        # Test empty data
        with self.assertRaises(ValueError) as cm:
            CredentialFile(
                key_id="test-id",
                name="test-name",
                salt="test-salt",
                data=""
            )
        self.assertIn("data cannot be empty", str(cm.exception))

    def test_credential_file_to_dict(self):
        """Test CredentialFile to_dict method."""
        cred_file = CredentialFile(
            key_id="test-id",
            name="test-name",
            salt="test-salt",
            data="test-data"
        )
        
        result = cred_file.to_dict()
        
        self.assertEqual(result["key_id"], "test-id")
        self.assertEqual(result["name"], "test-name")
        self.assertEqual(result["salt"], "test-salt")
        self.assertEqual(result["data"], "test-data")
        self.assertIn("created_at", result)

    def test_credential_file_from_dict(self):
        """Test CredentialFile from_dict method."""
        data = {
            "key_id": "test-id",
            "name": "test-name",
            "salt": "test-salt",
            "data": "test-data",
            "created_at": "2023-01-01T12:00:00+00:00"
        }
        
        cred_file = CredentialFile.from_dict(data)
        
        self.assertEqual(cred_file.key_id, "test-id")
        self.assertEqual(cred_file.name, "test-name")
        self.assertEqual(cred_file.salt, "test-salt")
        self.assertEqual(cred_file.data, "test-data")
        self.assertIsInstance(cred_file.created_at, datetime)


class TestCredentialsIndex(unittest.TestCase):
    """Test cases for the CredentialsIndex class."""

    def test_credentials_index_creation(self):
        """Test CredentialsIndex creation."""
        index = CredentialsIndex()
        
        self.assertEqual(index.credentials, {})
        self.assertIsInstance(index.last_updated, datetime)

    def test_credentials_index_methods(self):
        """Test CredentialsIndex methods."""
        index = CredentialsIndex()
        
        # Test add_credential
        index.add_credential("key1", "name1")
        self.assertEqual(index.credentials["key1"], "name1")
        
        # Test remove_credential
        index.remove_credential("key1")
        self.assertNotIn("key1", index.credentials)
        
        # Test remove_credential with non-existent key
        index.remove_credential("non-existent")
        # Should not raise an error
        
        # Test get_name
        index.add_credential("key2", "name2")
        self.assertEqual(index.get_name("key2"), "name2")
        self.assertIsNone(index.get_name("non-existent"))
        
        # Test get_key_id
        self.assertEqual(index.get_key_id("name2"), "key2")
        self.assertIsNone(index.get_key_id("non-existent"))
        
        # Test has_name
        self.assertTrue(index.has_name("name2"))
        self.assertFalse(index.has_name("non-existent"))

    def test_credentials_index_to_dict(self):
        """Test CredentialsIndex to_dict method."""
        index = CredentialsIndex()
        index.add_credential("key1", "name1")
        
        result = index.to_dict()
        
        self.assertEqual(result["credentials"], {"key1": "name1"})
        self.assertIn("last_updated", result)

    def test_credentials_index_from_dict_with_defaults(self):
        """Test CredentialsIndex from_dict with default values."""
        # Test with minimal data
        data = {}
        index = CredentialsIndex.from_dict(data)
        self.assertEqual(index.credentials, {})
        self.assertIsInstance(index.last_updated, datetime)

    def test_credentials_index_from_dict_with_data(self):
        """Test CredentialsIndex from_dict with data."""
        data = {
            "credentials": {"key1": "name1", "key2": "name2"},
            "last_updated": "2023-01-01T12:00:00+00:00"
        }
        
        index = CredentialsIndex.from_dict(data)
        
        self.assertEqual(index.credentials, {"key1": "name1", "key2": "name2"})
        self.assertIsInstance(index.last_updated, datetime)


if __name__ == '__main__':
    unittest.main(verbosity=2) 