"""Integration tests for core KeyCustodian functionality."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.exceptions import (
    ValidationError,
    KeyNotFoundError,
    EncryptionError,
    FileOperationError,
    MasterKeyError,
)
from tests.test_utility import TestUtilities, TestDataHelper


class TestKeyCustodianCore(unittest.TestCase):
    """Integration tests for core KeyCustodian functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = TestUtilities.create_temp_data_dir()
        self.master_password = TestDataHelper.create_test_master_password()
        self.custodian = TestUtilities.create_test_custodian(self.temp_dir, self.master_password)
        self.sample_credential = TestUtilities.get_sample_credential()

    def tearDown(self):
        """Clean up test fixtures."""
        TestUtilities.cleanup_temp_dir(self.temp_dir)

    def test_initialization(self):
        """Test KeyCustodian initialization."""
        self.assertEqual(self.custodian.data_directory, self.temp_dir)
        self.assertIsNotNone(self.custodian.master_key_id)
        self.assertEqual(self.custodian.credential_count, 0)

    def test_create_credential(self):
        """Test creating a credential."""
        key_id = self.custodian.create_credential(**self.sample_credential)
        
        self.assertIsNotNone(key_id)
        self.assertEqual(self.custodian.credential_count, 1)

    def test_read_credential(self):
        """Test reading a credential."""
        # Create credential
        key_id = self.custodian.create_credential(**self.sample_credential)
        
        # Read credential
        data = self.custodian.read_credential(key_id)
        
        self.assertEqual(data["credentials"]["username"], "test_user")
        self.assertEqual(data["credentials"]["password"], "test_pass")
        self.assertEqual(data["meta_data"]["service"], "test_service")

    def test_list_credentials(self):
        """Test listing credentials."""
        # Create multiple credentials
        key_id1 = self.custodian.create_credential(
            name="Credential 1",
            credentials={"test": "data1"}
        )
        key_id2 = self.custodian.create_credential(
            name="Credential 2",
            credentials={"test": "data2"}
        )
        
        # List credentials
        credentials = self.custodian.list_credentials()
        
        self.assertEqual(len(credentials), 2)
        names = [cred["name"] for cred in credentials]
        self.assertIn("Credential 1", names)
        self.assertIn("Credential 2", names)

    def test_find_credential_by_name(self):
        """Test finding credential by name."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"test": "data"}
        )
        
        # Find by name
        found = self.custodian.find_credential_by_name("Test Credential")
        
        self.assertIsNotNone(found)
        self.assertEqual(found["key_id"], key_id)
        self.assertEqual(found["name"], "Test Credential")

    def test_delete_credential(self):
        """Test deleting a credential."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"test": "data"}
        )
        
        # Verify it exists
        self.assertEqual(self.custodian.credential_count, 1)
        
        # Delete credential
        self.custodian.delete_credential(key_id)
        
        # Verify it's deleted
        self.assertEqual(self.custodian.credential_count, 0)
        
        # Verify it's not found
        with self.assertRaises(KeyNotFoundError):
            self.custodian.read_credential(key_id)

    def test_update_credential(self):
        """Test updating a credential."""
        # Create credential
        key_id = self.custodian.create_credential(
            name="Test Credential",
            credentials={"username": "old_user", "password": "old_pass"}
        )
        
        # Update credential
        updated_credentials = {"username": "new_user", "password": "new_pass"}
        self.custodian.update_credential(key_id, credentials=updated_credentials)
        
        # Read and verify update
        data = self.custodian.read_credential(key_id)
        self.assertEqual(data["credentials"]["username"], "new_user")
        self.assertEqual(data["credentials"]["password"], "new_pass")

    def test_credential_persistence(self):
        """Test that credentials persist across custodian instances."""
        # Create credential with first custodian
        key_id = self.custodian.create_credential(**self.sample_credential)
        
        # Create new custodian instance
        new_custodian = KeyCustodian(self.master_password, self.temp_dir)
        
        # Verify credential exists in new instance
        self.assertEqual(new_custodian.credential_count, 1)
        
        # Verify we can read the credential
        data = new_custodian.read_credential(key_id)
        self.assertEqual(data["credentials"]["username"], "test_user")

    def test_invalid_key_id(self):
        """Test handling of invalid key ID."""
        with self.assertRaises(KeyNotFoundError):
            self.custodian.read_credential("invalid-key-id")

    def test_duplicate_credential_name(self):
        """Test creating credentials with duplicate names."""
        # Create first credential
        self.custodian.create_credential(
            name="Duplicate Name",
            credentials={"test": "data1"}
        )
        
        # Create second credential with same name should fail
        with self.assertRaises(ValidationError):
            self.custodian.create_credential(
                name="Duplicate Name",
                credentials={"test": "data2"}
            )
        
        # Only one should exist
        credentials = self.custodian.list_credentials()
        duplicate_names = [cred["name"] for cred in credentials if cred["name"] == "Duplicate Name"]
        self.assertEqual(len(duplicate_names), 1)

    def test_empty_credentials(self):
        """Test creating credential with empty credentials."""
        with self.assertRaises(ValidationError):
            self.custodian.create_credential(
                name="Empty Credential",
                credentials={}
            )

    def test_large_credential_data(self):
        """Test creating credential with large data."""
        large_credentials = {
            "username": "user",
            "password": "pass",
            "large_field": "x" * 1000  # 1KB of data
        }
        
        key_id = self.custodian.create_credential(
            name="Large Credential",
            credentials=large_credentials
        )
        
        data = self.custodian.read_credential(key_id)
        self.assertEqual(data["credentials"]["large_field"], "x" * 1000)

    def test_batch_credential_operations(self):
        """Test batch credential operations using shared utilities."""
        # Create multiple credentials using batch utility
        credentials = TestUtilities.create_test_credentials_batch(3, "batch")
        key_ids = []
        
        for cred in credentials:
            key_id = self.custodian.create_credential(**cred)
            key_ids.append(key_id)
        
        # Verify all credentials were created
        self.assertEqual(self.custodian.credential_count, 3)
        
        # Verify each credential can be read
        for i, key_id in enumerate(key_ids):
            data = self.custodian.read_credential(key_id)
            TestUtilities.verify_credential_data(
                data, 
                credentials[i]["credentials"], 
                credentials[i]["meta_data"]
            )
        
        # Test finding credentials by name
        for cred in credentials:
            found = self.custodian.find_credential_by_name(cred["name"])
            self.assertIsNotNone(found)
            self.assertEqual(found["name"], cred["name"])


if __name__ == "__main__":
    unittest.main()
