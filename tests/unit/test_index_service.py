"""Unit tests for the IndexService module."""

import tempfile
import unittest
import os
import shutil

from splurge_key_custodian.services.index_service import IndexService
from splurge_key_custodian.exceptions import FileOperationError
from splurge_key_custodian.models import CredentialsIndex, CredentialFile
from splurge_key_custodian.file_manager import FileManager


class TestIndexService(unittest.TestCase):
    """Unit tests for IndexService class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.file_manager = FileManager(self.temp_dir)
        self.service = IndexService(self.file_manager)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_rebuild_index_success(self):
        """Test successful index rebuilding."""
        # Create actual credential files
        credential_files = [
            CredentialFile(
                name="Credential 1",
                key_id="id-1",
                salt="salt1_encoded",
                data="data1_encoded",
                created_at="2023-01-01T00:00:00Z"
            ),
            CredentialFile(
                name="Credential 2",
                key_id="id-2", 
                salt="salt2_encoded",
                data="data2_encoded",
                created_at="2023-01-02T00:00:00Z"
            )
        ]

        # Save credential files using file manager
        for cred_file in credential_files:
            self.file_manager.save_credential_file(cred_file.key_id, cred_file)

        self.service.rebuild_index()

        # Verify index was rebuilt correctly by loading it
        result = self.service.load_index()
        self.assertIsInstance(result, CredentialsIndex)
        self.assertEqual(len(result.credentials), 2)
        self.assertIn("id-1", result.credentials)
        self.assertIn("id-2", result.credentials)
        self.assertEqual(result.credentials["id-1"], "Credential 1")
        self.assertEqual(result.credentials["id-2"], "Credential 2")

    def test_rebuild_index_empty_credentials(self):
        """Test index rebuilding with no credentials."""
        self.service.rebuild_index()

        # Verify empty index was created by loading it
        result = self.service.load_index()
        self.assertIsInstance(result, CredentialsIndex)
        self.assertEqual(len(result.credentials), 0)

    def test_rebuild_index_with_missing_files(self):
        """Test index rebuilding when some credential files are missing."""
        # Create only some credential files
        credential_files = [
            CredentialFile(
                name="Credential 1",
                key_id="id-1",
                salt="salt1_encoded",
                data="data1_encoded",
                created_at="2023-01-01T00:00:00Z"
            ),
            CredentialFile(
                name="Credential 3",
                key_id="id-3",
                salt="salt3_encoded",
                data="data3_encoded",
                created_at="2023-01-03T00:00:00Z"
            )
        ]

        # Save only some credential files
        for cred_file in credential_files:
            self.file_manager.save_credential_file(cred_file.key_id, cred_file)

        self.service.rebuild_index()

        # Verify only existing files are included by loading the index
        result = self.service.load_index()
        self.assertEqual(len(result.credentials), 2)
        self.assertIn("id-1", result.credentials)
        self.assertIn("id-3", result.credentials)
        self.assertNotIn("id-2", result.credentials)

    def test_load_index_success(self):
        """Test successful index loading."""
        # Create and save an index
        index = CredentialsIndex(credentials={"id-1": "Credential 1"})
        self.file_manager.save_credentials_index(index)

        result = self.service.load_index()

        # Verify index was loaded correctly
        self.assertIsInstance(result, CredentialsIndex)
        self.assertEqual(len(result.credentials), 1)
        self.assertIn("id-1", result.credentials)
        self.assertEqual(result.credentials["id-1"], "Credential 1")

    def test_load_index_not_found(self):
        """Test index loading when index file doesn't exist."""
        result = self.service.load_index()

        # Should return empty CredentialsIndex when index doesn't exist and no credential files
        self.assertIsInstance(result, CredentialsIndex)
        self.assertEqual(len(result.credentials), 0)

    def test_save_index_success(self):
        """Test successful index saving."""
        index = CredentialsIndex(credentials={"id-1": "Credential 1"})

        self.service.save_index(index)

        # Verify index was saved by loading it back
        loaded_index = self.file_manager.read_credentials_index()
        self.assertIsInstance(loaded_index, CredentialsIndex)
        self.assertEqual(len(loaded_index.credentials), 1)
        self.assertIn("id-1", loaded_index.credentials)
        self.assertEqual(loaded_index.credentials["id-1"], "Credential 1")

    def test_get_credential_from_index_success(self):
        """Test getting credential from index."""
        # Create and save an index with a credential
        index = CredentialsIndex(credentials={"target-id": "Target Credential"})
        self.file_manager.save_credentials_index(index)

        result = self.service.get_credential_from_index("target-id")

        self.assertEqual(result["name"], "Target Credential")

    def test_get_credential_from_index_not_found(self):
        """Test getting non-existent credential from index."""
        # Create empty index
        index = CredentialsIndex(credentials={})
        self.file_manager.save_credentials_index(index)
        
        result = self.service.get_credential_from_index("non-existent")

        self.assertIsNone(result)

    def test_search_credentials_by_name_success(self):
        """Test searching credentials by name."""
        # Create and save an index with a credential
        index = CredentialsIndex(credentials={"target-id": "Target Credential"})
        self.file_manager.save_credentials_index(index)

        result = self.service.search_credentials_by_name("Target")

        self.assertIn("target-id", result)
        self.assertEqual(result["target-id"]["name"], "Target Credential")

    def test_search_credentials_by_name_not_found(self):
        """Test searching for non-existent credential name."""
        # Create empty index
        index = CredentialsIndex(credentials={})
        self.file_manager.save_credentials_index(index)

        result = self.service.search_credentials_by_name("Non-existent")

        self.assertEqual(len(result), 0)

    def test_add_credential_to_index(self):
        """Test adding credential to index."""
        # Start with empty index
        index = CredentialsIndex(credentials={})
        self.file_manager.save_credentials_index(index)

        self.service.add_credential_to_index("new-id", "New Credential")

        # Verify credential was added by loading the index
        loaded_index = self.file_manager.read_credentials_index()
        self.assertIn("new-id", loaded_index.credentials)
        self.assertEqual(loaded_index.credentials["new-id"], "New Credential")

    def test_remove_credential_from_index(self):
        """Test removing credential from index."""
        # Create index with a credential to remove
        index = CredentialsIndex(credentials={"remove-id": "To Remove"})
        self.file_manager.save_credentials_index(index)

        self.service.remove_credential_from_index("remove-id")

        # Verify credential was removed by loading the index
        loaded_index = self.file_manager.read_credentials_index()
        self.assertNotIn("remove-id", loaded_index.credentials)

    def test_update_credential_in_index(self):
        """Test updating credential in index."""
        # Create index with a credential to update
        index = CredentialsIndex(credentials={"update-id": "Original Name"})
        self.file_manager.save_credentials_index(index)

        self.service.update_credential_in_index("update-id", "Updated Name")

        # Verify credential was updated by loading the index
        loaded_index = self.file_manager.read_credentials_index()
        self.assertIn("update-id", loaded_index.credentials)
        self.assertEqual(loaded_index.credentials["update-id"], "Updated Name")

    def test_list_credentials_from_index(self):
        """Test listing all credentials from index."""
        # Create index with multiple credentials
        index = CredentialsIndex(credentials={
            "id-1": "Credential 1",
            "id-2": "Credential 2"
        })
        self.file_manager.save_credentials_index(index)

        result = self.service.list_credentials_from_index()

        # Verify all credentials are returned
        self.assertEqual(len(result), 2)
        self.assertIn("id-1", result)
        self.assertIn("id-2", result)
        self.assertEqual(result["id-1"]["name"], "Credential 1")
        self.assertEqual(result["id-2"]["name"], "Credential 2")

    def test_get_index_statistics(self):
        """Test getting index statistics."""
        # Create index with multiple credentials
        index = CredentialsIndex(credentials={
            "id-1": "Credential 1",
            "id-2": "Credential 2"
        })
        self.file_manager.save_credentials_index(index)

        result = self.service.get_index_statistics()

        # Verify statistics are returned
        self.assertIn("total_credentials", result)
        self.assertEqual(result["total_credentials"], 2)
        self.assertIn("unique_names", result)
        self.assertEqual(result["unique_names"], 2)
        self.assertIn("index_size_bytes", result)
