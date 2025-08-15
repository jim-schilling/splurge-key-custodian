#!/usr/bin/env python3
"""Integration tests for key rotation functionality."""

import tempfile

import pytest

from splurge_key_custodian.constants import Constants
from splurge_key_custodian.key_custodian import KeyCustodian


class TestKeyCustodianRotationIntegration:
    """Test KeyCustodian integration with rotation functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def master_password(self):
        """Valid master password for testing."""
        return "MySecureMasterPassword123!@#ExtraLongEnough"

    @pytest.fixture
    def custodian(self, temp_dir, master_password):
        """Create a KeyCustodian instance with test credentials."""
        custodian = KeyCustodian(master_password, temp_dir)
        
        # Create some test credentials
        custodian.create_credential(
            name="Test Credential 1",
            credentials={"username": "user1", "password": "pass1"}
        )
        custodian.create_credential(
            name="Test Credential 2", 
            credentials={"username": "user2", "password": "pass2"}
        )
        
        return custodian

    def test_custodian_rotate_master_key_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.rotate_master_key works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform master key rotation
        rotation_id = custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Verify credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Create a new custodian with the same iterations used during rotation
        new_custodian = KeyCustodian(master_password, custodian.data_directory, iterations=Constants.MIN_ITERATIONS() + 1)
        
        # Verify we can read the credentials with the new custodian
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_change_master_password_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.change_master_password works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform master password change
        new_password = "NewSecureMasterPassword456!@#ExtraLongEnough"
        rotation_id = custodian.change_master_password(
            new_master_password=new_password,
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Create new custodian with new password
        new_custodian = KeyCustodian(new_password, custodian.data_directory, iterations=Constants.MIN_ITERATIONS() + 1)
        
        # Verify credentials are accessible with new password
        updated_credentials = new_custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_rotate_all_credentials_works_end_to_end(self, custodian, master_password):
        """Test that KeyCustodian.rotate_all_credentials works end-to-end."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform bulk rotation
        rotation_id = custodian.rotate_all_credentials(
            create_backup=True
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Verify credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_get_rotation_history_returns_history(self, custodian, master_password):
        """Test that KeyCustodian.get_rotation_history returns rotation history."""
        # Perform a rotation to create history
        custodian.rotate_master_key(
            create_backup=True
        )
        
        # Get rotation history
        history = custodian.get_rotation_history()
        
        # Verify history contains the rotation
        assert len(history) == 1
        assert history[0].rotation_type == "master"

    def test_custodian_cleanup_expired_backups_works(self, custodian, master_password):
        """Test that KeyCustodian.cleanup_expired_backups works."""
        # Perform a rotation to create a backup
        custodian.rotate_master_key(
            create_backup=True,
            backup_retention_days=1  # Short retention for testing
        )
        
        # Cleanup expired backups (should not remove recent backup)
        cleaned_count = custodian.cleanup_expired_backups()
        
        # Verify no recent backups were cleaned
        assert cleaned_count == 0

    def test_custodian_rotation_with_multiple_credentials(self, temp_dir, master_password):
        """Test rotation with multiple credentials to ensure all are handled correctly."""
        custodian = KeyCustodian(master_password, temp_dir)
        
        # Create multiple test credentials
        test_credentials = [
            {"name": "Web Login", "credentials": {"username": "webuser", "password": "webpass"}},
            {"name": "Database", "credentials": {"host": "localhost", "port": "5432", "user": "dbuser", "password": "dbpass"}},
            {"name": "API Key", "credentials": {"api_key": "sk-1234567890abcdef", "endpoint": "https://api.example.com"}},
            {"name": "SSH Key", "credentials": {"host": "server.example.com", "user": "sshuser", "private_key": "-----BEGIN PRIVATE KEY-----"}},
        ]
        
        for cred_data in test_credentials:
            custodian.create_credential(
                name=cred_data["name"],
                credentials=cred_data["credentials"]
            )
        
        # Verify all credentials were created
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 4
        
        # Perform master key rotation
        rotation_id = custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=True
        )
        
        assert rotation_id is not None
        
        # Verify all credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 4
        
        # Create a new custodian with the new iterations to read the re-encrypted credentials
        new_custodian = KeyCustodian(master_password, temp_dir, iterations=Constants.MIN_ITERATIONS() + 1)
        
        # Verify each credential's data is preserved
        for i, cred in enumerate(updated_credentials):
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert credential_data['credentials'] == test_credentials[i]["credentials"]

    def test_custodian_rotation_preserves_credential_metadata(self, custodian, master_password):
        """Test that rotation preserves credential metadata like creation dates."""
        # Get initial credential data
        initial_credentials = custodian.list_credentials()
        initial_creation_dates = {}
        
        for cred in initial_credentials:
            # Get the credential file to access creation date
            credential_file = custodian._file_manager.read_credential_file(cred['key_id'])
            initial_creation_dates[cred['key_id']] = credential_file.created_at
        
        # Perform rotation
        rotation_id = custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=True
        )
        
        assert rotation_id is not None
        
        # Verify creation dates are preserved
        updated_credentials = custodian.list_credentials()
        for cred in updated_credentials:
            credential_file = custodian._file_manager.read_credential_file(cred['key_id'])
            assert credential_file.created_at == initial_creation_dates[cred['key_id']]

    def test_custodian_rotation_with_backup_disabled(self, custodian, master_password):
        """Test rotation when backup creation is disabled."""
        # Verify initial credentials exist
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 2
        
        # Perform rotation without backup
        rotation_id = custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=False
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Create a new custodian with the new iterations to read the re-encrypted credentials
        new_custodian = KeyCustodian(master_password, custodian.data_directory, iterations=Constants.MIN_ITERATIONS() + 1)
        
        # Verify credentials are still accessible
        updated_credentials = new_custodian.list_credentials()
        assert len(updated_credentials) == 2
        
        # Verify we can read the credentials
        for cred in updated_credentials:
            credential_data = new_custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']

    def test_custodian_rotation_with_custom_backup_retention(self, custodian, master_password):
        """Test rotation with custom backup retention days."""
        # Perform rotation with custom retention
        rotation_id = custodian.rotate_master_key(
            new_iterations=Constants.MIN_ITERATIONS() + 1,
            create_backup=True,
            backup_retention_days=7  # 7 days retention
        )
        
        # Verify rotation was successful
        assert rotation_id is not None
        
        # Get rotation history to verify the rotation was recorded
        history = custodian.get_rotation_history()
        assert len(history) == 1
        assert history[0].rotation_type == "master"
        assert history[0].rotation_id == rotation_id

    def test_custodian_bulk_rotation_with_batch_processing(self, temp_dir, master_password):
        """Test bulk rotation with batch processing for large numbers of credentials."""
        custodian = KeyCustodian(master_password, temp_dir)
        
        # Create many credentials to test batch processing
        for i in range(25):
            custodian.create_credential(
                name=f"Test Credential {i}",
                credentials={
                    "username": f"user{i}",
                    "password": f"pass{i}",
                    "description": f"Test credential number {i}"
                }
            )
        
        # Verify all credentials were created
        initial_credentials = custodian.list_credentials()
        assert len(initial_credentials) == 25
        
        # Perform bulk rotation
        rotation_id = custodian.rotate_all_credentials(
            create_backup=True,
            batch_size=5  # Process in batches of 5
        )
        
        assert rotation_id is not None
        
        # Verify all credentials are still accessible
        updated_credentials = custodian.list_credentials()
        assert len(updated_credentials) == 25
        
        # Verify we can read all credentials
        for cred in updated_credentials:
            credential_data = custodian.read_credential(cred['key_id'])
            assert 'username' in credential_data['credentials']
            assert 'password' in credential_data['credentials']
            assert 'description' in credential_data['credentials']
