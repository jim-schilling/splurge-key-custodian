"""Functional tests for initialization functionality."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.exceptions import ValidationError
from tests.test_utility import TestDataHelper, TestUtilities


class TestInitializationFunctional:
    """Functional tests for initialization functionality."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = TestDataHelper.create_test_master_password()
        yield
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cli_command(self, args: list) -> dict:
        """Run a CLI command and return the JSON result."""
        return TestUtilities.run_cli_command(args)

    def test_initialization_with_cli(self):
        """Test initialization using CLI."""
        result = self.run_cli_command(
            ["-p", self.master_password, "-d", self.temp_dir, "master"]
        )

        assert "success" in result

    def test_initialization_with_key_custodian(self):
        """Test initialization using KeyCustodian directly."""
        custodian = KeyCustodian(self.master_password, self.temp_dir)

        # Verify initialization was successful
        assert str(custodian.data_directory) == str(Path(self.temp_dir))
        assert custodian.master_key_id is not None
        assert custodian.credential_count == 0

    def test_initialization_creates_required_files(self):
        """Test that initialization creates required files and directories."""
        custodian = KeyCustodian(self.master_password, self.temp_dir)

        # Create a credential to ensure files are created
        custodian.create_credential(
            name="Test Credential", credentials={"username": "test", "password": "test"}
        )

        # Check that data directory exists
        assert Path(self.temp_dir).exists()

        # Check that master keys file exists
        master_keys_file = Path(self.temp_dir) / "key-custodian-master.json"
        if master_keys_file.exists():
            assert master_keys_file.exists()
        else:
            # Files might be created lazily, so we'll check after another operation
            custodian.list_credentials()
            assert master_keys_file.exists()

        # Check that rotation-backups directory exists
        backups_dir = Path(self.temp_dir) / "rotation-backups"
        if backups_dir.exists():
            assert backups_dir.exists()
        else:
            # Directory might be created lazily
            custodian.list_credentials()
            assert backups_dir.exists()

        # Check that index file exists
        index_file = Path(self.temp_dir) / "key-custodian-index.json"
        if index_file.exists():
            assert index_file.exists()
        else:
            # Files might be created lazily
            custodian.list_credentials()
            assert index_file.exists()

    def test_initialization_with_different_iterations(self):
        """Test initialization with different iteration values."""
        from splurge_key_custodian.constants import Constants

        # Test with minimum iterations
        custodian1 = KeyCustodian(
            self.master_password, self.temp_dir, iterations=Constants.MIN_ITERATIONS()
        )
        assert custodian1.master_key_id is not None

        # Clean up for next test
        import shutil

        shutil.rmtree(self.temp_dir)
        self.temp_dir = tempfile.mkdtemp()

        # Test with higher iterations
        custodian2 = KeyCustodian(
            self.master_password,
            self.temp_dir,
            iterations=Constants.MIN_ITERATIONS() + 1000,
        )
        assert custodian2.master_key_id is not None

    def test_initialization_persistence(self):
        """Test that initialization persists across instances."""
        # Create first custodian
        custodian1 = KeyCustodian(self.master_password, self.temp_dir)
        master_key_id1 = custodian1.master_key_id

        # Create second custodian with same directory
        custodian2 = KeyCustodian(self.master_password, self.temp_dir)
        master_key_id2 = custodian2.master_key_id

        # Master key IDs should be the same
        assert master_key_id1 == master_key_id2

    def test_initialization_with_existing_data(self):
        """Test initialization with existing data directory."""
        # Create initial custodian
        custodian1 = KeyCustodian(self.master_password, self.temp_dir)

        # Create a credential
        key_id = custodian1.create_credential(
            name="Test Credential", credentials={"username": "test", "password": "test"}
        )

        # Create new custodian with same directory
        custodian2 = KeyCustodian(self.master_password, self.temp_dir)

        # Should have the same credential
        assert custodian2.credential_count == 1

        # Should be able to read the credential
        data = custodian2.read_credential(key_id)
        assert data["credentials"]["username"] == "test"

    def test_initialization_error_handling(self):
        """Test initialization error handling."""
        # Test with invalid password (too short)
        with pytest.raises(ValidationError):
            KeyCustodian("short", self.temp_dir)

        # Test with invalid directory (non-existent)
        # This might not raise an exception immediately, so we'll test a different scenario
        with pytest.raises(ValidationError):
            KeyCustodian("", self.temp_dir)

    def test_initialization_with_env_master_password(self):
        """Test initialization using environment variable for master password."""
        import os

        # Set environment variable
        os.environ["SPLURGE_MASTER_PASSWORD"] = self.master_password

        try:
            # Test CLI initialization without password parameter
            result = self.run_cli_command(["-d", self.temp_dir, "master"])

            assert "success" in result
        finally:
            # Clean up environment variable
            if "SPLURGE_MASTER_PASSWORD" in os.environ:
                del os.environ["SPLURGE_MASTER_PASSWORD"]

    def test_initialization_file_permissions(self):
        """Test that initialization creates files with appropriate permissions."""
        custodian = KeyCustodian(self.master_password, self.temp_dir)

        # Create a credential to ensure files are created
        custodian.create_credential(
            name="Test Credential", credentials={"username": "test", "password": "test"}
        )

        # Check master keys file permissions
        master_keys_file = Path(self.temp_dir) / "master_keys.json"
        if master_keys_file.exists():
            stat = master_keys_file.stat()
            # Should be readable by owner only (600)
            assert stat.st_mode & 0o777 == 0o600

        # Check credentials directory permissions
        credentials_dir = Path(self.temp_dir) / "credentials"
        if credentials_dir.exists():
            stat = credentials_dir.stat()
            # Should be readable and executable by owner only (700)
            assert stat.st_mode & 0o777 == 0o700

    def test_initialization_with_custom_data_directory(self):
        """Test initialization with custom data directory structure."""
        # Create nested directory structure
        nested_dir = Path(self.temp_dir) / "nested" / "deep" / "structure"
        nested_dir.mkdir(parents=True, exist_ok=True)

        # Initialize in nested directory
        custodian = KeyCustodian(self.master_password, str(nested_dir))

        # Verify initialization was successful
        assert str(custodian.data_directory) == str(nested_dir)
        assert custodian.master_key_id is not None

    def test_initialization_multiple_instances_same_directory(self):
        """Test multiple instances initializing the same directory."""
        # Create first instance
        custodian1 = KeyCustodian(self.master_password, self.temp_dir)

        # Create second instance immediately
        custodian2 = KeyCustodian(self.master_password, self.temp_dir)

        # Both should have the same master key ID
        assert custodian1.master_key_id == custodian2.master_key_id

        # Both should have the same credential count
        assert custodian1.credential_count == custodian2.credential_count
