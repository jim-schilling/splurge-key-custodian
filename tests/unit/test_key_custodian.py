"""Simplified unit tests for the KeyCustodian module using actual data classes."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timezone
import tempfile
import os
import json

from splurge_key_custodian.key_custodian import KeyCustodian
from splurge_key_custodian.exceptions import (
    ValidationError,
    KeyNotFoundError,
    EncryptionError,
    MasterKeyError,
)
from splurge_key_custodian.models import (
    CredentialData,
    CredentialFile,
    CredentialsIndex,
    MasterKey,
)
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.base58 import Base58


class TestKeyCustodianUnit(unittest.TestCase):
    """Simplified unit tests for KeyCustodian class using actual data."""

    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = "ThisIsAValidTestPasswordWithAllRequirements123!@#"
        
        # Create a real KeyCustodian instance
        self.custodian = KeyCustodian(
            self.master_password,
            self.temp_dir,
            iterations=500000
        )
        
        # Set up some test data
        self.test_credentials = {
            "username": "testuser",
            "password": "testpass123"
        }
        self.test_meta_data = {
            "service": "test-service",
            "url": "https://test.com"
        }

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove temporary directory
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test KeyCustodian initialization."""
        self.assertEqual(self.custodian._data_dir, self.temp_dir)
        self.assertEqual(self.custodian._master_password, self.master_password)
        self.assertIsNotNone(self.custodian._file_manager)

    def test_initialization_none_master_password(self):
        """Test initialization with None master password."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                None,
                self.temp_dir
            )
        
        self.assertIn("Master password cannot be None", str(cm.exception))

    def test_initialization_empty_master_password(self):
        """Test initialization with empty master password."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                "",
                self.temp_dir
            )
        
        self.assertIn("Master password cannot be empty", str(cm.exception))

    def test_initialization_whitespace_only_master_password(self):
        """Test initialization with whitespace-only master password."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                "   \t\n   ",
                self.temp_dir
            )
        
        self.assertIn("Master password cannot contain only whitespace", str(cm.exception))

    def test_initialization_none_data_dir(self):
        """Test initialization with None data directory."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                self.master_password,
                None
            )
        
        self.assertIn("Data directory cannot be None", str(cm.exception))

    def test_initialization_empty_data_dir(self):
        """Test initialization with empty data directory."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                self.master_password,
                ""
            )
        
        self.assertIn("Data directory cannot be empty", str(cm.exception))

    def test_initialization_whitespace_only_data_dir(self):
        """Test initialization with whitespace-only data directory."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                self.master_password,
                "   \t\n   "
            )
        
        self.assertIn("Data directory cannot contain only whitespace", str(cm.exception))

    def test_initialization_password_too_short(self):
        """Test initialization with password shorter than 32 characters."""
        short_password = "short123"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                short_password,
                self.temp_dir
            )
        
        self.assertIn("Master password must be at least 32 characters long", str(cm.exception))

    def test_initialization_password_missing_uppercase(self):
        """Test initialization with password missing uppercase characters."""
        password_missing_uppercase = "thisisalongpasswordwithlowercase123!@#"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                password_missing_uppercase,
                self.temp_dir
            )
        
        self.assertIn("uppercase", str(cm.exception))

    def test_initialization_password_missing_lowercase(self):
        """Test initialization with password missing lowercase characters."""
        password_missing_lowercase = "THISISALONGPASSWORDWITHUPPERCASE123!@#"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                password_missing_lowercase,
                self.temp_dir
            )
        
        self.assertIn("lowercase", str(cm.exception))

    def test_initialization_password_missing_numeric(self):
        """Test initialization with password missing numeric characters."""
        password_missing_numeric = "ThisIsALongPasswordWithLetters!@#"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                password_missing_numeric,
                self.temp_dir
            )
        
        self.assertIn("numeric", str(cm.exception))

    def test_initialization_password_missing_symbol(self):
        """Test initialization with password missing symbol characters."""
        password_missing_symbol = "ThisIsALongPasswordWithLetters123"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                password_missing_symbol,
                self.temp_dir
            )
        
        self.assertIn("symbol", str(cm.exception))

    def test_initialization_password_missing_multiple_classes(self):
        """Test initialization with password missing multiple character classes."""
        password_missing_multiple = "thisisalongpasswordwithlowercaseonly"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                password_missing_multiple,
                self.temp_dir
            )
        
        error_message = str(cm.exception)
        self.assertIn("uppercase", error_message)
        self.assertIn("numeric", error_message)
        self.assertIn("symbol", error_message)

    def test_initialization_password_valid_complexity(self):
        """Test initialization with password meeting all complexity requirements."""
        valid_password = "ThisIsAValidPasswordWithAllRequirements123!@#"
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(
                valid_password,
                fresh_temp_dir,
                iterations=500000
            )
            self.assertEqual(custodian._master_password, valid_password)
            self.assertEqual(custodian._iterations, 500000)
        except ValidationError:
            self.fail("Valid password should not raise ValidationError")
        finally:
            # Clean up the fresh temporary directory
            import shutil
            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_validate_master_password_complexity_valid(self):
        """Test _validate_master_password_complexity with valid password."""
        valid_password = "ThisIsAValidPasswordWithAllRequirements123!@#"
        try:
            KeyCustodian._validate_master_password_complexity(valid_password)
        except ValidationError:
            self.fail("Valid password should not raise ValidationError")

    def test_validate_master_password_complexity_too_short(self):
        """Test _validate_master_password_complexity with too short password."""
        short_password = "short123"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian._validate_master_password_complexity(short_password)
        
        self.assertIn("Master password must be at least 32 characters long", str(cm.exception))

    def test_validate_master_password_complexity_missing_classes(self):
        """Test _validate_master_password_complexity with missing character classes."""
        password_missing_classes = "thisisalongpasswordwithlowercaseonly"
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian._validate_master_password_complexity(password_missing_classes)
        
        error_message = str(cm.exception)
        self.assertIn("uppercase", error_message)
        self.assertIn("numeric", error_message)
        self.assertIn("symbol", error_message)

    def test_initialization_iterations_too_low(self):
        """Test initialization with iterations below minimum."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian(
                self.master_password,
                self.temp_dir,
                iterations=100000
            )
        
        self.assertIn("Iterations must be at least 500,000", str(cm.exception))

    def test_initialization_iterations_valid(self):
        """Test initialization with valid iterations."""
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(
                self.master_password,
                fresh_temp_dir,
                iterations=600000
            )
            self.assertEqual(custodian._iterations, 600000)
        finally:
            # Clean up the fresh temporary directory
            import shutil
            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_iterations_none(self):
        """Test initialization with None iterations (should use default)."""
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(
                self.master_password,
                fresh_temp_dir,
                iterations=None
            )
            self.assertIsNone(custodian._iterations)
        finally:
            # Clean up the fresh temporary directory
            import shutil
            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_init_from_environment_success(self):
        """Test successful initialization from environment variable."""
        env_var = "TEST_MASTER_PASSWORD"
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))
        
        with patch.dict(os.environ, {env_var: encoded_password}):
            custodian = KeyCustodian.init_from_environment(env_var, self.temp_dir, iterations=500000)
            self.assertIsInstance(custodian, KeyCustodian)
            self.assertEqual(custodian._data_dir, self.temp_dir)
            self.assertEqual(custodian._iterations, 500000)

    def test_init_from_environment_none_env_variable(self):
        """Test init_from_environment with None environment variable name."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian.init_from_environment(None, self.temp_dir)
        
        self.assertIn("Environment variable name cannot be None", str(cm.exception))

    def test_init_from_environment_empty_env_variable(self):
        """Test init_from_environment with empty environment variable name."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian.init_from_environment("", self.temp_dir)
        
        self.assertIn("Environment variable name cannot be empty", str(cm.exception))

    def test_init_from_environment_whitespace_only_env_variable(self):
        """Test init_from_environment with whitespace-only environment variable name."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian.init_from_environment("   \t\n   ", self.temp_dir)
        
        self.assertIn("Environment variable name cannot contain only whitespace", str(cm.exception))

    def test_init_from_environment_missing_env_variable(self):
        """Test init_from_environment with missing environment variable."""
        with self.assertRaises(ValidationError) as cm:
            KeyCustodian.init_from_environment("NONEXISTENT_VAR", self.temp_dir)
        
        self.assertIn("Environment variable NONEXISTENT_VAR not set", str(cm.exception))

    def test_init_from_environment_empty_env_value(self):
        """Test init_from_environment with empty environment variable value."""
        env_var = "TEST_EMPTY_PASSWORD"
        
        with patch.dict(os.environ, {env_var: ""}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)
            
            self.assertIn("Environment variable TEST_EMPTY_PASSWORD is empty", str(cm.exception))

    def test_init_from_environment_whitespace_only_env_value(self):
        """Test init_from_environment with whitespace-only environment variable value."""
        env_var = "TEST_WHITESPACE_PASSWORD"
        
        with patch.dict(os.environ, {env_var: "   \t\n   "}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)
            
            self.assertIn("Environment variable TEST_WHITESPACE_PASSWORD contains only whitespace", str(cm.exception))

    def test_init_from_environment_invalid_base58(self):
        """Test init_from_environment with invalid Base58 in environment variable."""
        env_var = "TEST_INVALID_PASSWORD"
        
        with patch.dict(os.environ, {env_var: "invalid-base58!"}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)
            
            self.assertIn("Invalid Base58 in TEST_INVALID_PASSWORD", str(cm.exception))

    def test_init_from_environment_password_too_short(self):
        """Test init_from_environment with password too short."""
        env_var = "TEST_SHORT_PASSWORD"
        # Create a Base58-encoded short password
        short_password = "short123"
        encoded_password = Base58.encode(short_password.encode('utf-8'))
        
        with patch.dict(os.environ, {env_var: encoded_password}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)
            
            self.assertIn("Master password must be at least 32 characters long", str(cm.exception))

    def test_init_from_environment_password_missing_complexity(self):
        """Test init_from_environment with password missing complexity."""
        env_var = "TEST_WEAK_PASSWORD"
        # Create a Base58-encoded password missing character classes
        weak_password = "thisisalongpasswordwithlowercaseonly"
        encoded_password = Base58.encode(weak_password.encode('utf-8'))
        
        with patch.dict(os.environ, {env_var: encoded_password}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)
            
            error_message = str(cm.exception)
            self.assertIn("uppercase", error_message)
            self.assertIn("numeric", error_message)
            self.assertIn("symbol", error_message)

    def test_init_from_environment_iterations_too_low(self):
        """Test init_from_environment with iterations below minimum."""
        env_var = "TEST_MASTER_PASSWORD"
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))
        
        with patch.dict(os.environ, {env_var: encoded_password}):
            with self.assertRaises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir, iterations=100000)
            
            self.assertIn("Iterations must be at least 500,000", str(cm.exception))

    def test_data_directory_property(self):
        """Test data_directory property."""
        self.assertEqual(self.custodian.data_directory, self.temp_dir)

    def test_master_key_id_property(self):
        """Test master_key_id property."""
        # The custodian should have created a master key during initialization
        master_key_id = self.custodian.master_key_id
        self.assertIsNotNone(master_key_id)
        self.assertIsInstance(master_key_id, str)
        self.assertTrue(len(master_key_id) > 0)

    def test_credential_count_property_empty(self):
        """Test credential_count property when no credentials exist."""
        count = self.custodian.credential_count
        self.assertEqual(count, 0)

    def test_credential_count_property_with_credentials(self):
        """Test credential_count property when credentials exist."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data
        )
        
        count = self.custodian.credential_count
        self.assertEqual(count, 1)

    def test_create_credential_empty_name(self):
        """Test create_credential with empty name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name="",
                credentials=self.test_credentials
            )
        
        self.assertIn("Credential name cannot be empty", str(cm.exception))

    def test_create_credential_none_name(self):
        """Test create_credential with None name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name=None,
                credentials=self.test_credentials
            )
        
        self.assertIn("Credential name cannot be None", str(cm.exception))

    def test_create_credential_whitespace_only_name(self):
        """Test create_credential with whitespace-only name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name="   \t\n   ",
                credentials=self.test_credentials
            )
        
        self.assertIn("Credential name cannot contain only whitespace", str(cm.exception))

    def test_create_credential_empty_credentials(self):
        """Test create_credential with empty credentials."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name="test-credential",
                credentials={}
            )
        
        self.assertIn("Credentials cannot be empty", str(cm.exception))

    def test_create_credential_none_credentials(self):
        """Test create_credential with None credentials."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name="test-credential",
                credentials=None
            )
        
        self.assertIn("Credentials cannot be None", str(cm.exception))

    def test_create_credential_duplicate_name(self):
        """Test create_credential with duplicate name."""
        # Create first credential
        self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Try to create second credential with same name
        with self.assertRaises(ValidationError) as cm:
            self.custodian.create_credential(
                name="test-credential",
                credentials=self.test_credentials
            )
        
        self.assertIn("Credential name 'test-credential' already exists", str(cm.exception))

    def test_create_credential_success(self):
        """Test successful credential creation."""
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data
        )
        
        self.assertIsInstance(key_id, str)
        self.assertTrue(len(key_id) > 0)
        
        # Verify the credential was created
        credential_data = self.custodian.read_credential(key_id)
        self.assertEqual(credential_data["credentials"], self.test_credentials)
        self.assertEqual(credential_data["meta_data"], self.test_meta_data)

    def test_read_credential_success(self):
        """Test successful credential reading."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data
        )
        
        # Read the credential
        credential_data = self.custodian.read_credential(key_id)
        self.assertEqual(credential_data["credentials"], self.test_credentials)
        self.assertEqual(credential_data["meta_data"], self.test_meta_data)

    def test_read_credential_not_found(self):
        """Test reading non-existent credential."""
        with self.assertRaises(KeyNotFoundError) as cm:
            self.custodian.read_credential("non-existent-key-id")
        
        self.assertIn("Credential with key ID 'non-existent-key-id' not found", str(cm.exception))

    def test_read_credential_empty_key_id(self):
        """Test read_credential with empty key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.read_credential("")
        
        self.assertIn("Key ID cannot be empty", str(cm.exception))

    def test_read_credential_none_key_id(self):
        """Test read_credential with None key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.read_credential(None)
        
        self.assertIn("Key ID cannot be None", str(cm.exception))

    def test_read_credential_whitespace_only_key_id(self):
        """Test read_credential with whitespace-only key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.read_credential("   \t\n   ")
        
        self.assertIn("Key ID cannot contain only whitespace", str(cm.exception))

    def test_update_credential_success(self):
        """Test successful credential update."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data
        )
        
        # Update the credential
        new_credentials = {"username": "newuser", "password": "newpass"}
        new_meta_data = {"service": "new-service", "url": "https://new.com"}
        
        self.custodian.update_credential(
            key_id=key_id,
            name="updated-credential",
            credentials=new_credentials,
            meta_data=new_meta_data
        )
        
        # Verify the update
        credential_data = self.custodian.read_credential(key_id)
        self.assertEqual(credential_data["credentials"], new_credentials)
        self.assertEqual(credential_data["meta_data"], new_meta_data)

    def test_update_credential_not_found(self):
        """Test updating non-existent credential."""
        with self.assertRaises(KeyNotFoundError) as cm:
            self.custodian.update_credential(
                key_id="non-existent-key-id",
                name="updated-name"
            )
        
        self.assertIn("Credential with key ID 'non-existent-key-id' not found", str(cm.exception))

    def test_update_credential_empty_key_id(self):
        """Test update_credential with empty key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id="",
                name="updated-name"
            )
        
        self.assertIn("Key ID cannot be empty", str(cm.exception))

    def test_update_credential_none_key_id(self):
        """Test update_credential with None key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id=None,
                name="updated-name"
            )
        
        self.assertIn("Key ID cannot be None", str(cm.exception))

    def test_update_credential_whitespace_only_key_id(self):
        """Test update_credential with whitespace-only key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id="   \t\n   ",
                name="updated-name"
            )
        
        self.assertIn("Key ID cannot contain only whitespace", str(cm.exception))

    def test_update_credential_none_name(self):
        """Test update_credential with None name (should be allowed)."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Update with None name (should not change the name)
        self.custodian.update_credential(
            key_id=key_id,
            name=None
        )
        
        # Verify the name wasn't changed
        credential_info = self.custodian.find_credential_by_name("test-credential")
        self.assertIsNotNone(credential_info)
        self.assertEqual(credential_info["key_id"], key_id)

    def test_update_credential_empty_name(self):
        """Test update_credential with empty name."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id=key_id,
                name=""
            )
        
        self.assertIn("Credential name cannot be empty", str(cm.exception))

    def test_update_credential_whitespace_only_name(self):
        """Test update_credential with whitespace-only name."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id=key_id,
                name="   \t\n   "
            )
        
        self.assertIn("Credential name cannot contain only whitespace", str(cm.exception))

    def test_update_credential_none_credentials(self):
        """Test update_credential with None credentials (should be allowed)."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Update with None credentials (should not change the credentials)
        self.custodian.update_credential(
            key_id=key_id,
            credentials=None
        )
        
        # Verify the credentials weren't changed
        credential_data = self.custodian.read_credential(key_id)
        self.assertEqual(credential_data["credentials"], self.test_credentials)

    def test_update_credential_empty_credentials(self):
        """Test update_credential with empty credentials."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        with self.assertRaises(ValidationError) as cm:
            self.custodian.update_credential(
                key_id=key_id,
                credentials={}
            )
        
        self.assertIn("Credentials cannot be empty", str(cm.exception))

    def test_delete_credential_success(self):
        """Test successful credential deletion."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Verify it exists
        credential_data = self.custodian.read_credential(key_id)
        self.assertIsNotNone(credential_data)
        
        # Delete the credential
        self.custodian.delete_credential(key_id)
        
        # Verify it's gone
        with self.assertRaises(KeyNotFoundError):
            self.custodian.read_credential(key_id)

    def test_delete_credential_not_found(self):
        """Test deleting non-existent credential."""
        with self.assertRaises(KeyNotFoundError) as cm:
            self.custodian.delete_credential("non-existent-key-id")
        
        self.assertIn("Credential with key ID 'non-existent-key-id' not found", str(cm.exception))

    def test_delete_credential_empty_key_id(self):
        """Test delete_credential with empty key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.delete_credential("")
        
        self.assertIn("Key ID cannot be empty", str(cm.exception))

    def test_delete_credential_none_key_id(self):
        """Test delete_credential with None key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.delete_credential(None)
        
        self.assertIn("Key ID cannot be None", str(cm.exception))

    def test_delete_credential_whitespace_only_key_id(self):
        """Test delete_credential with whitespace-only key ID."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.delete_credential("   \t\n   ")
        
        self.assertIn("Key ID cannot contain only whitespace", str(cm.exception))

    def test_list_credentials_empty(self):
        """Test list_credentials when no credentials exist."""
        credentials = self.custodian.list_credentials()
        self.assertEqual(credentials, [])

    def test_list_credentials_with_data(self):
        """Test list_credentials when credentials exist."""
        # Create some credentials
        key_id1 = self.custodian.create_credential(
            name="credential-1",
            credentials=self.test_credentials
        )
        key_id2 = self.custodian.create_credential(
            name="credential-2",
            credentials=self.test_credentials
        )
        
        credentials = self.custodian.list_credentials()
        self.assertEqual(len(credentials), 2)
        
        # Verify the credentials are in the list
        credential_names = [cred["name"] for cred in credentials]
        self.assertIn("credential-1", credential_names)
        self.assertIn("credential-2", credential_names)

    def test_find_credential_by_name(self):
        """Test finding credential by name."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Find it by name
        credential_info = self.custodian.find_credential_by_name("test-credential")
        self.assertIsNotNone(credential_info)
        self.assertEqual(credential_info["key_id"], key_id)
        self.assertEqual(credential_info["name"], "test-credential")

    def test_find_credential_by_name_not_found(self):
        """Test finding non-existent credential by name."""
        credential_info = self.custodian.find_credential_by_name("non-existent-credential")
        self.assertIsNone(credential_info)

    def test_find_credential_by_name_none_name(self):
        """Test find_credential_by_name with None name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.find_credential_by_name(None)
        
        self.assertIn("Name cannot be None", str(cm.exception))

    def test_find_credential_by_name_empty_name(self):
        """Test find_credential_by_name with empty name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.find_credential_by_name("")
        
        self.assertIn("Name cannot be empty", str(cm.exception))

    def test_find_credential_by_name_whitespace_only_name(self):
        """Test find_credential_by_name with whitespace-only name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.find_credential_by_name("   \t\n   ")
        
        self.assertIn("Name cannot contain only whitespace", str(cm.exception))

    def test_rebuild_index(self):
        """Test manual index rebuild."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Rebuild the index
        self.custodian.rebuild_index()
        
        # Verify the credential is still accessible
        credential_data = self.custodian.read_credential(key_id)
        self.assertIsNotNone(credential_data)

    def test_backup_credentials(self):
        """Test credential backup."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # Create backup directory
        backup_dir = os.path.join(self.temp_dir, "backup")
        
        # Perform backup
        self.custodian.backup_credentials(backup_dir)
        
        # Verify backup directory exists
        self.assertTrue(os.path.exists(backup_dir))

    def test_backup_credentials_none_backup_dir(self):
        """Test backup_credentials with None backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.backup_credentials(None)
        
        self.assertIn("Backup directory cannot be None", str(cm.exception))

    def test_backup_credentials_empty_backup_dir(self):
        """Test backup_credentials with empty backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.backup_credentials("")
        
        self.assertIn("Backup directory cannot be empty", str(cm.exception))

    def test_backup_credentials_whitespace_only_backup_dir(self):
        """Test backup_credentials with whitespace-only backup directory."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian.backup_credentials("   \t\n   ")
        
        self.assertIn("Backup directory cannot contain only whitespace", str(cm.exception))

    def test_initialize_master_key_with_dependencies_empty_master_password(self):
        """Test _initialize_master_key_with_dependencies with empty master password."""
        with self.assertRaises(MasterKeyError) as cm:
            self.custodian._initialize_master_key_with_dependencies(
                master_password="",
                data_dir=self.temp_dir,
                file_manager=self.custodian._file_manager
            )
        
        self.assertIn("Master password is not set", str(cm.exception))

    def test_initialize_master_key_with_dependencies_empty_data_dir(self):
        """Test _initialize_master_key_with_dependencies with empty data directory."""
        with self.assertRaises(MasterKeyError) as cm:
            self.custodian._initialize_master_key_with_dependencies(
                master_password=self.master_password,
                data_dir="",
                file_manager=self.custodian._file_manager
            )
        
        self.assertIn("Data directory is not set", str(cm.exception))

    def test_initialize_master_key_with_dependencies_none_file_manager(self):
        """Test _initialize_master_key_with_dependencies with None file manager."""
        with self.assertRaises(MasterKeyError) as cm:
            self.custodian._initialize_master_key_with_dependencies(
                master_password=self.master_password,
                data_dir=self.temp_dir,
                file_manager=None
            )
        
        self.assertIn("File manager is not initialized", str(cm.exception))

    def test_load_credentials_index_with_dependencies_none_file_manager(self):
        """Test _load_credentials_index_with_dependencies with None file manager."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._load_credentials_index_with_dependencies(
                file_manager=None,
                data_dir=self.temp_dir
            )
        
        self.assertIn("File manager is not initialized", str(cm.exception))

    def test_load_credentials_index_with_dependencies_empty_data_dir(self):
        """Test _load_credentials_index_with_dependencies with empty data directory."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._load_credentials_index_with_dependencies(
                file_manager=self.custodian._file_manager,
                data_dir=""
            )
        
        self.assertIn("Data directory is not set", str(cm.exception))

    def test_rebuild_index_from_files_with_dependencies_none_file_manager(self):
        """Test _rebuild_index_from_files_with_dependencies with None file manager."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._rebuild_index_from_files_with_dependencies(
                file_manager=None,
                data_dir=self.temp_dir
            )
        
        self.assertIn("File manager is not initialized", str(cm.exception))

    def test_rebuild_index_from_files_with_dependencies_empty_data_dir(self):
        """Test _rebuild_index_from_files_with_dependencies with empty data directory."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._rebuild_index_from_files_with_dependencies(
                file_manager=self.custodian._file_manager,
                data_dir=""
            )
        
        self.assertIn("Data directory is not set", str(cm.exception))

    def test_should_rebuild_index_with_dependencies_none_file_manager(self):
        """Test _should_rebuild_index_with_dependencies with None file manager."""
        result = self.custodian._should_rebuild_index_with_dependencies(
            file_manager=None,
            data_dir=self.temp_dir,
            credentials_index=self.custodian._credentials_index
        )
        self.assertFalse(result)

    def test_should_rebuild_index_with_dependencies_empty_data_dir(self):
        """Test _should_rebuild_index_with_dependencies with empty data directory."""
        result = self.custodian._should_rebuild_index_with_dependencies(
            file_manager=self.custodian._file_manager,
            data_dir="",
            credentials_index=self.custodian._credentials_index
        )
        self.assertFalse(result)

    def test_should_rebuild_index_with_dependencies_no_master_keys(self):
        """Test _should_rebuild_index_with_dependencies with no master keys."""
        # Mock file manager to return no master keys
        mock_file_manager = Mock()
        mock_file_manager.read_master_keys.return_value = {}
        
        result = self.custodian._should_rebuild_index_with_dependencies(
            file_manager=mock_file_manager,
            data_dir=self.temp_dir,
            credentials_index=self.custodian._credentials_index
        )
        self.assertFalse(result)

    def test_should_rebuild_index_with_dependencies_no_credentials_index(self):
        """Test _should_rebuild_index_with_dependencies with no credentials index."""
        # Mock file manager to return master keys but no credential files
        mock_file_manager = Mock()
        mock_file_manager.read_master_keys.return_value = {"master_keys": [{"key_id": "test"}]}
        mock_file_manager.list_credential_files.return_value = []
        
        result = self.custodian._should_rebuild_index_with_dependencies(
            file_manager=mock_file_manager,
            data_dir=self.temp_dir,
            credentials_index=None
        )
        self.assertFalse(result)

    def test_should_rebuild_index_with_dependencies_with_credential_files(self):
        """Test _should_rebuild_index_with_dependencies with credential files but no index."""
        # Mock file manager to return master keys and credential files
        mock_file_manager = Mock()
        mock_file_manager.read_master_keys.return_value = {"master_keys": [{"key_id": "test"}]}
        mock_file_manager.list_credential_files.return_value = ["cred1", "cred2"]
        
        result = self.custodian._should_rebuild_index_with_dependencies(
            file_manager=mock_file_manager,
            data_dir=self.temp_dir,
            credentials_index=None
        )
        self.assertTrue(result)

    def test_check_name_uniqueness_with_dependencies_none_name(self):
        """Test _check_name_uniqueness_with_dependencies with None name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._check_name_uniqueness_with_dependencies(
                name=None,
                exclude_key_id=None,
                credentials_index=self.custodian._credentials_index
            )
        
        self.assertIn("Credential name cannot be None", str(cm.exception))

    def test_check_name_uniqueness_with_dependencies_empty_name(self):
        """Test _check_name_uniqueness_with_dependencies with empty name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._check_name_uniqueness_with_dependencies(
                name="",
                exclude_key_id=None,
                credentials_index=self.custodian._credentials_index
            )
        
        self.assertIn("Credential name cannot be empty", str(cm.exception))

    def test_check_name_uniqueness_with_dependencies_whitespace_only_name(self):
        """Test _check_name_uniqueness_with_dependencies with whitespace-only name."""
        with self.assertRaises(ValidationError) as cm:
            self.custodian._check_name_uniqueness_with_dependencies(
                name="   \t\n   ",
                exclude_key_id=None,
                credentials_index=self.custodian._credentials_index
            )
        
        self.assertIn("Credential name cannot contain only whitespace", str(cm.exception))

    def test_check_name_uniqueness_with_dependencies_duplicate_name(self):
        """Test _check_name_uniqueness_with_dependencies with duplicate name."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        with self.assertRaises(ValidationError) as cm:
            self.custodian._check_name_uniqueness_with_dependencies(
                name="test-credential",
                exclude_key_id=None,
                credentials_index=self.custodian._credentials_index
            )
        
        self.assertIn("Credential name 'test-credential' already exists", str(cm.exception))

    def test_check_name_uniqueness_with_dependencies_same_credential(self):
        """Test _check_name_uniqueness_with_dependencies with same credential (should pass)."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials
        )
        
        # This should not raise an exception because we're updating the same credential
        self.custodian._check_name_uniqueness_with_dependencies(
            name="test-credential",
            exclude_key_id=key_id,
            credentials_index=self.custodian._credentials_index
        )

    def test_check_name_uniqueness_with_dependencies_none_credentials_index(self):
        """Test _check_name_uniqueness_with_dependencies with None credentials index."""
        # This should not raise an exception because it creates a new index
        self.custodian._check_name_uniqueness_with_dependencies(
            name="new-credential",
            exclude_key_id=None,
            credentials_index=None
        )

    def test_master_key_id_property_none_master_key(self):
        """Test master_key_id property when _current_master_key is None."""
        # Temporarily set _current_master_key to None
        original_master_key = self.custodian._current_master_key
        self.custodian._current_master_key = None
        
        try:
            master_key_id = self.custodian.master_key_id
            self.assertEqual(master_key_id, "")
        finally:
            # Restore the original master key
            self.custodian._current_master_key = original_master_key

    def test_credential_count_property_none_credentials_index(self):
        """Test credential count property when credentials index is None."""
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            # Create a new custodian without initializing the index
            custodian = KeyCustodian(self.master_password, fresh_temp_dir)
            custodian._credentials_index = None
            
            self.assertEqual(custodian.credential_count, 0)
        finally:
            # Clean up the fresh temporary directory
            import shutil
            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_rate_limiting_initialization(self):
        """Test rate limiting initialization."""
        self.assertEqual(self.custodian._failed_attempts, 0)
        self.assertEqual(self.custodian._last_failed_attempt, 0.0)
        self.assertEqual(self.custodian._lockout_until, 0.0)

    def test_rate_limiting_check_rate_limit_no_lockout(self):
        """Test rate limiting check when not locked out."""
        # Should not raise an exception when not locked out
        try:
            self.custodian._check_rate_limit()
        except MasterKeyError:
            self.fail("Should not raise exception when not locked out")

    def test_rate_limiting_record_failed_attempt(self):
        """Test recording failed attempts."""
        import time
        
        # Record a failed attempt
        self.custodian._record_failed_attempt()
        
        self.assertEqual(self.custodian._failed_attempts, 1)
        self.assertGreater(self.custodian._last_failed_attempt, 0.0)

    def test_rate_limiting_reset_failed_attempts(self):
        """Test resetting failed attempts."""
        # Set some failed attempts
        self.custodian._failed_attempts = 3
        self.custodian._lockout_until = 123.0
        
        # Reset
        self.custodian._reset_failed_attempts()
        
        self.assertEqual(self.custodian._failed_attempts, 0)
        self.assertEqual(self.custodian._lockout_until, 0.0)

    def test_rate_limiting_max_attempts_lockout(self):
        """Test lockout after maximum failed attempts."""
        import time
        
        # Record maximum attempts (should raise exception on the last one)
        with self.assertRaises(MasterKeyError) as cm:
            for i in range(KeyCustodian._MAX_LOGIN_ATTEMPTS):
                self.custodian._record_failed_attempt()
        
        self.assertIn("locked", str(cm.exception))
        self.assertGreater(self.custodian._lockout_until, time.time())
        
        # Should still be locked out when checking rate limit
        with self.assertRaises(MasterKeyError) as cm2:
            self.custodian._check_rate_limit()
        
        self.assertIn("locked", str(cm2.exception))

    def test_rate_limiting_lockout_expiry(self):
        """Test that lockout expires after duration."""
        import time
        
        # Set lockout to expire in the past
        self.custodian._lockout_until = time.time() - 1
        
        # Should not be locked out anymore
        try:
            self.custodian._check_rate_limit()
        except MasterKeyError:
            self.fail("Should not be locked out after expiry")

    def test_rate_limiting_failed_attempt_reset_after_duration(self):
        """Test that failed attempts reset after lockout duration."""
        import time
        
        # Record a failed attempt
        self.custodian._record_failed_attempt()
        initial_attempts = self.custodian._failed_attempts
        
        # Set last failed attempt to be older than lockout duration
        self.custodian._last_failed_attempt = time.time() - KeyCustodian._LOCKOUT_DURATION - 1
        
        # Check rate limit (should reset attempts)
        self.custodian._check_rate_limit()
        
        self.assertEqual(self.custodian._failed_attempts, 0) 