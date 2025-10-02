"""Simplified unit tests for the KeyCustodian module using actual data classes."""

import os
import tempfile
from unittest.mock import patch

import pytest
from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants
from splurge_key_custodian.exceptions import (
    KeyNotFoundError,
    ValidationError,
)
from splurge_key_custodian.key_custodian import KeyCustodian


class TestKeyCustodianUnit:
    """Simplified unit tests for KeyCustodian class using actual data."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = "ThisIsAValidTestPasswordWithAllRequirements123!@#"
        self.custodian = KeyCustodian(
            self.master_password, self.temp_dir, iterations=Constants.MIN_ITERATIONS()
        )
        self.test_credentials = {"username": "testuser", "password": "testpass123"}
        self.test_meta_data = {"service": "test-service", "url": "https://test.com"}
        yield
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test KeyCustodian initialization."""
        assert self.custodian.data_directory == self.temp_dir
        # Note: We can't test _master_password or _file_manager directly as they are private
        # The functionality is tested through the public methods

    def test_initialization_none_master_password(self):
        """Test initialization with None master password."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(None, self.temp_dir)

        assert "Master password cannot be None" in str(cm.value)

    def test_initialization_empty_master_password(self):
        """Test initialization with empty master password."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian("", self.temp_dir)

        assert "Master password cannot be empty" in str(cm.value)

    def test_initialization_whitespace_only_master_password(self):
        """Test initialization with whitespace-only master password."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian("   \t\n   ", self.temp_dir)

        assert "Master password cannot contain only whitespace" in str(cm.value)

    def test_initialization_none_data_dir(self):
        """Test initialization with None data directory."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(self.master_password, None)

        assert "Data directory cannot be None" in str(cm.value)

    def test_initialization_empty_data_dir(self):
        """Test initialization with empty data directory."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(self.master_password, "")

        assert "Data directory cannot be empty" in str(cm.value)

    def test_initialization_whitespace_only_data_dir(self):
        """Test initialization with whitespace-only data directory."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(self.master_password, "   \t\n   ")

        assert "Data directory cannot contain only whitespace" in str(cm.value)

    def test_initialization_password_too_short(self):
        """Test initialization with password shorter than 32 characters."""
        short_password = "short123"
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(short_password, self.temp_dir)

        assert "Master password must be at least 32 characters long" in str(cm.value)

    def test_initialization_password_missing_uppercase(self):
        """Test that password missing uppercase is rejected."""
        password_missing_uppercase = (
            "thisisalongpasswordwithlowercase123!@#thisislongenough"
        )
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValidationError) as cm:
                KeyCustodian(password_missing_uppercase, fresh_temp_dir)
            assert "uppercase" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_password_missing_lowercase(self):
        """Test that password missing lowercase is rejected."""
        password_missing_lowercase = (
            "THISISALONGPASSWORDWITHUPPERCASE123!@#EXTRALENGTHHERE"
        )
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValidationError) as cm:
                KeyCustodian(password_missing_lowercase, fresh_temp_dir)
            assert "lowercase" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_password_missing_numeric(self):
        """Test that password missing numeric is rejected."""
        password_missing_numeric = (
            "ThisIsALongPasswordWithLetters!@#AndMoreLettersToBeLong"
        )
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValidationError) as cm:
                KeyCustodian(password_missing_numeric, fresh_temp_dir)
            assert "numeric" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_password_missing_symbol(self):
        """Test that password missing symbol is rejected."""
        password_missing_symbol = (
            "ThisIsALongPasswordWithLetters123AndMoreLettersToBeLong"
        )
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValidationError) as cm:
                KeyCustodian(password_missing_symbol, fresh_temp_dir)
            assert "special" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_password_missing_multiple_classes(self):
        """Test that password missing multiple character classes is rejected."""
        password_missing_multiple = (
            "thisisalongpasswordwithlowercaseonlyandmoretexttomakelong"
        )
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with pytest.raises(ValidationError) as cm:
                KeyCustodian(password_missing_multiple, fresh_temp_dir)
            # Should fail because password lacks uppercase, numeric, and special characters
            assert "uppercase" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_initialization_password_valid_complexity(self):
        """Test initialization with password meeting all complexity requirements."""
        valid_password = "ThisIsAValidPasswordWithAllRequirements123!@#"
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(
                valid_password, fresh_temp_dir, iterations=Constants.MIN_ITERATIONS()
            )
            # Note: We can't test _master_password directly as it is private
            # The functionality is tested through the public methods
            assert custodian.iterations == Constants.MIN_ITERATIONS()
        except ValidationError:
            pytest.fail("Valid password should not raise ValidationError")
        finally:
            # Clean up the fresh temporary directory
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_validate_master_password_complexity_valid(self):
        """Test password validation with valid password."""
        valid_password = "ThisIsAValidPasswordWithAllRequirements123!@#"
        # We test password validation through public methods rather than accessing private methods
        # The validation functionality is tested through the public interface
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(valid_password, fresh_temp_dir)
            assert custodian is not None
        finally:
            # Clean up the fresh temporary directory
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_validate_master_password_complexity_too_short(self):
        """Test password validation with too short password."""
        short_password = "short123"
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(short_password, self.temp_dir)

        assert "Master password must be at least 32 characters long" in str(cm.value)

    def test_validate_master_password_complexity_missing_classes(self):
        """Test that password missing character classes is rejected."""
        password_missing_classes = (
            "thisisalongpasswordwithlowercaseonlyandmoretexttomakelong"
        )
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(password_missing_classes, self.temp_dir)
        # Should fail because password lacks uppercase, numeric, and special characters
        assert "uppercase" in str(cm.value)

    def test_initialization_iterations_too_low(self):
        """Test initialization with iterations below minimum."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian(
                self.master_password,
                self.temp_dir,
                iterations=Constants.MIN_ITERATIONS() - 1,
            )

        assert "Iterations must be at least 10,000" in str(cm.value)

    def test_initialization_iterations_valid(self):
        """Test initialization with valid iterations."""
        # Use a fresh temporary directory to avoid conflicts with existing master key
        fresh_temp_dir = tempfile.mkdtemp()
        try:
            custodian = KeyCustodian(
                self.master_password,
                fresh_temp_dir,
                iterations=Constants.MIN_ITERATIONS(),
            )
            assert custodian.iterations == Constants.MIN_ITERATIONS()
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
                self.master_password, fresh_temp_dir, iterations=None
            )
            # Test behavior: should be able to create and read credentials
            key_id = custodian.create_credential(
                name="Test Credential",
                credentials={"username": "test", "password": "test123"},
            )
            assert key_id is not None

            # Should be able to read the credential back
            credential = custodian.read_credential(key_id)
            assert credential["credentials"]["username"] == "test"
            assert credential["credentials"]["password"] == "test123"
        finally:
            # Clean up the fresh temporary directory
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_init_from_environment_success(self):
        """Test successful initialization from environment variable."""
        env_var = "TEST_MASTER_PASSWORD"
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))

        with patch.dict(os.environ, {env_var: encoded_password}):
            custodian = KeyCustodian.init_from_environment(
                env_var, self.temp_dir, iterations=Constants.MIN_ITERATIONS()
            )
            assert isinstance(custodian, KeyCustodian)
            assert custodian.data_directory == self.temp_dir
            assert custodian.iterations == Constants.MIN_ITERATIONS()

    def test_init_from_environment_none_env_variable(self):
        """Test init_from_environment with None environment variable name."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian.init_from_environment(None, self.temp_dir)

        assert "Environment variable name cannot be None" in str(cm.value)

    def test_init_from_environment_empty_env_variable(self):
        """Test init_from_environment with empty environment variable name."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian.init_from_environment("", self.temp_dir)

        assert "Environment variable name cannot be empty" in str(cm.value)

    def test_init_from_environment_whitespace_only_env_variable(self):
        """Test init_from_environment with whitespace-only environment variable name."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian.init_from_environment("   \t\n   ", self.temp_dir)

        assert "Environment variable name cannot contain only whitespace" in str(
            cm.value
        )

    def test_init_from_environment_missing_env_variable(self):
        """Test init_from_environment with missing environment variable."""
        with pytest.raises(ValidationError) as cm:
            KeyCustodian.init_from_environment("NONEXISTENT_VAR", self.temp_dir)

        assert "Environment variable NONEXISTENT_VAR not set" in str(cm.value)

    def test_init_from_environment_empty_env_value(self):
        """Test init_from_environment with empty environment variable value."""
        env_var = "TEST_EMPTY_PASSWORD"

        with patch.dict(os.environ, {env_var: ""}):
            with pytest.raises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)

            assert "Environment variable TEST_EMPTY_PASSWORD is empty" in str(cm.value)

    def test_init_from_environment_whitespace_only_env_value(self):
        """Test init_from_environment with whitespace-only environment variable value."""
        env_var = "TEST_WHITESPACE_PASSWORD"

        with patch.dict(os.environ, {env_var: "   \t\n   "}):
            with pytest.raises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)

            assert (
                "Environment variable TEST_WHITESPACE_PASSWORD contains only whitespace"
                in str(cm.value)
            )

    def test_init_from_environment_invalid_base58(self):
        """Test init_from_environment with invalid Base58 in environment variable."""
        env_var = "TEST_INVALID_PASSWORD"

        with patch.dict(os.environ, {env_var: "invalid-base58!"}):
            with pytest.raises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)

            assert "Invalid Base58 in TEST_INVALID_PASSWORD" in str(cm.value)

    def test_init_from_environment_password_too_short(self):
        """Test init_from_environment with password too short."""
        env_var = "TEST_SHORT_PASSWORD"
        # Create a Base58-encoded short password
        short_password = "short123"
        encoded_password = Base58.encode(short_password.encode("utf-8"))

        with patch.dict(os.environ, {env_var: encoded_password}):
            with pytest.raises(ValidationError) as cm:
                KeyCustodian.init_from_environment(env_var, self.temp_dir)

            assert "Master password must be at least 32 characters long" in str(
                cm.value
            )

    def test_init_from_environment_password_missing_complexity(self):
        """Test that password with missing character classes is rejected."""
        env_var = "TEST_WEAK_PASSWORD"
        weak_password = "thisisalongpasswordwithlowercaseonlyandmoretexttomakelong"
        encoded_password = Base58.encode(weak_password.encode("utf-8"))

        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with patch.dict(os.environ, {env_var: encoded_password}):
                with pytest.raises(ValidationError) as cm:
                    KeyCustodian.init_from_environment(env_var, fresh_temp_dir)

                # Should fail because password lacks uppercase, numeric, and special characters
                assert "uppercase" in str(cm.value)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_init_from_environment_password_with_complexity(self):
        """Test that password with all required character classes passes."""
        env_var = "TEST_COMPLEX_PASSWORD"
        complex_password = "ThisIsAComplexPassword123!WithAllRequiredClasses"
        encoded_password = Base58.encode(complex_password.encode("utf-8"))

        fresh_temp_dir = tempfile.mkdtemp()
        try:
            with patch.dict(os.environ, {env_var: encoded_password}):
                custodian = KeyCustodian.init_from_environment(env_var, fresh_temp_dir)
                assert isinstance(custodian, KeyCustodian)
        finally:
            import shutil

            shutil.rmtree(fresh_temp_dir, ignore_errors=True)

    def test_init_from_environment_iterations_too_low(self):
        """Test init_from_environment with iterations below minimum."""
        env_var = "TEST_MASTER_PASSWORD"
        encoded_password = Base58.encode(self.master_password.encode("utf-8"))

        with patch.dict(os.environ, {env_var: encoded_password}):
            with pytest.raises(ValidationError) as cm:
                KeyCustodian.init_from_environment(
                    env_var, self.temp_dir, iterations=Constants.MIN_ITERATIONS() - 1
                )

            assert "Iterations must be at least 10,000" in str(cm.value)

    def test_data_directory_property(self):
        """Test data_directory property."""
        assert self.custodian.data_directory == self.temp_dir

    def test_master_key_id_property(self):
        """Test master_key_id property."""
        # The custodian should have created a master key during initialization
        master_key_id = self.custodian.master_key_id
        assert master_key_id is not None
        assert isinstance(master_key_id, str)
        assert len(master_key_id) > 0

    def test_credential_count_property_empty(self):
        """Test credential_count property when no credentials exist."""
        count = self.custodian.credential_count
        assert count == 0

    def test_credential_count_property_with_credentials(self):
        """Test credential_count property when credentials exist."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data,
        )

        count = self.custodian.credential_count
        assert count == 1

    def test_create_credential_empty_name(self):
        """Test create_credential with empty name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(name="", credentials=self.test_credentials)

        assert "Credential name cannot be empty" in str(cm.value)

    def test_create_credential_none_name(self):
        """Test create_credential with None name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(
                name=None, credentials=self.test_credentials
            )

        assert "Credential name cannot be None" in str(cm.value)

    def test_create_credential_whitespace_only_name(self):
        """Test create_credential with whitespace-only name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(
                name="   \t\n   ", credentials=self.test_credentials
            )

        assert "Credential name cannot contain only whitespace" in str(cm.value)

    def test_create_credential_empty_credentials(self):
        """Test create_credential with empty credentials."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(name="test-credential", credentials={})

        assert "Credentials cannot be empty" in str(cm.value)

    def test_create_credential_none_credentials(self):
        """Test create_credential with None credentials."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(name="test-credential", credentials=None)

        assert "Credentials cannot be None" in str(cm.value)

    def test_create_credential_duplicate_name(self):
        """Test create_credential with duplicate name."""
        # Create first credential
        self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Try to create second credential with same name
        with pytest.raises(ValidationError) as cm:
            self.custodian.create_credential(
                name="test-credential", credentials=self.test_credentials
            )

        assert "Credential name 'test-credential' already exists" in str(cm.value)

    def test_create_credential_success(self):
        """Test successful credential creation."""
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data,
        )

        assert isinstance(key_id, str)
        assert len(key_id) > 0

        # Verify the credential was created
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data["credentials"] == self.test_credentials
        assert credential_data["meta_data"] == self.test_meta_data

    def test_read_credential_success(self):
        """Test successful credential reading."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data,
        )

        # Read the credential
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data["credentials"] == self.test_credentials
        assert credential_data["meta_data"] == self.test_meta_data

    def test_read_credential_not_found(self):
        """Test reading non-existent credential."""
        with pytest.raises(KeyNotFoundError) as cm:
            self.custodian.read_credential("non-existent-key-id")

        assert "Credential with key ID 'non-existent-key-id' not found" in str(cm.value)

    def test_read_credential_empty_key_id(self):
        """Test read_credential with empty key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.read_credential("")

        assert "Key ID cannot be empty" in str(cm.value)

    def test_read_credential_none_key_id(self):
        """Test read_credential with None key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.read_credential(None)

        assert "Key ID cannot be None" in str(cm.value)

    def test_read_credential_whitespace_only_key_id(self):
        """Test read_credential with whitespace-only key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.read_credential("   \t\n   ")

        assert "Key ID cannot contain only whitespace" in str(cm.value)

    def test_update_credential_success(self):
        """Test successful credential update."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential",
            credentials=self.test_credentials,
            meta_data=self.test_meta_data,
        )

        # Update the credential
        new_credentials = {"username": "newuser", "password": "newpass"}
        new_meta_data = {"service": "new-service", "url": "https://new.com"}

        self.custodian.update_credential(
            key_id=key_id,
            name="updated-credential",
            credentials=new_credentials,
            meta_data=new_meta_data,
        )

        # Verify the update
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data["credentials"] == new_credentials
        assert credential_data["meta_data"] == new_meta_data

    def test_update_credential_not_found(self):
        """Test updating non-existent credential."""
        with pytest.raises(KeyNotFoundError) as cm:
            self.custodian.update_credential(
                key_id="non-existent-key-id", name="updated-name"
            )

        assert "Credential with key ID 'non-existent-key-id' not found" in str(cm.value)

    def test_update_credential_empty_key_id(self):
        """Test update_credential with empty key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id="", name="updated-name")

        assert "Key ID cannot be empty" in str(cm.value)

    def test_update_credential_none_key_id(self):
        """Test update_credential with None key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id=None, name="updated-name")

        assert "Key ID cannot be None" in str(cm.value)

    def test_update_credential_whitespace_only_key_id(self):
        """Test update_credential with whitespace-only key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id="   \t\n   ", name="updated-name")

        assert "Key ID cannot contain only whitespace" in str(cm.value)

    def test_update_credential_none_name(self):
        """Test update_credential with None name (should be allowed)."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Update with None name (should not change the name)
        self.custodian.update_credential(key_id=key_id, name=None)

        # Verify the name wasn't changed
        credential_info = self.custodian.find_credential_by_name("test-credential")
        assert credential_info is not None
        assert credential_info["key_id"] == key_id

    def test_update_credential_empty_name(self):
        """Test update_credential with empty name."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id=key_id, name="")

        assert "Credential name cannot be empty" in str(cm.value)

    def test_update_credential_whitespace_only_name(self):
        """Test update_credential with whitespace-only name."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id=key_id, name="   \t\n   ")

        assert "Credential name cannot contain only whitespace" in str(cm.value)

    def test_update_credential_none_credentials(self):
        """Test update_credential with None credentials (should be allowed)."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Update with None credentials (should not change the credentials)
        self.custodian.update_credential(key_id=key_id, credentials=None)

        # Verify the credentials weren't changed
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data["credentials"] == self.test_credentials

    def test_update_credential_empty_credentials(self):
        """Test update_credential with empty credentials."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        with pytest.raises(ValidationError) as cm:
            self.custodian.update_credential(key_id=key_id, credentials={})

        assert "Credentials cannot be empty" in str(cm.value)

    def test_delete_credential_success(self):
        """Test successful credential deletion."""
        # Create a credential first
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Verify it exists
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data is not None

        # Delete the credential
        self.custodian.delete_credential(key_id)

        # Verify it's gone
        with pytest.raises(KeyNotFoundError):
            self.custodian.read_credential(key_id)

    def test_delete_credential_not_found(self):
        """Test deleting non-existent credential."""
        with pytest.raises(KeyNotFoundError) as cm:
            self.custodian.delete_credential("non-existent-key-id")

        assert "Credential with key ID 'non-existent-key-id' not found" in str(cm.value)

    def test_delete_credential_empty_key_id(self):
        """Test delete_credential with empty key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.delete_credential("")

        assert "Key ID cannot be empty" in str(cm.value)

    def test_delete_credential_none_key_id(self):
        """Test delete_credential with None key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.delete_credential(None)

        assert "Key ID cannot be None" in str(cm.value)

    def test_delete_credential_whitespace_only_key_id(self):
        """Test delete_credential with whitespace-only key ID."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.delete_credential("   \t\n   ")

        assert "Key ID cannot contain only whitespace" in str(cm.value)

    def test_list_credentials_empty(self):
        """Test list_credentials when no credentials exist."""
        credentials = self.custodian.list_credentials()
        assert credentials == []

    def test_list_credentials_with_data(self):
        """Test list_credentials when credentials exist."""
        # Create some credentials
        key_id1 = self.custodian.create_credential(
            name="credential-1", credentials=self.test_credentials
        )
        key_id2 = self.custodian.create_credential(
            name="credential-2", credentials=self.test_credentials
        )

        credentials = self.custodian.list_credentials()
        assert len(credentials) == 2

        # Verify the credentials are in the list
        credential_names = [cred["name"] for cred in credentials]
        assert "credential-1" in credential_names
        assert "credential-2" in credential_names

    def test_find_credential_by_name(self):
        """Test finding credential by name."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Find it by name
        credential_info = self.custodian.find_credential_by_name("test-credential")
        assert credential_info is not None
        assert credential_info["key_id"] == key_id
        assert credential_info["name"] == "test-credential"

    def test_find_credential_by_name_not_found(self):
        """Test finding non-existent credential by name."""
        credential_info = self.custodian.find_credential_by_name(
            "non-existent-credential"
        )
        assert credential_info is None

    def test_find_credential_by_name_none_name(self):
        """Test find_credential_by_name with None name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.find_credential_by_name(None)

        assert "Name cannot be None" in str(cm.value)

    def test_find_credential_by_name_empty_name(self):
        """Test find_credential_by_name with empty name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.find_credential_by_name("")

        assert "Name cannot be empty" in str(cm.value)

    def test_find_credential_by_name_whitespace_only_name(self):
        """Test find_credential_by_name with whitespace-only name."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.find_credential_by_name("   \t\n   ")

        assert "Name cannot contain only whitespace" in str(cm.value)

    def test_rebuild_index(self):
        """Test manual index rebuild."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Rebuild the index
        self.custodian.rebuild_index()

        # Verify the credential is still accessible
        credential_data = self.custodian.read_credential(key_id)
        assert credential_data is not None

    def test_backup_credentials(self):
        """Test credential backup."""
        # Create a credential
        key_id = self.custodian.create_credential(
            name="test-credential", credentials=self.test_credentials
        )

        # Create backup directory
        backup_dir = os.path.join(self.temp_dir, "backup")

        # Perform backup
        self.custodian.backup_credentials(backup_dir)

        # Verify backup directory exists
        assert os.path.exists(backup_dir)

    def test_backup_credentials_none_backup_dir(self):
        """Test backup_credentials with None backup directory."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.backup_credentials(None)

        assert "Backup directory cannot be None" in str(cm.value)

    def test_backup_credentials_empty_backup_dir(self):
        """Test backup_credentials with empty backup directory."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.backup_credentials("")

        assert "Backup directory cannot be empty" in str(cm.value)

    def test_backup_credentials_whitespace_only_backup_dir(self):
        """Test backup_credentials with whitespace-only backup directory."""
        with pytest.raises(ValidationError) as cm:
            self.custodian.backup_credentials("   \t\n   ")

        assert "Backup directory cannot contain only whitespace" in str(cm.value)
