"""Shared test utilities for the splurge-key-custodian project."""

import json
import os
import subprocess
import tempfile
import shutil
from typing import Dict, Any

from splurge_key_custodian.models import CredentialFile, MasterKey
from splurge_key_custodian.constants import Constants
from splurge_key_custodian import KeyCustodian


class TestDataHelper:
    """Helper class for creating test data with valid Base58 encoding."""

    # Valid Base58 encoded strings for testing
    VALID_BASE58_SALT = "2NEpo7TZRRrLZSi2U"  # Decodes to "Hello World!"
    # For credential data, we need actual Base58 encoded JSON
    VALID_CREDENTIAL_DATA_JSON = '{"encrypted_key":"test_key","encrypted_data":"test_data"}'
    VALID_BASE58_CREDENTIAL_DATA = "2NEpo7TZRRrLZSi2U"  # Will be replaced with actual Base58 encoded JSON
    VALID_BASE58_CREDENTIALS = "2NEpo7TZRRrLZSi2U"  # Decodes to "Hello World!"

    @classmethod
    def create_test_credentials(cls) -> Dict[str, Any]:
        """Create test credential data."""
        return {
            "username": "testuser",
            "password": "testpass"
        }

    @classmethod
    def create_test_meta_data(cls) -> Dict[str, Any]:
        """Create test metadata."""
        return {
            "service": "test-service",
            "url": "https://test.com"
        }

    @classmethod
    def create_test_master_password(cls) -> str:
        """Create a test master password that meets complexity requirements."""
        return "TestMasterPassword123!@#ComplexityRequired"

    @classmethod
    def create_test_credential_file(
        cls,
        name: str = "Test Credential",
        key_id: str = "test-id",
        salt: str | None = None,
        data: str | None = None,
        created_at: str = "2023-01-01T00:00:00Z"
    ) -> CredentialFile:
        """Create a test CredentialFile with valid Base58 data."""
        if data is None:
            data = cls.create_base58_encoded_credential_data()
        
        return CredentialFile(
            name=name,
            key_id=key_id,
            salt=salt or cls.VALID_BASE58_SALT,
            data=data,
            created_at=created_at
        )

    @classmethod
    def create_test_master_key(
        cls,
        key_id: str = "test-key-id",
        salt: str | None = None,
        credentials: str | None = None,
        iterations: int | None = None,
        created_at: str = "2023-01-01T00:00:00Z"
    ) -> MasterKey:
        """Create a test MasterKey with valid Base58 data."""
        return MasterKey(
            key_id=key_id,
            salt=salt or cls.VALID_BASE58_SALT,
            credentials=credentials or cls.VALID_BASE58_CREDENTIALS,
            iterations=iterations or Constants.MIN_ITERATIONS(),
            created_at=created_at
        )

    @classmethod
    def create_master_keys_data(cls, master_key: MasterKey | None = None) -> Dict[str, Any]:
        """Create master keys data structure for file manager mocks."""
        if master_key is None:
            master_key = cls.create_test_master_key()
        
        return {
            "master_keys": [master_key.to_dict()]
        }

    @classmethod
    def create_credential_data_json(cls, credentials: Dict[str, Any] | None = None, meta_data: Dict[str, Any] | None = None) -> str:
        """Create JSON string for credential data."""
        data = {
            "credentials": credentials or cls.create_test_credentials(),
            "meta_data": meta_data or cls.create_test_meta_data()
        }
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def create_encrypted_credential_data(cls, credentials: Dict[str, Any] | None = None, meta_data: Dict[str, Any] | None = None) -> str:
        """Create Base58 encoded encrypted credential data structure."""
        from splurge_key_custodian.base58 import Base58
        
        # Create actual Base58 encoded encrypted data
        encrypted_key = Base58.encode(b"encrypted_key_bytes")
        encrypted_data = Base58.encode(b"encrypted_data_bytes")
        
        data = {
            "encrypted_key": encrypted_key,
            "encrypted_data": encrypted_data
        }
        return json.dumps(data, ensure_ascii=False)

    @classmethod
    def create_base58_encoded_credential_data(cls) -> str:
        """Create actual Base58 encoded credential data for testing."""
        from splurge_key_custodian.base58 import Base58
        json_data = cls.create_encrypted_credential_data()
        return Base58.encode(json_data.encode("utf-8"))


class TestUtilities:
    """Test utilities for integration tests."""

    @staticmethod
    def create_temp_data_dir() -> str:
        """Create a temporary directory for test data."""
        temp_dir = tempfile.mkdtemp(prefix="test_key_custodian_")
        return temp_dir

    @staticmethod
    def create_test_custodian(temp_dir: str, master_password: str) -> KeyCustodian:
        """Create a test KeyCustodian instance."""
        return KeyCustodian(master_password, temp_dir)

    @staticmethod
    def get_sample_credential() -> Dict[str, Any]:
        """Get a sample credential for testing."""
        return {
            "name": "Test Credential",
            "credentials": {
                "username": "test_user",
                "password": "test_pass"
            },
            "meta_data": {
                "service": "test_service",
                "url": "https://test.com"
            }
        }

    @staticmethod
    def cleanup_temp_dir(temp_dir: str) -> None:
        """Clean up temporary directory."""
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    @staticmethod
    def run_cli_command(args: list) -> dict:
        """Run a CLI command and return the JSON result."""
        try:
            result = subprocess.run(
                ["python", "-m", "splurge_key_custodian.cli"] + args,
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            # Handle both stdout and stderr for error responses
            if e.stdout.strip():
                try:
                    return json.loads(e.stdout.strip())
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON in stdout", "output": e.stdout.strip()}
            elif e.stderr.strip():
                try:
                    return json.loads(e.stderr.strip())
                except json.JSONDecodeError:
                    return {"success": False, "error": "Invalid JSON in stderr", "output": e.stderr.strip()}
            else:
                return {"success": False, "error": "Command failed with no output"}

    @staticmethod
    def run_cli_command_plain(args: list) -> str:
        """Run a CLI command and return the plain text result."""
        try:
            result = subprocess.run(
                ["python", "-m", "splurge_key_custodian.cli"] + args,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return e.stderr.strip()

    @staticmethod
    def create_test_credentials_batch(count: int, prefix: str = "test") -> list:
        """Create a batch of test credentials."""
        credentials = []
        for i in range(count):
            credentials.append({
                "name": f"{prefix}_credential_{i}",
                "credentials": {
                    "username": f"{prefix}_user_{i}",
                    "password": f"{prefix}_pass_{i}"
                },
                "meta_data": {
                    "service": f"{prefix}_service_{i}",
                    "index": i
                }
            })
        return credentials

    @staticmethod
    def create_complex_credential() -> Dict[str, Any]:
        """Create a complex credential with nested data."""
        return {
            "name": "Complex Test Credential",
            "credentials": {
                "username": "complex_user",
                "password": "complex_pass",
                "api_key": "sk-1234567890abcdef",
                "metadata": {
                    "created": "2023-01-01",
                    "tags": ["production", "api"],
                    "nested": {
                        "level1": {
                            "level2": "deep_value"
                        }
                    }
                }
            },
            "meta_data": {
                "service": "complex_service",
                "environment": "production",
                "version": "1.0.0"
            }
        }

    @staticmethod
    def verify_credential_data(actual_data: Dict[str, Any], expected_credentials: Dict[str, Any], expected_meta_data: Dict[str, Any] | None = None) -> None:
        """Verify that credential data matches expected values."""
        # Verify credentials
        for key, value in expected_credentials.items():
            assert actual_data["credentials"][key] == value, f"Credential {key} mismatch"
        
        # Verify meta_data if provided
        if expected_meta_data:
            for key, value in expected_meta_data.items():
                assert actual_data["meta_data"][key] == value, f"Meta data {key} mismatch"

    @staticmethod
    def create_test_rotation_scenario(custodian: KeyCustodian, credential_count: int = 3) -> list:
        """Create a test scenario with multiple credentials for rotation testing."""
        credentials = TestUtilities.create_test_credentials_batch(credential_count, "rotation")
        key_ids = []
        
        for cred in credentials:
            key_id = custodian.create_credential(**cred)
            key_ids.append(key_id)
        
        return key_ids

    @staticmethod
    def verify_rotation_preserves_data(custodian: KeyCustodian, key_ids: list, expected_credentials: list) -> None:
        """Verify that rotation preserves all credential data."""
        for i, key_id in enumerate(key_ids):
            data = custodian.read_credential(key_id)
            expected = expected_credentials[i]
            
            # Verify credentials
            for key, value in expected["credentials"].items():
                assert data["credentials"][key] == value, f"Credential {key} not preserved after rotation"
            
            # Verify meta_data
            for key, value in expected["meta_data"].items():
                assert data["meta_data"][key] == value, f"Meta data {key} not preserved after rotation" 