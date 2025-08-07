"""Shared utilities for tests."""

import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any

from splurge_key_custodian import KeyCustodian


class TestUtilities:
    """Utility class for test setup and teardown."""
    
    @staticmethod
    def create_temp_data_dir() -> str:
        """Create a temporary data directory for tests."""
        return tempfile.mkdtemp()
    
    @staticmethod
    def cleanup_temp_dir(temp_dir: str) -> None:
        """Clean up a temporary directory."""
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    @staticmethod
    def create_test_custodian(data_dir: str, master_password: str = "TestMasterPasswordWithComplexity123!@#") -> KeyCustodian:
        """Create a KeyCustodian instance for testing."""
        return KeyCustodian(
            master_password,
            data_dir
        )
    
    @staticmethod
    def get_sample_credential() -> Dict[str, Any]:
        """Get sample credential data for tests."""
        return {
            "name": "Test Credential",
            "credentials": {"username": "test_user", "password": "test_pass"},
            "meta_data": {"service": "test_service"}
        }
    
    @staticmethod
    def get_sample_credentials(count: int = 3) -> list[Dict[str, Any]]:
        """Get multiple sample credentials for tests."""
        return [
            {
                "name": f"Test Credential {i}",
                "credentials": {"username": f"user_{i}", "password": f"pass_{i}"},
                "meta_data": {"service": f"service_{i}"}
            }
            for i in range(1, count + 1)
        ]
    
    @staticmethod
    def create_test_file_with_content(content: str, suffix: str = ".txt") -> str:
        """Create a temporary file with specified content."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False)
        temp_file.write(content)
        temp_file.close()
        return temp_file.name
    
    @staticmethod
    def cleanup_test_file(file_path: str) -> None:
        """Clean up a test file."""
        try:
            Path(file_path).unlink()
        except FileNotFoundError:
            pass 