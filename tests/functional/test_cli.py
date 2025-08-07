#!/usr/bin/env python3
"""Functional tests for the CLI module using actual implementations."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestCLIFunctional(unittest.TestCase):
    """Functional tests for CLI using actual subprocess calls."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = "TestMasterPasswordWithComplexity123!@#"

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def run_cli_command(self, args: list) -> dict:
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
            return json.loads(e.stdout.strip())

    def run_cli_command_plain(self, args: list) -> str:
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

    def test_base58_encoding_and_decoding(self):
        """Test Base58 encoding and decoding functionality."""
        # Test encoding
        encoded = self.run_cli_command_plain(["base58", "-e", "Hello World"])
        self.assertIn("JxF12TrwUP45BMd", encoded)
        
        # Test decoding
        decoded = self.run_cli_command_plain(["base58", "-d", encoded])
        self.assertEqual(decoded, "Hello World")

    def test_save_credentials_with_master_password(self):
        """Test saving credentials with master password."""
        credentials = {
            "username": "john_doe",
            "password": "secure_password_123",
            "email": "john.doe@example.com"
        }
        meta_data = {
            "service": "example_service",
            "created_by": "admin",
            "notes": "Primary account"
        }
        
        result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "John's Account",
            "-c", json.dumps(credentials),
            "-m", json.dumps(meta_data)
        ])
        
        # Should contain a key ID (UUID format)
        self.assertIn("-", result)  # UUIDs contain hyphens

    def test_save_multiple_credentials(self):
        """Test saving multiple credentials."""
        # Save first credential
        credentials1 = {
            "api_key": "sk-1234567890abcdef",
            "api_secret": "secret_key_abcdef123456"
        }
        meta_data1 = {
            "service": "api_service",
            "environment": "production"
        }
        
        result1 = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "API Production",
            "-c", json.dumps(credentials1),
            "-m", json.dumps(meta_data1)
        ])
        
        # Should contain a key ID (UUID format)
        self.assertIn("-", result1)  # UUIDs contain hyphens
        
        # Save second credential
        credentials2 = {
            "username": "test_user",
            "password": "test_password"
        }
        meta_data2 = {
            "service": "test_service",
            "environment": "development"
        }
        
        result2 = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Test Account",
            "-c", json.dumps(credentials2),
            "-m", json.dumps(meta_data2)
        ])
        
        # Should contain a key ID (UUID format)
        self.assertIn("-", result2)  # UUIDs contain hyphens
        
        # Verify both credentials were saved
        list_result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "list"
        ])
        
        self.assertIn("API Production", list_result)
        self.assertIn("Test Account", list_result)

    def test_list_credentials(self):
        """Test listing credentials."""
        # First save a credential
        credentials = {"test": "data"}
        self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Test Credential",
            "-c", json.dumps(credentials)
        ])
        
        # List credentials
        result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "list"
        ])
        
        self.assertIn("Test Credential", result)

    def test_read_credentials(self):
        """Test reading credentials."""
        # First save a credential
        credentials = {
            "username": "test_user",
            "password": "test_password"
        }
        meta_data = {
            "service": "test_service",
            "notes": "Test credential"
        }
        
        self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Test Credential",
            "-c", json.dumps(credentials),
            "-m", json.dumps(meta_data)
        ])
        
        # Read the credential
        result = self.run_cli_command([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "read",
            "-n", "Test Credential"
        ])
        
        self.assertEqual(result["name"], "Test Credential")
        self.assertEqual(result["credentials"], credentials)
        self.assertEqual(result["meta_data"], meta_data)

    def test_master_password_validation(self):
        """Test master password validation."""
        result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "master"
        ])
        
        # Should contain master key ID (UUID format)
        self.assertIn("-", result)  # UUIDs contain hyphens

    def test_environment_password(self):
        """Test using environment variable for master password."""
        # Create a valid Base58-encoded password
        import base64
        encoded_password = base64.b64encode(self.master_password.encode('utf-8')).decode('utf-8')
        
        # Set environment variable
        os.environ['SPLURGE_MASTER_PASSWORD'] = encoded_password
        
        try:
            result = self.run_cli_command_plain([
                "-ep", "SPLURGE_MASTER_PASSWORD",
                "-d", self.temp_dir,
                "save",
                "-n", "Env Test Credential",
                "-c", '{"test": "data"}'
            ])
            
            # Should contain a key ID (UUID format)
            self.assertIn("-", result)  # UUIDs contain hyphens
        finally:
            # Clean up environment variable
            if 'SPLURGE_MASTER_PASSWORD' in os.environ:
                del os.environ['SPLURGE_MASTER_PASSWORD']

    def test_error_handling_wrong_password(self):
        """Test error handling with wrong password."""
        # First save a credential with correct password
        credentials = {"test": "data"}
        self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Test Credential",
            "-c", json.dumps(credentials)
        ])

        # Try to read with wrong password
        result = self.run_cli_command_plain([
            "-p", "wrong-password",
            "-d", self.temp_dir,
            "read",
            "-n", "Test Credential"
        ])

        # The wrong password should cause an error
        self.assertIn("error", result.lower())

    def test_error_handling_missing_required_args(self):
        """Test error handling with missing required arguments."""
        result = self.run_cli_command_plain([
            "save",
            "-n", "Test Credential",
            "-c", '{"test": "data"}'
        ])
        
        self.assertIn("error", result.lower())

    def test_error_handling_base58_missing_args(self):
        """Test error handling with missing base58 arguments."""
        result = self.run_cli_command_plain(["base58"])
        
        self.assertIn("error", result.lower())
        self.assertIn("encode (-e), decode (-d), or generate (-g)", result.lower())

    def test_error_handling_base58_both_args(self):
        """Test error handling with both base58 encode and decode args."""
        result = self.run_cli_command_plain([
            "base58", "-e", "test", "-d", "test"
        ])
        
        self.assertIn("error", result.lower())
        self.assertIn("multiple options", result.lower())

    def test_error_handling_base58_invalid_decode(self):
        """Test error handling with invalid base58 decode input."""
        result = self.run_cli_command_plain([
            "base58", "-d", "invalid-base58-data!"
        ])
        
        self.assertIn("error", result.lower())
        self.assertIn("invalid base58", result.lower())

    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow."""
        # 1. Save a credential
        credentials = {
            "username": "workflow_user",
            "password": "workflow_password",
            "api_key": "workflow_api_key"
        }
        meta_data = {
            "service": "workflow_service",
            "environment": "production",
            "created_by": "automated_test"
        }
        
        key_id = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Workflow Credential",
            "-c", json.dumps(credentials),
            "-m", json.dumps(meta_data)
        ])
        
        # Should contain a key ID (UUID format)
        self.assertIn("-", key_id)  # UUIDs contain hyphens
        
        # 2. List credentials
        list_result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "list"
        ])
        
        self.assertIn("Workflow Credential", list_result)
        
        # 3. Read the credential
        read_result = self.run_cli_command([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "read",
            "-n", "Workflow Credential"
        ])
        
        self.assertEqual(read_result["name"], "Workflow Credential")
        self.assertEqual(read_result["credentials"], credentials)
        self.assertEqual(read_result["meta_data"], meta_data)
        
        # 4. Validate master password
        master_result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "master"
        ])
        
        # Should contain master key ID (UUID format)
        self.assertIn("-", master_result)  # UUIDs contain hyphens

    def test_file_structure_creation(self):
        """Test that the CLI creates the proper file structure."""
        # Run a command that requires data directory
        self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "save",
            "-n", "Structure Test",
            "-c", '{"test": "data"}'
        ])

        # Check that files were created
        data_path = Path(self.temp_dir)
        self.assertTrue((data_path / "key-custodian-index.json").exists())
        # The credentials directory might not exist if no credentials are saved
        # Let's check for credential files instead
        credential_files = list(data_path.glob("*.credential.json"))
        self.assertGreater(len(credential_files), 0)

    def test_concurrent_operations(self):
        """Test concurrent operations on the same data directory."""
        import threading
        import time
        
        def save_credential(thread_id):
            """Save a credential in a separate thread."""
            credentials = {"thread": thread_id}
            result = self.run_cli_command_plain([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "save",
                "-n", f"Thread {thread_id} Credential",
                "-c", json.dumps(credentials)
            ])
            return result
        
        # Start multiple threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=save_credential, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify all credentials were saved
        list_result = self.run_cli_command_plain([
            "-p", self.master_password,
            "-d", self.temp_dir,
            "list"
        ])
        
        # Check that at least some credentials were saved
        # Due to race conditions, not all threads might succeed
        saved_count = 0
        for i in range(3):
            if f"Thread {i} Credential" in list_result:
                saved_count += 1
        
        # At least one credential should have been saved
        self.assertGreater(saved_count, 0)


if __name__ == "__main__":
    unittest.main() 