"""Unit tests for the CLI module using real implementations."""

import unittest
from unittest.mock import patch
import json
import sys
import os
import tempfile
import shutil
from io import StringIO

from splurge_key_custodian.cli import KeyCustodianCLI, main
from splurge_key_custodian.exceptions import (
    ValidationError,
    KeyNotFoundError,
    EncryptionError,
)
from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.constants import Constants


class TestKeyCustodianCLIUnit(unittest.TestCase):
    """Unit tests for KeyCustodianCLI class using real implementations."""

    def setUp(self):
        """Set up test fixtures."""
        self.cli = KeyCustodianCLI()
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = "TestMasterPasswordWithComplexity123!@#"
        
        # Test data
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
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # Removed parser internals test to avoid testing implementation details

    def test_run_save_command_success(self):
        """Test successful save command execution."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "save",
                "-n", "Test Credential",
                "-c", json.dumps(self.test_credentials),
                "-m", json.dumps(self.test_meta_data)
            ])
        
        output = mock_stdout.getvalue()
        # Should contain a key ID (UUID format)
        self.assertIn("-", output)  # UUIDs contain hyphens
        # Should not contain success message anymore
        self.assertNotIn("Credential 'Test Credential' saved successfully", output)

    def test_run_save_command_with_env_password(self):
        """Test save command with environment password."""
        # Create a valid Base58-encoded password
        encoded_password = Base58.encode(self.master_password.encode('utf-8'))

        with patch.dict('os.environ', {'MASTER_PASSWORD': encoded_password}):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                self.cli.run([
                    "-ep", "MASTER_PASSWORD",
                    "-d", self.temp_dir,
                    "save",
                    "-n", "Test Credential",
                    "-c", json.dumps(self.test_credentials)
                ])

        output = mock_stdout.getvalue()
        # Should contain a key ID (UUID format)
        self.assertIn("-", output)  # UUIDs contain hyphens
        # Should not contain success message anymore
        self.assertNotIn("Credential 'Test Credential' saved successfully", output)

    def test_run_save_command_validation_error(self):
        """Test save command with validation error."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "-d", self.temp_dir,
                    "save",
                    "-n", "Test Credential",
                    "-c", '{"invalid": json}'
                ])
        
        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_read_command_success(self):
        """Test successful read command execution."""
        # First create a credential
        with patch('sys.stdout', new=StringIO()):
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "save",
                "-n", "Test Credential",
                "-c", json.dumps(self.test_credentials),
                "-m", json.dumps(self.test_meta_data)
            ])
        
        # Now read it
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "read",
                "-n", "Test Credential"
            ])
        
        output = mock_stdout.getvalue()
        result = json.loads(output)
        self.assertIn("Test Credential", result["name"])
        self.assertIn("testuser", str(result["credentials"]))
        self.assertIn("testpass123", str(result["credentials"]))

    def test_run_read_command_not_found(self):
        """Test read command with non-existent credential."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "-d", self.temp_dir,
                    "read",
                    "-n", "Non-existent Credential"
                ])
        
        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("not found", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_list_command_success(self):
        """Test successful list command execution."""
        # Create some credentials
        with patch('sys.stdout', new=StringIO()):
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "save",
                "-n", "First Credential",
                "-c", json.dumps({"username": "user1", "password": "pass1"})
            ])
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "save",
                "-n", "Second Credential",
                "-c", json.dumps({"username": "user2", "password": "pass2"})
            ])

        # List credentials
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "list"
            ])

        payload = json.loads(mock_stdout.getvalue())
        self.assertTrue(payload["success"]) 
        self.assertEqual(payload["command"], "list")
        self.assertEqual(payload["count"], 2)
        self.assertIn("First Credential", payload["names"]) 
        self.assertIn("Second Credential", payload["names"]) 

    def test_run_list_command_empty(self):
        """Test list command with no credentials."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "list"
            ])

        payload = json.loads(mock_stdout.getvalue())
        self.assertTrue(payload["success"]) 
        self.assertEqual(payload["command"], "list")
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["names"], [])

    def test_run_master_command_success(self):
        """Test successful master command execution."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "master"
            ])

        payload = json.loads(mock_stdout.getvalue())
        self.assertTrue(payload["success"]) 
        self.assertEqual(payload["command"], "master")
        self.assertIn("-", payload["master_key_id"])  # UUIDs contain hyphens

    def test_run_base58_encode_success(self):
        """Test successful base58 encode command."""
        test_data = "Hello World"
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "--advanced",
                "base58",
                "-e",
                test_data
            ])

        output = mock_stdout.getvalue()
        encoded_data = output.strip()
        
        # Verify it's valid Base58 by trying to decode it
        try:
            decoded = Base58.decode(encoded_data)
            decoded_text = decoded.decode("utf-8")
            self.assertEqual(decoded_text, test_data)
        except Exception as e:
            self.fail(f"Encoded string is not valid Base58: {e}")

    def test_run_base58_decode_success(self):
        """Test base58 decode command with valid data."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "--advanced",
                "base58",
                "-d",
                "JxF12TrwUP45BMd"
            ])

        output = mock_stdout.getvalue()
        self.assertEqual(output.strip(), "Hello World")

    def test_run_base58_generate_success(self):
        """Test base58 generate command."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "--advanced",
                "base58",
                "-g",
                "32"
            ])

        output = mock_stdout.getvalue()
        # Should generate a 32-character Base58-like string
        self.assertIsInstance(output.strip(), str)
        self.assertEqual(len(output.strip()), Constants.MIN_PASSWORD_LENGTH())
        
        # Verify it contains the expected character sets
        generated_string = output.strip()
        
        # Check that the generated string contains characters from all expected sets
        string_chars = set(generated_string)
        self.assertTrue(any(c in Base58.ALPHA_UPPER for c in string_chars))
        self.assertTrue(any(c in Base58.ALPHA_LOWER for c in string_chars))
        self.assertTrue(any(c in Base58.DIGITS for c in string_chars))
        self.assertTrue(any(c in Constants.ALLOWABLE_SPECIAL() for c in string_chars))

    def test_run_base58_both_args_error(self):
        """Test base58 command with both encode and decode args."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "--advanced",
                    "base58",
                    "-e", "test",
                    "-d", "test"
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("multiple options", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_base58_no_args_error(self):
        """Test base58 command with no encode or decode args."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "--advanced",
                    "base58"
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("encode (-e), decode (-d), or generate (-g)", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_base58_decode_invalid_error(self):
        """Test base58 decode command with invalid data."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "--advanced",
                    "base58",
                    "-d",
                    "invalid-base58-data!"
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("invalid base58", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_no_command_error(self):
        """Test CLI with no command specified."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("no command specified", output.lower())
        # The parser may call exit multiple times, so just check that it was called with 1
        self.assertIn(1, [call.args[0] for call in mock_exit.call_args_list])

    def test_run_unknown_command_error(self):
        """Test CLI with unknown command."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "-d", self.temp_dir,
                    "unknown"
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("unknown command", output.lower())
        # The parser may call exit multiple times, so just check that it was called with 1
        self.assertIn(1, [call.args[0] for call in mock_exit.call_args_list])

    def test_run_respects_default_data_dir(self):
        """Test CLI uses default or SKC_DATA_DIR when data dir not provided."""
        with patch.dict('os.environ', {'SKC_DATA_DIR': self.temp_dir}):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                self.cli.run([
                    "-p", self.master_password,
                    "list"
                ])

        payload = json.loads(mock_stdout.getvalue())
        self.assertTrue(payload["success"]) 
        self.assertEqual(payload["command"], "list")

    def test_run_missing_password_error(self):
        """Test CLI with missing password."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-d", self.temp_dir,
                    "save",
                    "-n", "Test Credential",
                    "-c", json.dumps(self.test_credentials)
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("password", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_both_passwords_error(self):
        """Test CLI with both password and environment password."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "-ep", "ENV_VAR",
                    "-d", self.temp_dir,
                    "save",
                    "-n", "Test Credential",
                    "-c", json.dumps(self.test_credentials)
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("both password and environment password", output.lower())
        mock_exit.assert_called_once_with(1)

    # Removed tests that mock KeyCustodian to simulate keyboard interrupt or unexpected errors

    def test_main_function(self):
        """Test main function."""
        with patch('sys.argv', ['cli.py', '-p', self.master_password, '-d', self.temp_dir, 'list']):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                main()
                
                payload = json.loads(mock_stdout.getvalue())
                self.assertTrue(payload["success"]) 
                self.assertEqual(payload["command"], "list")
                self.assertEqual(payload["count"], 0)
                self.assertEqual(payload["names"], [])

    # Removed direct tests of private _sanitize_input in favor of behavior via run()

    def test_sanitize_input_integration(self):
        """Test input sanitization integration in save command."""
        # Test with dangerous characters in name
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "-d", self.temp_dir,
                    "save",
                    "-n", "Test;Credential",  # Dangerous character
                    "-c", json.dumps(self.test_credentials)
                ])
        
        output = mock_stderr.getvalue()
        self.assertIn("dangerous character", output)
        mock_exit.assert_called_with(1)


if __name__ == "__main__":
    unittest.main() 