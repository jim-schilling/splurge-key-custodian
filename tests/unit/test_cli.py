"""Unit tests for the CLI module using real implementations."""

import unittest
from unittest.mock import patch
import json
import sys
import os
import tempfile
import shutil
from io import StringIO

from splurge_key_custodian.cli import KeyCustodianCLI
from splurge_key_custodian.exceptions import (
    ValidationError,
    KeyNotFoundError,
    EncryptionError,
)
from splurge_key_custodian.base58 import Base58


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

    def test_cli_initialization(self):
        """Test CLI initialization."""
        self.assertIsNotNone(self.cli)
        self.assertIsNotNone(self.cli._parser)

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

        output = mock_stdout.getvalue()
        # Should contain credential names, one per line
        self.assertIn("First Credential", output)
        self.assertIn("Second Credential", output)
        # Should not contain JSON structure
        self.assertNotIn("success", output.lower())
        self.assertNotIn("count", output.lower())

    def test_run_list_command_empty(self):
        """Test list command with no credentials."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "list"
            ])

        output = mock_stdout.getvalue()
        # Should be empty or just whitespace
        self.assertEqual(output.strip(), "")

    def test_run_master_command_success(self):
        """Test successful master command execution."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password,
                "-d", self.temp_dir,
                "master"
            ])

        output = mock_stdout.getvalue()
        # Should contain master key ID (UUID format)
        self.assertIn("-", output)  # UUIDs contain hyphens
        # Should not contain JSON structure
        self.assertNotIn("success", output.lower())
        self.assertNotIn("master_key_id", output.lower())

    def test_run_base58_encode_success(self):
        """Test successful base58 encode command."""
        test_data = "Hello World"
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "base58",
                "-e",
                test_data
            ])

        output = mock_stdout.getvalue()
        encoded_data = output.strip()
        
        # Verify it's valid Base58 by trying to decode it
        from splurge_key_custodian.base58 import Base58
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
                "base58",
                "-g"
            ])

        output = mock_stdout.getvalue()
        # Should generate a Base58-encoded string
        self.assertIsInstance(output.strip(), str)
        self.assertGreater(len(output.strip()), 0)
        
        # Verify it's valid Base58 by trying to decode it
        from splurge_key_custodian.base58 import Base58
        try:
            decoded = Base58.decode(output.strip())
            decoded_text = decoded.decode("utf-8")
            # Should be 64 characters (the length of the generated string)
            self.assertEqual(len(decoded_text), 64)
            
            # Verify it contains the expected character sets
            from splurge_key_custodian.crypto_utils import CryptoUtils
            b58_chars = set(CryptoUtils._B58_ALPHANUMERIC)
            special_chars = set(CryptoUtils._SPECIAL)
            numeric_chars = set(CryptoUtils._B58_NUMERIC)
            
            # Check that the decoded string contains characters from all expected sets
            string_chars = set(decoded_text)
            self.assertTrue(any(c in b58_chars for c in string_chars))
            self.assertTrue(any(c in special_chars for c in string_chars))
            self.assertTrue(any(c in numeric_chars for c in string_chars))
        except Exception as e:
            self.fail(f"Generated string is not valid Base58: {e}")

    def test_run_base58_both_args_error(self):
        """Test base58 command with both encode and decode args."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
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

    def test_run_missing_data_dir_error(self):
        """Test CLI with missing data directory."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password,
                    "save",
                    "-n", "Test Credential",
                    "-c", json.dumps(self.test_credentials)
                ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("data directory", output.lower())
        mock_exit.assert_called_once_with(1)

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

    def test_run_keyboard_interrupt(self):
        """Test CLI with keyboard interrupt."""
        with patch('splurge_key_custodian.cli.KeyCustodian') as mock_key_custodian_class:
            mock_custodian = mock_key_custodian_class.return_value
            mock_custodian.create_credential.side_effect = KeyboardInterrupt()

            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('sys.exit') as mock_exit:
                    self.cli.run([
                        "-p", self.master_password,
                        "-d", self.temp_dir,
                        "save",
                        "-n", "Test Credential",
                        "-c", json.dumps(self.test_credentials)
                    ])

        output = mock_stderr.getvalue()
        self.assertIn("operation cancelled", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_run_unexpected_error(self):
        """Test CLI with unexpected error."""
        with patch('splurge_key_custodian.cli.KeyCustodian') as mock_key_custodian_class:
            mock_custodian = mock_key_custodian_class.return_value
            mock_custodian.create_credential.side_effect = Exception("Unexpected error")

            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('sys.exit') as mock_exit:
                    self.cli.run([
                        "-p", self.master_password,
                        "-d", self.temp_dir,
                        "save",
                        "-n", "Test Credential",
                        "-c", json.dumps(self.test_credentials)
                    ])

        output = mock_stderr.getvalue()
        self.assertIn("error", output.lower())
        self.assertIn("unexpected error", output.lower())
        mock_exit.assert_called_once_with(1)

    def test_main_function(self):
        """Test main function."""
        with patch('sys.argv', ['cli.py', '-p', self.master_password, '-d', self.temp_dir, 'list']):
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                from splurge_key_custodian.cli import main
                main()
                
                # Should complete successfully without calling sys.exit(0)
                output = mock_stdout.getvalue()
                # Should be empty since no credentials exist
                self.assertEqual(output.strip(), "")

    def test_sanitize_input_valid(self):
        """Test input sanitization with valid input."""
        valid_inputs = [
            "normal-text",
            "text with spaces",
            "text-with-dashes",
            "text_with_underscores",
            "text with numbers 123",
            "text with unicode: café, naïve, résumé",
            "a" * 1000  # Maximum length
        ]
        
        for input_text in valid_inputs:
            sanitized = self.cli._sanitize_input(input_text)
            self.assertEqual(sanitized, input_text.strip())

    def test_sanitize_input_dangerous_chars(self):
        """Test input sanitization with dangerous characters."""
        dangerous_inputs = [
            ("text;with;semicolons", ";"),
            ("text|with|pipes", "|"),
            ("text&with&amps", "&"),
            ("text`with`backticks", "`"),
            ("text$with$dollars", "$"),
            ("text(with)parens", "("),
            ("text<with>brackets", "<"),
            ("text>with>brackets", ">"),
        ]
        
        for input_text, dangerous_char in dangerous_inputs:
            with self.assertRaises(ValidationError) as cm:
                self.cli._sanitize_input(input_text)
            self.assertIn(f"dangerous character: {dangerous_char}", str(cm.exception))

    def test_sanitize_input_null_bytes(self):
        """Test input sanitization with null bytes."""
        with self.assertRaises(ValidationError) as cm:
            self.cli._sanitize_input("text\x00with\x00nulls")
        self.assertIn("null bytes", str(cm.exception))

    def test_sanitize_input_too_long(self):
        """Test input sanitization with input that's too long."""
        long_input = "a" * 1001  # Over the 1000 character limit
        with self.assertRaises(ValidationError) as cm:
            self.cli._sanitize_input(long_input)
        self.assertIn("too long", str(cm.exception))

    def test_sanitize_input_whitespace(self):
        """Test input sanitization with whitespace."""
        # Should trim whitespace
        result = self.cli._sanitize_input("  text with spaces  ")
        self.assertEqual(result, "text with spaces")
        
        # Empty string after trimming should be allowed
        result = self.cli._sanitize_input("   ")
        self.assertEqual(result, "")

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