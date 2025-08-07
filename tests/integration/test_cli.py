"""Integration tests for the CLI module using actual implementations."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest
from io import StringIO

from splurge_key_custodian.exceptions import (
    ValidationError,
    KeyNotFoundError,
    EncryptionError,
    MasterKeyError,
)
from splurge_key_custodian.base58 import Base58ValidationError, Base58
from splurge_key_custodian.cli import KeyCustodianCLI, main
from splurge_key_custodian import KeyCustodian


class TestKeyCustodianCLI:
    """Integration test cases for the KeyCustodianCLI class using actual implementations."""

    def setup_method(self):
        """Set up test fixtures."""
        self.cli = KeyCustodianCLI()
        self.temp_dir = tempfile.mkdtemp()
        self.master_password = "TestMasterPasswordWithComplexity123!@#"

    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_parser(self):
        """Test that the argument parser is created correctly."""
        parser = self.cli._parser
        assert parser is not None
        assert parser.description == "Splurge Key Custodian File - Secure credential management"

    def test_validate_required_args_base58(self):
        """Test that base58 command doesn't require password or data dir."""
        args = self.cli._parser.parse_args(["base58", "-e", "test"])
        
        # Should not raise any exception
        self.cli._validate_required_args(args)

    def test_validate_required_args_missing_password(self):
        """Test validation fails when no password is provided."""
        # Global args must come before subcommand
        args = self.cli._parser.parse_args(["-d", self.temp_dir, "save", "-n", "test", "-c", '{"test":"data"}'])
        
        with pytest.raises(ValidationError, match="Either password \\(-p/--password\\) or environment password \\(-ep/--env-password\\) is required"):
            self.cli._validate_required_args(args)

    def test_validate_required_args_missing_data_dir(self):
        """Test validation fails when no data directory is provided."""
        # Global args must come before subcommand
        args = self.cli._parser.parse_args(["-p", "test", "save", "-n", "test", "-c", '{"test":"data"}'])
        
        with pytest.raises(ValidationError, match="Data directory \\(-d/--data-dir\\) is required"):
            self.cli._validate_required_args(args)

    def test_validate_required_args_both_passwords(self):
        """Test validation fails when both password types are specified."""
        # Global args must come before subcommand
        args = self.cli._parser.parse_args([
            "-p", "test", "-ep", "ENV_VAR", "-d", self.temp_dir, 
            "save", "-n", "test", "-c", '{"test":"data"}'
        ])
        
        with pytest.raises(ValidationError, match="Cannot specify both password and environment password"):
            self.cli._validate_required_args(args)

    def test_validate_required_args_valid(self):
        """Test validation passes with valid arguments."""
        # Global args must come before subcommand
        args = self.cli._parser.parse_args([
            "-p", "test", "-d", self.temp_dir, 
            "save", "-n", "test", "-c", '{"test":"data"}'
        ])
        
        # Should not raise any exception
        self.cli._validate_required_args(args)

    def test_parse_json_valid(self):
        """Test JSON parsing with valid JSON."""
        result = self.cli._parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_invalid(self):
        """Test JSON parsing with invalid JSON."""
        with pytest.raises(ValidationError, match="Invalid JSON"):
            self.cli._parse_json('{"key": "value"')

    def test_get_custodian_with_password(self):
        """Test creating custodian with password using actual implementation."""
        # Global args must come before subcommand
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "test", "-c", '{"test":"data"}'
        ])
        
        custodian = self.cli._get_custodian(args)
        assert custodian is not None
        assert isinstance(custodian, KeyCustodian)

    def test_get_custodian_with_env_password(self):
        """Test creating custodian with environment password using actual implementation."""
        # Create a valid Base58-encoded password
        encoded_password = Base58.encode(self.master_password.encode('utf-8'))
        
        with patch.dict('os.environ', {'TEST_PASSWORD': encoded_password}):
            # Global args must come before subcommand
            args = self.cli._parser.parse_args([
                "-ep", "TEST_PASSWORD", "-d", self.temp_dir,
                "save", "-n", "test", "-c", '{"test":"data"}'
            ])
            
            custodian = self.cli._get_custodian(args)
            assert custodian is not None
            assert isinstance(custodian, KeyCustodian)

    def test_handle_save_success(self):
        """Test successful save command execution."""
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "Test Credential", "-c", '{"username": "testuser", "password": "testpass"}'
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_save(args)
        
        output = mock_stdout.getvalue()
        # Should contain a key ID (UUID format)
        assert "-" in output  # UUIDs contain hyphens
        # Should not contain success message anymore
        assert "Credential 'Test Credential' saved successfully" not in output

    def test_handle_save_failure(self):
        """Test save command execution with failure."""
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "Test Credential", "-c", '{"invalid": json}'
        ])
        
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli._handle_save(args)
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_handle_read_success(self):
        """Test successful read command execution."""
        # First create a credential
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "Test Credential", "-c", '{"username": "testuser", "password": "testpass"}'
        ])
        
        with patch('sys.stdout', new=StringIO()):
            self.cli._handle_save(args)
        
        # Now read it
        read_args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "read", "-n", "Test Credential"
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_read(read_args)
        
        output = mock_stdout.getvalue()
        result = json.loads(output)
        assert result["name"] == "Test Credential"
        assert result["credentials"]["username"] == "testuser"
        assert result["credentials"]["password"] == "testpass"

    def test_handle_read_not_found(self):
        """Test read command execution with non-existent credential."""
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "read", "-n", "Non-existent Credential"
        ])
        
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli._handle_read(args)
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "not found" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_handle_list_success(self):
        """Test successful list command execution."""
        # Create some credentials
        args1 = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "First Credential", "-c", '{"username": "user1", "password": "pass1"}'
        ])
        args2 = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "save", "-n", "Second Credential", "-c", '{"username": "user2", "password": "pass2"}'
        ])
        
        with patch('sys.stdout', new=StringIO()):
            self.cli._handle_save(args1)
            self.cli._handle_save(args2)
        
        # List credentials
        list_args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "list"
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_list(list_args)
        
        output = mock_stdout.getvalue()
        # Should contain credential names, one per line
        assert "First Credential" in output
        assert "Second Credential" in output
        # Should not contain JSON structure
        assert "success" not in output.lower()
        assert "count" not in output.lower()

    def test_handle_master_success(self):
        """Test successful master command execution."""
        args = self.cli._parser.parse_args([
            "-p", self.master_password, "-d", self.temp_dir,
            "master"
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_master(args)
        
        output = mock_stdout.getvalue()
        # Should contain master key ID (UUID format)
        assert "-" in output  # UUIDs contain hyphens
        # Should not contain JSON structure
        assert "success" not in output.lower()
        assert "master_key_id" not in output.lower()

    def test_handle_base58_encode_success(self):
        """Test successful base58 encode command."""
        args = self.cli._parser.parse_args([
            "base58", "-e", "Hello World"
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_base58(args)
        
        output = mock_stdout.getvalue()
        # Should contain encoded data
        assert "JxF12TrwUP45BMd" in output
        # Should not contain JSON structure
        assert "success" not in output.lower()
        assert "operation" not in output.lower()

    def test_handle_base58_decode_success(self):
        """Test successful base58 decode command."""
        # First encode some data
        encode_args = self.cli._parser.parse_args([
            "base58", "-e", "Hello World"
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_base58(encode_args)
        
        encoded_data = mock_stdout.getvalue().strip()
        
        # Now decode it
        decode_args = self.cli._parser.parse_args([
            "base58", "-d", encoded_data
        ])
        
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli._handle_base58(decode_args)
        
        output = mock_stdout.getvalue()
        # Should contain decoded data
        assert "Hello World" in output
        # Should not contain JSON structure
        assert "success" not in output.lower()
        assert "operation" not in output.lower()

    def test_handle_base58_no_args(self):
        """Test base58 command with no encode or decode args."""
        args = self.cli._parser.parse_args([
            "base58"
        ])
        
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli._handle_base58(args)
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "encode (-e), decode (-d), or generate (-g)" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_handle_base58_both_args(self):
        """Test base58 command with both encode and decode args."""
        args = self.cli._parser.parse_args([
            "base58", "-e", "test", "-d", "test"
        ])
        
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli._handle_base58(args)
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "multiple options" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_handle_base58_decode_invalid(self):
        """Test base58 decode command with invalid data."""
        args = self.cli._parser.parse_args([
            "base58", "-d", "invalid-base58-data!"
        ])
        
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli._handle_base58(args)
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "invalid base58" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_run_save_command(self):
        """Test running save command through the main run method."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "-p", self.master_password, "-d", self.temp_dir,
                "save", "-n", "Test Credential", "-c", '{"username": "testuser", "password": "testpass"}'
            ])
        
        output = mock_stdout.getvalue()
        # Should contain a key ID (UUID format)
        assert "-" in output  # UUIDs contain hyphens
        # Should not contain success message anymore
        assert "Credential 'Test Credential' saved successfully" not in output

    def test_run_base58_command(self):
        """Test running base58 command through the main run method."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            self.cli.run([
                "base58", "-e", "Hello World"
            ])
        
        output = mock_stdout.getvalue()
        # Should contain encoded data
        assert "JxF12TrwUP45BMd" in output
        # Should not contain JSON structure
        assert "success" not in output.lower()
        assert "operation" not in output.lower()

    def test_run_no_command(self):
        """Test running CLI with no command."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([])

        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "no command specified" in output.lower()
        # The parser may call exit multiple times, so just check that it was called with 1
        assert 1 in [call.args[0] for call in mock_exit.call_args_list]

    def test_run_validation_error(self):
        """Test running CLI with validation error."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                self.cli.run([
                    "-p", self.master_password, "-d", self.temp_dir,
                    "save", "-n", "Test Credential", "-c", '{"invalid": json}'
                ])
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_run_keyboard_interrupt(self):
        """Test running CLI with keyboard interrupt."""
        with patch('splurge_key_custodian.cli.KeyCustodian') as mock_key_custodian_class:
            mock_custodian = mock_key_custodian_class.return_value
            mock_custodian.create_credential.side_effect = KeyboardInterrupt()
            
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('sys.exit') as mock_exit:
                    self.cli.run([
                        "-p", self.master_password, "-d", self.temp_dir,
                        "save", "-n", "Test Credential", "-c", '{"username": "testuser", "password": "testpass"}'
                    ])
        
        output = mock_stderr.getvalue()
        assert "operation cancelled" in output.lower()
        mock_exit.assert_called_once_with(1)

    def test_run_unexpected_error(self):
        """Test running CLI with unexpected error."""
        with patch('splurge_key_custodian.cli.KeyCustodian') as mock_key_custodian_class:
            mock_custodian = mock_key_custodian_class.return_value
            mock_custodian.create_credential.side_effect = Exception("Unexpected error")
            
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('sys.exit') as mock_exit:
                    self.cli.run([
                        "-p", self.master_password, "-d", self.temp_dir,
                        "save", "-n", "Test Credential", "-c", '{"username": "testuser", "password": "testpass"}'
                    ])
        
        output = mock_stderr.getvalue()
        assert "error" in output.lower()
        assert "unexpected error" in output.lower()
        mock_exit.assert_called_once_with(1)


class TestCLIIntegration:
    """Integration tests for CLI functionality using actual implementations."""

    def test_cli_help_output(self):
        """Test CLI help output."""
        cli = KeyCustodianCLI()
        # The help output goes to stdout, not through print
        # Just verify the parser exists and has help
        assert cli._parser is not None
        assert cli._parser.description is not None

    def test_cli_base58_help_output(self):
        """Test CLI base58 help output."""
        cli = KeyCustodianCLI()
        base58_parser = None
        for action in cli._parser._subparsers._group_actions:
            if hasattr(action, 'choices'):
                base58_parser = action.choices.get('base58')
                break
        
        assert base58_parser is not None
        # Just verify the parser exists and has arguments
        assert len(base58_parser._actions) > 0

    def test_cli_save_help_output(self):
        """Test CLI save help output."""
        cli = KeyCustodianCLI()
        save_parser = None
        for action in cli._parser._subparsers._group_actions:
            if hasattr(action, 'choices'):
                save_parser = action.choices.get('save')
                break
        
        assert save_parser is not None
        # Just verify the parser exists and has arguments
        assert len(save_parser._actions) > 0

    def test_end_to_end_cli_workflow(self):
        """Test complete CLI workflow using actual implementations."""
        temp_dir = tempfile.mkdtemp()
        master_password = "TestMasterPasswordWithComplexity123!@#"
        
        try:
            cli = KeyCustodianCLI()
            
            # 1. Save a credential
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "save", "-n", "Test Account",
                    "-c", '{"username": "test_user", "password": "test_pass"}',
                    "-m", '{"service": "test_service"}'
                ])
                
                # Verify save was successful - should contain key ID
                output = mock_stdout.getvalue()
                assert "-" in output  # UUIDs contain hyphens
            
            # 2. List credentials
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "list"
                ])
                
                # Verify list was successful
                output = mock_stdout.getvalue()
                assert "Test Account" in output
            
            # 3. Read the credential
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "read", "-n", "Test Account"
                ])
                
                # Verify read was successful
                output = mock_stdout.getvalue()
                result = json.loads(output)
                assert result["credentials"]["username"] == "test_user"
                assert result["credentials"]["password"] == "test_pass"
                assert result["meta_data"]["service"] == "test_service"
            
            # 4. Test master command
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "master"
                ])
                
                # Verify master command was successful
                output = mock_stdout.getvalue()
                assert "-" in output  # UUIDs contain hyphens
                
        finally:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestCLIMain:
    """Tests for the main function using actual implementations."""

    def test_main_function(self):
        """Test the main function with actual CLI implementation."""
        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            with patch('sys.exit') as mock_exit:
                # Test with no arguments (should show help and exit)
                with patch('sys.argv', ['cli.py']):
                    main()
                    
                    # Should have called exit
                    assert mock_exit.called

    def test_main_function_with_base58_command(self):
        """Test the main function with base58 command."""
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('sys.argv', ['cli.py', 'base58', '-e', 'Hello World']):
                main()
                
                # Verify success message was printed
                output = mock_stdout.getvalue()
                assert "JxF12TrwUP45BMd" in output 