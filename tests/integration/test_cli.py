"""Integration tests for the CLI module using actual implementations."""

import json
import os
import tempfile
from unittest.mock import patch
from io import StringIO

from splurge_key_custodian.cli import KeyCustodianCLI, main


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
                
                # Verify save was successful - parse JSON
                payload = json.loads(mock_stdout.getvalue())
                assert payload["success"] is True
                assert payload["command"] == "save"
                assert "-" in payload["key_id"]
            
            # 2. List credentials
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "list"
                ])
                
                # Verify list was successful
                payload = json.loads(mock_stdout.getvalue())
                assert payload["success"] is True
                assert payload["command"] == "list"
                assert "Test Account" in payload["names"]
            
            # 3. Read the credential
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                # Global args must come before subcommand
                cli.run([
                    "-p", master_password, "-d", temp_dir,
                    "read", "-n", "Test Account"
                ])
                
                # Verify read was successful
                result = json.loads(mock_stdout.getvalue())
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
                payload = json.loads(mock_stdout.getvalue())
                assert payload["success"] is True
                assert payload["command"] == "master"
                assert "-" in payload["master_key_id"]  # UUIDs contain hyphens
                
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
            with patch('sys.argv', ['cli.py', '--advanced', 'base58', '-e', 'Hello World']):
                main()
                
                # Verify success message was printed
                output = mock_stdout.getvalue()
                assert "JxF12TrwUP45BMd" in output 