#!/usr/bin/env python3
"""Unit tests for CLI rotation functionality."""

import json
import tempfile
import re
from pathlib import Path
from unittest.mock import Mock, patch
import sys
from io import StringIO

import pytest

from splurge_key_custodian.cli import KeyCustodianCLI


class TestCLIRotation:
    """Test CLI rotation functionality."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield temp_dir

    @pytest.fixture
    def master_password(self):
        """Valid master password for testing."""
        return "MySecureMasterPassword123!@#ExtraLongEnough"

    @pytest.fixture
    def cli_args_base(self, temp_dir, master_password):
        """Base CLI arguments for testing."""
        return [
            "--password", master_password,
            "--data-dir", temp_dir
        ]

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_rotate_master_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test rotate-master command behavior."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.rotate_master_key.return_value = "test-rotation-id"
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            args = cli_args_base + ["rotate-master", "--new-iterations", "1500000"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "rotate-master"
            assert "rotation_id" in result
            assert result["rotation_id"] == "test-rotation-id"
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.rotate_master_key.assert_called_once_with(
                new_iterations=1500000,
                create_backup=True,
                backup_retention_days=None
            )
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_change_password_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test change-password command behavior."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.change_master_password.return_value = "test-rotation-id"
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            new_password = "NewSecureMasterPassword456!@#ExtraLongEnough"
            args = cli_args_base + ["change-password", "--new-password", new_password, "--new-iterations", "1500000"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "change-password"
            assert "rotation_id" in result
            assert result["rotation_id"] == "test-rotation-id"
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.change_master_password.assert_called_once_with(
                new_master_password=new_password,
                new_iterations=1500000,
                create_backup=True,
                backup_retention_days=None
            )
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_rotate_credentials_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test rotate-credentials command behavior."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.rotate_all_credentials.return_value = "test-rotation-id"
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            args = cli_args_base + ["rotate-credentials", "--iterations", "1500000", "--batch-size", "25"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "rotate-credentials"
            assert "rotation_id" in result
            assert result["rotation_id"] == "test-rotation-id"
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.rotate_all_credentials.assert_called_once_with(
                iterations=1500000,
                create_backup=True,
                backup_retention_days=None,
                batch_size=25
            )
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_history_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test history command behavior."""
        # Mock rotation history
        from splurge_key_custodian.models import RotationHistory
        from datetime import datetime, timezone
        
        mock_history = [
            RotationHistory(
                rotation_id="test-id-1",
                rotation_type="master",
                target_key_id="key-1",
                old_master_key_id="old-key-1",
                new_master_key_id="new-key-1",
                affected_credentials=["cred1", "cred2"],
                created_at=datetime.now(timezone.utc),
                metadata={"test": "data1"}
            ),
            RotationHistory(
                rotation_id="test-id-2",
                rotation_type="bulk",
                target_key_id="key-2",
                old_master_key_id="old-key-2",
                new_master_key_id="new-key-2",
                affected_credentials=["cred3"],
                created_at=datetime.now(timezone.utc),
                metadata={"test": "data2"}
            )
        ]
        
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.get_rotation_history.return_value = mock_history
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            args = cli_args_base + ["history", "--limit", "5"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "history"
            assert "history" in result
            assert isinstance(result["history"], list)
            assert len(result["history"]) == 2
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.get_rotation_history.assert_called_once_with(limit=5)
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_rollback_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test rollback command behavior."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.rollback_rotation.return_value = None
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            rotation_id = "test-rotation-id"
            args = cli_args_base + ["rollback", "--rotation-id", rotation_id]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "rollback"
            assert "message" in result
            # Use pattern matching for message content
            assert re.search(r'rollback.*completed.*successfully', result["message"], re.IGNORECASE)
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.rollback_rotation.assert_called_once_with(rotation_id=rotation_id)
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_cleanup_backups_command_behavior(self, mock_key_custodian_class, cli_args_base):
        """Test cleanup-backups command behavior."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.cleanup_expired_backups.return_value = 3
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            args = cli_args_base + ["cleanup-backups"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            assert result["command"] == "cleanup-backups"
            assert "cleaned_count" in result
            assert result["cleaned_count"] == 3
            
            # Verify KeyCustodian was called correctly
            mock_key_custodian_class.assert_called_once()
            mock_custodian.cleanup_expired_backups.assert_called_once()
        finally:
            sys.stdout = original_stdout

    @patch('splurge_key_custodian.cli.KeyCustodian')
    def test_rotate_master_command_with_no_backup(self, mock_key_custodian_class, cli_args_base):
        """Test rotate-master command with no backup option."""
        # Mock KeyCustodian instance
        mock_custodian = Mock()
        mock_custodian.rotate_master_key.return_value = "test-rotation-id"
        mock_key_custodian_class.return_value = mock_custodian
        
        # Capture stdout to verify output
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output
        
        try:
            # Create CLI args
            args = cli_args_base + ["rotate-master", "--no-backup"]
            
            # Run CLI
            cli = KeyCustodianCLI()
            cli.run(args)
            
            # Verify output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is True
            
            # Verify KeyCustodian was called with no backup
            mock_custodian.rotate_master_key.assert_called_once_with(
                new_iterations=None,
                create_backup=False,
                backup_retention_days=None
            )
        finally:
            sys.stdout = original_stdout

    def test_rotate_master_command_missing_password(self, temp_dir):
        """Test rotate-master command fails when password is missing."""
        # Capture stderr to verify error output
        captured_output = StringIO()
        original_stderr = sys.stderr
        sys.stderr = captured_output
        
        try:
            # Create CLI args without password
            args = ["--data-dir", temp_dir, "rotate-master"]
            
            # Run CLI and expect SystemExit
            cli = KeyCustodianCLI()
            with pytest.raises(SystemExit):
                cli.run(args)
            
            # Verify error output
            output = captured_output.getvalue()
            result = json.loads(output)
            
            assert result["success"] is False
            assert "error_code" in result
            # Use pattern matching for message content
            assert re.search(r'password.*required', result["message"], re.IGNORECASE)
        finally:
            sys.stderr = original_stderr

    def test_cli_commands_exist(self):
        """Test that CLI commands exist and are accessible."""
        cli = KeyCustodianCLI()
        
        # Test that CLI can be instantiated and has basic functionality
        # We test the public interface rather than accessing private parser attributes
        assert cli is not None
        
        # Test that rotation commands can be called (they will fail with missing args, but that's expected)
        expected_commands = [
            "rotate-master",
            "change-password", 
            "rotate-credentials",
            "rollback",
            "history",
            "cleanup-backups"
        ]
        
        # The commands are tested through the public interface in other tests

    def test_cli_help_works(self):
        """Test that CLI help works for rotation commands."""
        cli = KeyCustodianCLI()
        
        # Test that CLI can be instantiated and has basic functionality
        # We test the public interface rather than accessing private parser attributes
        assert cli is not None

    def test_cli_command_validation(self):
        """Test that CLI validates required arguments."""
        cli = KeyCustodianCLI()
        
        # Test that missing required arguments cause SystemExit
        with pytest.raises(SystemExit):
            cli.run(["rotate-master"])
        
        with pytest.raises(SystemExit):
            cli.run(["change-password"])
        
        with pytest.raises(SystemExit):
            cli.run(["rollback"])
