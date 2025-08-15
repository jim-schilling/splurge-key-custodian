#!/usr/bin/env python3
"""Command-line interface for Splurge Key Custodian File system."""

import argparse
import json
import os
import sys
from typing import Any, Optional

from splurge_key_custodian.base58 import Base58
from splurge_key_custodian.crypto_utils import CryptoUtils
from splurge_key_custodian.exceptions import ValidationError
from splurge_key_custodian.key_custodian import KeyCustodian
from splurge_key_custodian.constants import Constants

class KeyCustodianCLI:
    """Command-line interface for the Key Custodian system."""

    def __init__(self) -> None:
        """Initialize the CLI."""
        self._parser = self._create_parser()
        self._pretty = False
        self._advanced = False

    def _default_data_dir(self) -> str:
        """Compute a platform-appropriate default data directory."""
        # Environment override for tests/CI or advanced users
        env_dir = os.getenv("SKC_DATA_DIR")
        if env_dir:
            return env_dir

        # Windows: use %APPDATA%\splurge-key-custodian
        appdata = os.getenv("APPDATA")
        if appdata:
            return os.path.join(appdata, "splurge-key-custodian")

        # POSIX: ~/.config/splurge-key-custodian
        home = os.path.expanduser("~")
        if home:
            return os.path.join(home, ".config", "splurge-key-custodian")

        # Fallback to current directory
        return os.path.join(os.getcwd(), ".skc")

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser.

        Returns:
            Configured argument parser
        """
        parser = argparse.ArgumentParser(
            description="Splurge Key Custodian File - Secure credential management",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Save credentials with master password
  python cli.py -p "my-master-password" -d /path/to/data save -n "My Account" \\
    -c '{"username": "user", "password": "pass"}'

  # Save credentials with environment master password
  python cli.py -ep SPLURGE_MASTER_PASSWORD -d /path/to/data save -n "My Account" \\
    -c '{"username": "user", "password": "pass"}'

  # Save credentials with custom iterations
  python cli.py -p "my-master-password" -d /path/to/data -i 100000 save -n "My Account" \\
    -c '{"username": "user", "password": "pass"}'

  # Read credentials
  python cli.py -p "my-master-password" -d /path/to/data read -n "My Account"

  # List all credentials
  python cli.py -p "my-master-password" -d /path/to/data list

  # Validate master password
  python cli.py -p "my-master-password" -d /path/to/data master

  # Rotate master key (change master password)
  python cli.py -p "old-master-password" -d /path/to/data rotate-master \\
    -np "new-master-password"

  # Rotate master key with custom iterations
  python cli.py -p "old-master-password" -d /path/to/data rotate-master \\
    -np "new-master-password" -ni 2000000

  # Rotate master key (same password, new encryption key)
  python cli.py -p "my-master-password" -d /path/to/data rotate-master \\
    -ni 2000000

  # Change master password
  python cli.py -p "old-master-password" -d /path/to/data change-password \\
    -np "new-master-password"

  # Rotate credential keys (keep same master password)
  python cli.py -p "my-master-password" -d /path/to/data rotate-credentials

  # Rotate credentials with custom batch size
  python cli.py -p "my-master-password" -d /path/to/data rotate-credentials -bs 25

  # View rotation history
  python cli.py -p "my-master-password" -d /path/to/data history

  # View last 5 rotation entries
  python cli.py -p "my-master-password" -d /path/to/data history -l 5

  # Rollback a rotation
  python cli.py -p "my-master-password" -d /path/to/data rollback \\
    -r "rotation-uuid-here"

  # Clean up expired backups
  python cli.py -p "my-master-password" -d /path/to/data cleanup-backups

  # Base58 encode/decode/generate (requires -x or--advanced flag)
  python cli.py --advanced base58 -e "Hello, World!"
  python cli.py --advanced base58 -d "JxF12TrwUP45BMd"
  python cli.py --advanced base58 -g 32
            """,
        )

        # Global arguments
        parser.add_argument(
            "-d",
            "--data-dir",
            default=self._default_data_dir(),
            help="Data directory for storing credentials (default: platform config dir)",
        )
        parser.add_argument(
            "-p",
            "--password",
            help="Master password for encryption/decryption",
        )
        parser.add_argument(
            "-ep",
            "--env-password",
            help="Environment variable containing master password",
        )
        parser.add_argument(
            "-i",
            "--iterations",
            type=int,
            help=f"Number of iterations for key derivation (minimum: {Constants.MIN_ITERATIONS():,}, default: {Constants.DEFAULT_ITERATIONS():,})",
        )
        parser.add_argument(
            "--pretty",
            action="store_true",
            help="Pretty-print JSON outputs",
        )
        parser.add_argument(
            "-x",
            "--advanced",
            action="store_true",
            help="Enable advanced/experimental commands (e.g., base58)",
        )

        # Subcommands
        subparsers = parser.add_subparsers(
            dest="command",
            help="Available commands",
        )

        # Save command
        save_parser = subparsers.add_parser(
            "save",
            help="Save credentials",
        )
        save_parser.add_argument(
            "-n",
            "--name",
            required=True,
            help="Name for the credential",
        )
        save_parser.add_argument(
            "-c",
            "--credentials",
            required=True,
            help="JSON string containing credentials",
        )
        save_parser.add_argument(
            "-m",
            "--meta-data",
            help="JSON string containing metadata",
        )

        # Read command
        read_parser = subparsers.add_parser(
            "read",
            help="Read credentials",
        )
        read_parser.add_argument(
            "-n",
            "--name",
            required=True,
            help="Name of the credential to read",
        )

        # List command
        subparsers.add_parser(
            "list",
            help="List all credentials",
        )

        # Master command
        subparsers.add_parser(
            "master",
            help="Validate master password",
        )

        # Data-dir command
        subparsers.add_parser(
            "data-dir",
            help="Print the data directory path that will be used",
        )

        # Rotate master key command
        rotate_master_parser = subparsers.add_parser(
            "rotate-master",
            help="Rotate master encryption key (same password, new salt/key)",
        )
        rotate_master_parser.add_argument(
            "-ni",
            "--new-iterations",
            type=int,
            help="New iterations for key derivation (optional)",
        )
        rotate_master_parser.add_argument(
            "--no-backup",
            action="store_true",
            help="Skip creating backup before rotation",
        )
        rotate_master_parser.add_argument(
            "-br",
            "--backup-retention",
            type=int,
            help="Days to retain backup (default: 30)",
        )

        # Change master password command
        change_password_parser = subparsers.add_parser(
            "change-password",
            help="Change master password and rotate master key",
        )
        change_password_parser.add_argument(
            "-np",
            "--new-password",
            required=True,
            help="New master password",
        )
        change_password_parser.add_argument(
            "-ni",
            "--new-iterations",
            type=int,
            help="New iterations for key derivation (optional)",
        )
        change_password_parser.add_argument(
            "--no-backup",
            action="store_true",
            help="Skip creating backup before rotation",
        )
        change_password_parser.add_argument(
            "-br",
            "--backup-retention",
            type=int,
            help="Days to retain backup (default: 30)",
        )

        # Rotate credentials command
        rotate_credentials_parser = subparsers.add_parser(
            "rotate-credentials",
            help="Rotate encryption keys for all credentials (new individual keys)",
        )
        rotate_credentials_parser.add_argument(
            "-i",
            "--iterations",
            type=int,
            help="Iterations for key derivation (optional)",
        )
        rotate_credentials_parser.add_argument(
            "--no-backup",
            action="store_true",
            help="Skip creating backup before rotation",
        )
        rotate_credentials_parser.add_argument(
            "-br",
            "--backup-retention",
            type=int,
            help="Days to retain backup (default: 30)",
        )
        rotate_credentials_parser.add_argument(
            "-bs",
            "--batch-size",
            type=int,
            help="Number of credentials to rotate in each batch (optional)",
        )

        # Rollback rotation command
        rollback_parser = subparsers.add_parser(
            "rollback",
            help="Rollback a key rotation operation",
        )
        rollback_parser.add_argument(
            "-r",
            "--rotation-id",
            required=True,
            help="Rotation ID to rollback",
        )

        # Rotation history command
        history_parser = subparsers.add_parser(
            "history",
            help="View rotation history",
        )
        history_parser.add_argument(
            "-l",
            "--limit",
            type=int,
            help="Maximum number of history entries to show (optional)",
        )

        # Cleanup backups command
        subparsers.add_parser(
            "cleanup-backups",
            help="Clean up expired rotation backups",
        )

        # Base58 command
        base58_parser = subparsers.add_parser(
            "base58",
            help="Base58 encode/decode operations",
        )
        base58_parser.add_argument(
            "-e",
            "--encode",
            help="Text to encode to Base58",
        )
        base58_parser.add_argument(
            "-d",
            "--decode",
            help="Base58 string to decode",
        )
        base58_parser.add_argument(
            "-g",
            "--generate",
            type=int,
            nargs="?",
            const=Constants.MIN_PASSWORD_LENGTH(),
            help=f"Generate a cryptographically random Base58-like string (default: {Constants.MIN_PASSWORD_LENGTH()}, max: {Constants.MAX_PASSWORD_LENGTH()})",
        )

        return parser

    def _validate_required_args(self, args: argparse.Namespace) -> None:
        """Validate that required arguments are provided."""
        self._validate_required_args_with_dependencies(
            command=args.command,
            password=args.password,
            env_password=args.env_password,
            data_dir=args.data_dir
        )

    def _validate_required_args_with_dependencies(
        self,
        *,
        command: str,
        password: str | None,
        env_password: str | None,
        data_dir: str | None
    ) -> None:
        """Validate that required arguments are provided with explicit dependencies.

        Args:
            command: Command being executed
            password: Password argument
            env_password: Environment password argument
            data_dir: Data directory argument

        Raises:
            ValidationError: If required arguments are missing or invalid
        """
        if command == "base58":
            if not self._advanced:
                raise ValidationError("Advanced features are disabled. Re-run with -x or --advanced to use base58.")
            return

        if command == "data-dir":
            return  # Base58 doesn't need password or data dir

        # Validate data directory for commands that require it
        if not data_dir:
            raise ValidationError("Data directory (-d/--data-dir) is required")

        if not password and not env_password:
            raise ValidationError(
                "Either password (-p/--password) or environment password "
                "(-ep/--env-password) is required"
            )

        if password and env_password:
            raise ValidationError(
                "Cannot specify both password and environment password"
            )

    def _get_custodian(self, args: argparse.Namespace) -> KeyCustodian:
        """Get KeyCustodian instance based on arguments."""
        return self._get_custodian_with_dependencies(
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _get_custodian_with_dependencies(
        self,
        *,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> KeyCustodian:
        """Get KeyCustodian instance based on arguments with explicit dependencies.

        Args:
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (optional)

        Returns:
            KeyCustodian instance

        Raises:
            ValidationError: If arguments are invalid
        """
        if env_password:
            return KeyCustodian.init_from_environment(
                env_password,
                data_dir,
                iterations=iterations
            )

        return KeyCustodian(
            password,
            data_dir,
            iterations=iterations
        )

    def _parse_json(self, json_str: str) -> dict[str, Any]:
        """Parse JSON string safely."""
        return self._parse_json_with_dependencies(json_str=json_str)

    def _parse_json_with_dependencies(
        self,
        *,
        json_str: str
    ) -> dict[str, Any]:
        """Parse JSON string or file/stdin reference safely.

        Supports:
        - Literal JSON string
        - "@path/to/file.json" to load JSON from a file
        - "@-" to read JSON from stdin

        Raises ValidationError on any parsing error.
        """
        try:
            if isinstance(json_str, str) and json_str.startswith("@"):
                ref = json_str[1:]
                if ref == "-":
                    content = sys.stdin.read()
                    return json.loads(content)
                else:
                    with open(ref, "r", encoding="utf-8") as f:
                        return json.loads(f.read())

            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {e}")
        except FileNotFoundError as e:
            raise ValidationError(f"JSON file not found: {e}")
        except Exception as e:
            raise ValidationError(f"Failed to read JSON: {e}")

    def _print_json(self, payload: dict[str, Any]) -> None:
        """Print a JSON payload to stdout."""
        print(json.dumps(payload, indent=2 if self._pretty else None))

    def _print_error(self, *, message: str, code: str = "error", extra: dict[str, Any] | None = None) -> None:
        """Print a JSON error to stderr and exit non-zero."""
        error_obj = {
            "success": False,
            "error_code": code,
            "message": message,
        }
        if extra:
            error_obj["data"] = extra
        print(json.dumps(error_obj, indent=2), file=sys.stderr)
        sys.exit(1)

    def _handle_save(self, args: argparse.Namespace) -> None:
        """Handle save command."""
        self._handle_save_with_dependencies(
            name=args.name,
            credentials=args.credentials,
            meta_data=args.meta_data,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_save_with_dependencies(
        self,
        *,
        name: str,
        credentials: str,
        meta_data: str | None,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle save command with explicit dependencies.

        Args:
            name: Credential name
            credentials: JSON string containing credentials
            meta_data: JSON string containing metadata (optional)
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (optional)
        """
        try:
            # Sanitize inputs
            name = self._sanitize_input(name)
            credentials = self._sanitize_input(credentials)
            if meta_data:
                meta_data = self._sanitize_input(meta_data)
            
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )
            parsed_credentials = self._parse_json_with_dependencies(json_str=credentials)
            parsed_meta_data = self._parse_json_with_dependencies(json_str=meta_data) if meta_data else {}

            key_id = custodian.create_credential(
                name=name,
                credentials=parsed_credentials,
                meta_data=parsed_meta_data,
            )

            self._print_json({
                "success": True,
                "command": "save",
                "key_id": key_id,
                "name": name,
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_read(self, args: argparse.Namespace) -> None:
        """Handle read command."""
        self._handle_read_with_dependencies(
            name=args.name,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_read_with_dependencies(
        self,
        *,
        name: str,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle read command with explicit dependencies.

        Args:
            name: Credential name to read
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (optional)
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )
            credential_info = custodian.find_credential_by_name(name)

            if credential_info is None:
                raise ValidationError(f"Credential '{name}' not found")

            credential_data = custodian.read_credential(credential_info["key_id"])

            result = {
                "success": True,
                "command": "read",
                "key_id": credential_info["key_id"],
                "name": name,
                "credentials": credential_data["credentials"],
                "meta_data": credential_data["meta_data"],
            }
            self._print_json(result)

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_list(self, args: argparse.Namespace) -> None:
        """Handle list command."""
        self._handle_list_with_dependencies(
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_list_with_dependencies(
        self,
        *,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle list command with explicit dependencies.

        Args:
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (optional)
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )
            credentials = custodian.list_credentials()
            names = [cred["name"] for cred in credentials]

            self._print_json({
                "success": True,
                "command": "list",
                "count": len(names),
                "names": names,
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_master(self, args: argparse.Namespace) -> None:
        """Handle master command."""
        self._handle_master_with_dependencies(
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_master_with_dependencies(
        self,
        *,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle master command with explicit dependencies.

        Args:
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Number of iterations for key derivation (optional)
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )
            master_key_id = custodian.master_key_id

            self._print_json({
                "success": True,
                "command": "master",
                "master_key_id": master_key_id,
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_base58(self, args: argparse.Namespace) -> None:
        """Handle base58 command."""
        self._handle_base58_with_dependencies(
            encode=args.encode,
            decode=args.decode,
            generate=args.generate
        )

    def _handle_base58_with_dependencies(
        self,
        *,
        encode: str | None,
        decode: str | None,
        generate: int | None
    ) -> None:
        """Handle base58 command with explicit dependencies.

        Args:
            encode: String to encode to Base58
            decode: Base58 string to decode
            generate: Length of the random Base58-like string to generate
        """
        try:
            # Count how many options are specified
            options_count = sum([
                encode is not None,
                decode is not None,
                generate is not None
            ])
            
            if options_count == 0:
                raise ValidationError("Must specify either encode (-e), decode (-d), or generate (-g)")
            
            if options_count > 1:
                raise ValidationError("Cannot specify multiple options (encode, decode, generate)")
            
            if encode:
                # Encode plaintext to Base58
                encoded = Base58.encode(encode.encode("utf-8"))
                print(encoded)
            elif decode:
                # Decode the Base58 to plaintext
                try:
                    decoded_bytes = Base58.decode(decode)
                    # Try to decode as UTF-8, but if it fails, output as raw bytes
                    try:
                        decoded_text = decoded_bytes.decode("utf-8")
                        print(decoded_text)
                    except UnicodeDecodeError:
                        # If it's not valid UTF-8, output the raw bytes directly to stdout
                        sys.stdout.buffer.write(decoded_bytes)
                        sys.stdout.buffer.flush()

                except Exception as e:
                    raise ValidationError(f"Invalid Base58 string: {e}") from e
            else:
                # Generate a cryptographically random Base58-like string
                if generate < Constants.MIN_PASSWORD_LENGTH():
                    generate = Constants.MIN_PASSWORD_LENGTH()
                elif generate > Constants.MAX_PASSWORD_LENGTH():
                    generate = Constants.MAX_PASSWORD_LENGTH()
                random_string = CryptoUtils.generate_base58_like_random_string(length=generate)
                print(random_string)

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_rotate_master(self, args: argparse.Namespace) -> None:
        """Handle rotate-master command."""
        self._handle_rotate_master_with_dependencies(
            new_iterations=args.new_iterations,
            create_backup=not args.no_backup,
            backup_retention_days=args.backup_retention,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_rotate_master_with_dependencies(
        self,
        *,
        new_iterations: int | None,
        create_backup: bool,
        backup_retention_days: int | None,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle rotate-master command with explicit dependencies.

        Args:
            new_iterations: New iterations for key derivation
            create_backup: Whether to create backup
            backup_retention_days: Days to retain backup
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Current iterations for key derivation
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            rotation_id = custodian.rotate_master_key(
                new_iterations=new_iterations,
                create_backup=create_backup,
                backup_retention_days=backup_retention_days
            )

            self._print_json({
                "success": True,
                "command": "rotate-master",
                "rotation_id": rotation_id,
                "message": "Master key rotation completed successfully",
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_change_password(self, args: argparse.Namespace) -> None:
        """Handle change-password command."""
        self._handle_change_password_with_dependencies(
            new_password=args.new_password,
            new_iterations=args.new_iterations,
            create_backup=not args.no_backup,
            backup_retention_days=args.backup_retention,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_change_password_with_dependencies(
        self,
        *,
        new_password: str,
        new_iterations: int | None,
        create_backup: bool,
        backup_retention_days: int | None,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle change-password command with explicit dependencies.

        Args:
            new_password: New master password
            new_iterations: New iterations for key derivation
            create_backup: Whether to create backup
            backup_retention_days: Days to retain backup
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Current iterations for key derivation
        """
        try:
            # Sanitize inputs
            new_password = self._sanitize_input(new_password)
            
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            rotation_id = custodian.change_master_password(
                new_master_password=new_password,
                new_iterations=new_iterations,
                create_backup=create_backup,
                backup_retention_days=backup_retention_days
            )

            self._print_json({
                "success": True,
                "command": "change-password",
                "rotation_id": rotation_id,
                "message": "Master password changed and key rotated successfully",
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_rotate_credentials(self, args: argparse.Namespace) -> None:
        """Handle rotate-credentials command."""
        self._handle_rotate_credentials_with_dependencies(
            iterations=args.iterations,
            create_backup=not args.no_backup,
            backup_retention_days=args.backup_retention,
            batch_size=args.batch_size,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir
        )

    def _handle_rotate_credentials_with_dependencies(
        self,
        *,
        iterations: int | None,
        create_backup: bool,
        backup_retention_days: int | None,
        batch_size: int | None,
        env_password: str | None,
        password: str | None,
        data_dir: str
    ) -> None:
        """Handle rotate-credentials command with explicit dependencies.

        Args:
            iterations: Iterations for key derivation
            create_backup: Whether to create backup
            backup_retention_days: Days to retain backup
            batch_size: Number of credentials to rotate in each batch
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            rotation_id = custodian.rotate_all_credentials(
                iterations=iterations,
                create_backup=create_backup,
                backup_retention_days=backup_retention_days,
                batch_size=batch_size
            )

            self._print_json({
                "success": True,
                "command": "rotate-credentials",
                "rotation_id": rotation_id,
                "message": "Credential rotation completed successfully",
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_rollback(self, args: argparse.Namespace) -> None:
        """Handle rollback command."""
        self._handle_rollback_with_dependencies(
            rotation_id=args.rotation_id,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_rollback_with_dependencies(
        self,
        *,
        rotation_id: str,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle rollback command with explicit dependencies.

        Args:
            rotation_id: Rotation ID to rollback
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Iterations for key derivation
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            custodian.rollback_rotation(rotation_id=rotation_id)

            self._print_json({
                "success": True,
                "command": "rollback",
                "rotation_id": rotation_id,
                "message": "Rotation rollback completed successfully",
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_history(self, args: argparse.Namespace) -> None:
        """Handle history command."""
        self._handle_history_with_dependencies(
            limit=args.limit,
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_history_with_dependencies(
        self,
        *,
        limit: int | None,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle history command with explicit dependencies.

        Args:
            limit: Maximum number of history entries to show
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Iterations for key derivation
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            history = custodian.get_rotation_history(limit=limit)

            # Convert history objects to dictionaries for JSON serialization
            history_data = []
            for entry in history:
                history_data.append({
                    "rotation_id": entry.rotation_id,
                    "rotation_type": entry.rotation_type,
                    "target_key_id": entry.target_key_id,
                    "old_master_key_id": entry.old_master_key_id,
                    "new_master_key_id": entry.new_master_key_id,
                    "affected_credentials_count": len(entry.affected_credentials),
                    "created_at": entry.created_at.isoformat(),
                    "metadata": entry.metadata,
                })

            self._print_json({
                "success": True,
                "command": "history",
                "count": len(history_data),
                "history": history_data,
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _handle_cleanup_backups(self, args: argparse.Namespace) -> None:
        """Handle cleanup-backups command."""
        self._handle_cleanup_backups_with_dependencies(
            env_password=args.env_password,
            password=args.password,
            data_dir=args.data_dir,
            iterations=args.iterations
        )

    def _handle_cleanup_backups_with_dependencies(
        self,
        *,
        env_password: str | None,
        password: str | None,
        data_dir: str,
        iterations: int | None = None
    ) -> None:
        """Handle cleanup-backups command with explicit dependencies.

        Args:
            env_password: Environment variable name containing master password
            password: Master password
            data_dir: Directory to store key files
            iterations: Iterations for key derivation
        """
        try:
            custodian = self._get_custodian_with_dependencies(
                env_password=env_password,
                password=password,
                data_dir=data_dir,
                iterations=iterations
            )

            cleaned_count = custodian.cleanup_expired_backups()

            self._print_json({
                "success": True,
                "command": "cleanup-backups",
                "cleaned_count": cleaned_count,
                "message": f"Cleaned up {cleaned_count} expired backup(s)",
            })

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")

    def _sanitize_input(self, value: str) -> str:
        """Sanitize input to prevent injection attacks.
        
        Args:
            value: Input value to sanitize
            
        Returns:
            Sanitized value
            
        Raises:
            ValidationError: If input contains dangerous characters
        """
        if not isinstance(value, str):
            raise ValidationError("Input must be a string")
        
        # Check for potentially dangerous characters
        # Note: $, (, ), & are allowed for password complexity and legitimate use cases
        dangerous_chars = [';', '|', '`', '<', '>', '\\']
        for char in dangerous_chars:
            if char in value:
                raise ValidationError(f"Input contains potentially dangerous character: {char}")
        
        # Check for null bytes first
        if '\x00' in value:
            raise ValidationError("Input contains null bytes")
        
        # Check for control characters
        for char in value:
            if ord(char) < 32 and char != '\t' and char != '\n' and char != '\r':
                raise ValidationError(f"Input contains control character: {repr(char)}")
        
        # Limit password length
        if len(value) > Constants.MAX_PASSWORD_LENGTH():
            raise ValidationError(f"Password too long (max {Constants.MAX_PASSWORD_LENGTH()} characters)")
        
        # Trim whitespace
        return value.strip()

    def run(self, args: Optional[list[str]] = None) -> None:
        """Run the CLI with given arguments."""
        try:
            parsed_args = self._parser.parse_args(args)
            self._pretty = bool(getattr(parsed_args, "pretty", False))
            self._advanced = bool(getattr(parsed_args, "advanced", False))

            if not parsed_args.command:
                self._print_error(message="No command specified", code="missing_command")

            # Validate required arguments
            self._validate_required_args(parsed_args)

            # Handle commands
            if parsed_args.command == "save":
                self._handle_save(parsed_args)
            elif parsed_args.command == "read":
                self._handle_read(parsed_args)
            elif parsed_args.command == "list":
                self._handle_list(parsed_args)
            elif parsed_args.command == "master":
                self._handle_master(parsed_args)
            elif parsed_args.command == "data-dir":
                self._print_json({
                    "success": True,
                    "command": "data-dir",
                    "data_dir": parsed_args.data_dir,
                })
            elif parsed_args.command == "rotate-master":
                self._handle_rotate_master(parsed_args)
            elif parsed_args.command == "change-password":
                self._handle_change_password(parsed_args)
            elif parsed_args.command == "rotate-credentials":
                self._handle_rotate_credentials(parsed_args)
            elif parsed_args.command == "rollback":
                self._handle_rollback(parsed_args)
            elif parsed_args.command == "history":
                self._handle_history(parsed_args)
            elif parsed_args.command == "cleanup-backups":
                self._handle_cleanup_backups(parsed_args)
            elif parsed_args.command == "base58":
                self._handle_base58(parsed_args)
            else:
                self._print_error(message=f"Unknown command: {parsed_args.command}", code="unknown_command")

        except ValidationError as e:
            self._print_error(message=str(e), code="validation_error")
        except KeyboardInterrupt:
            self._print_error(message="Operation cancelled by user", code="cancelled")
        except Exception as e:
            self._print_error(message=str(e), code="unexpected_error")


def main() -> None:
    """Main entry point for the CLI."""
    cli = KeyCustodianCLI()
    cli.run()


if __name__ == "__main__":
    main()
