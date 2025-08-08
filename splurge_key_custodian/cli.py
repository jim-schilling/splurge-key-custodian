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


class KeyCustodianCLI:
    """Command-line interface for the Key Custodian system."""

    def __init__(self) -> None:
        """Initialize the CLI."""
        self._parser = self._create_parser()

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
  python cli.py -p "my-master-password" -d /path/to/data -i 500000 save -n "My Account" \\
    -c '{"username": "user", "password": "pass"}'

  # Read credentials
  python cli.py -p "my-master-password" -d /path/to/data read -n "My Account"

  # List all credentials
  python cli.py -p "my-master-password" -d /path/to/data list

  # Validate master password
  python cli.py -p "my-master-password" -d /path/to/data master

  # Base58 encode/decode
  python cli.py base58 -e "Hello, World!"
  python cli.py base58 -d "JxF12TrwUP45BMd"
            """,
        )

        # Global arguments
        parser.add_argument(
            "-d",
            "--data-dir",
            help="Data directory for storing credentials",
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
            help="Number of iterations for key derivation (minimum: 500,000, default: 1,000,000)",
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
            action="store_true",
            help="Generate a 64-character cryptographically random Base58-like string and return its Base58 encoded value",
        )

        return parser

    def _validate_required_args(self, args: argparse.Namespace) -> None:
        """Validate that required arguments are provided."""
        self._validate_required_args_with_dependencies(
            command=args.command,
            data_dir=args.data_dir,
            password=args.password,
            env_password=args.env_password
        )

    def _validate_required_args_with_dependencies(
        self,
        *,
        command: str,
        data_dir: Optional[str],
        password: Optional[str],
        env_password: Optional[str]
    ) -> None:
        """Validate that required arguments are provided with explicit dependencies.

        Args:
            command: Command being executed
            data_dir: Data directory argument
            password: Password argument
            env_password: Environment password argument

        Raises:
            ValidationError: If required arguments are missing or invalid
        """
        if command == "base58":
            return  # Base58 doesn't need password or data dir

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
        env_password: Optional[str],
        password: Optional[str],
        data_dir: str,
        iterations: Optional[int] = None
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
        """Parse JSON string safely with explicit dependencies.

        Args:
            json_str: JSON string to parse

        Returns:
            Parsed JSON as dictionary

        Raises:
            ValidationError: If JSON is invalid
        """
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {e}")

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
        meta_data: Optional[str],
        env_password: Optional[str],
        password: Optional[str],
        data_dir: str,
        iterations: Optional[int] = None
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

            print(key_id)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

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
        env_password: Optional[str],
        password: Optional[str],
        data_dir: str,
        iterations: Optional[int] = None
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
                "key_id": credential_info["key_id"],
                "name": name,
                "credentials": credential_data["credentials"],
                "meta_data": credential_data["meta_data"],
            }
            print(json.dumps(result, indent=2))

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

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
        env_password: Optional[str],
        password: Optional[str],
        data_dir: str,
        iterations: Optional[int] = None
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

            for name in names:
                print(name)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

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
        env_password: Optional[str],
        password: Optional[str],
        data_dir: str,
        iterations: Optional[int] = None
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
            test_credentials = custodian.list_credentials()

            print(f"{master_key_id}")

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

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
        encode: Optional[str],
        decode: Optional[str],
        generate: bool
    ) -> None:
        """Handle base58 command with explicit dependencies.

        Args:
            encode: String to encode to Base58
            decode: Base58 string to decode
            generate: Whether to generate a random 64-byte key
        """
        try:
            # Count how many options are specified
            options_count = sum([
                encode is not None,
                decode is not None,
                generate
            ])
            
            if options_count == 0:
                raise ValidationError("Must specify either encode (-e), decode (-d), or generate (-g)")
            
            if options_count > 1:
                raise ValidationError("Cannot specify multiple options (encode, decode, generate)")

            if generate:
                # Generate a 64-byte cryptographically random key
                random_string = CryptoUtils.generate_base58_like_random_string()
                encoded = Base58.encode(random_string.encode("utf-8"))
                print(encoded)
            elif encode:
                # Encode plaintext to Base58
                encoded = Base58.encode(encode.encode("utf-8"))
                print(encoded)
            else:
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

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

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
        
        # Limit input length
        if len(value) > 1000:
            raise ValidationError("Input too long (max 1000 characters)")
        
        # Trim whitespace
        return value.strip()

    def run(self, args: Optional[list[str]] = None) -> None:
        """Run the CLI with given arguments."""
        try:
            parsed_args = self._parser.parse_args(args)

            if not parsed_args.command:
                print("Error: No command specified", file=sys.stderr)
                self._parser.print_help()
                sys.exit(1)

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
            elif parsed_args.command == "base58":
                self._handle_base58(parsed_args)
            else:
                print(f"Unknown command: {parsed_args.command}", file=sys.stderr)
                sys.exit(1)

        except ValidationError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    cli = KeyCustodianCLI()
    cli.run()


if __name__ == "__main__":
    main()
