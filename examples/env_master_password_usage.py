#!/usr/bin/env python3
"""Example demonstrating KeyCustodian with Base58-encoded master password from environment variable."""

import json
import os
import tempfile
from datetime import datetime, timezone

from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.base58 import Base58


def encode_password_for_env(password: str) -> str:
    """Encode a password to Base58 for use as an environment variable.
    
    Args:
        password: Plain text password to encode
        
    Returns:
        Base58-encoded password string
    """
    return Base58.encode(password.encode('utf-8'))


def main():
    """Demonstrate KeyCustodian with environment variable master password."""
    # Create a temporary directory for this example
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Using temporary directory: {temp_dir}")

        # Example 1: Using default environment variable name (MASTER_PASSWORD)
        print("\n" + "="*60)
        print("EXAMPLE 1: Using default MASTER_PASSWORD environment variable")
        print("="*60)
        
        # Encode a password to Base58
        master_password = "MySuperSecureMasterPasswordWithComplexity123!@#"
        encoded_password = encode_password_for_env(master_password)
        print(f"Original password: {master_password}")
        print(f"Base58 encoded: {encoded_password}")
        
        # Set the environment variable
        os.environ["MASTER_PASSWORD"] = encoded_password
        
        # Create KeyCustodian using the environment variable
        custodian = KeyCustodian.init_from_environment(
            "MASTER_PASSWORD",
            temp_dir
        )
        
        print(f"Successfully created KeyCustodian from environment variable")
        print(f"Credential count: {custodian.credential_count}")
        print(f"Master key ID: {custodian.master_key_id}")
        
        # Test creating and reading a credential
        credential_data = {
            "username": "env_user",
            "password": "env_password",
            "api_key": "sk-env-1234567890abcdef",
        }
        
        key_id = custodian.create_credential(
            name="Environment Variable Test Credential",
            credentials=credential_data,
            meta_data={"source": "env_example", "method": "from_env_master_password"},
        )
        
        print(f"Created credential with ID: {key_id}")
        
        # Read the credential back
        retrieved_data = custodian.read_credential(key_id)
        print(f"Retrieved credential data: {retrieved_data['credentials']}")
        
        # Example 2: Using custom environment variable name
        print("\n" + "="*60)
        print("EXAMPLE 2: Using custom environment variable name")
        print("="*60)
        
        # Create a new temporary directory for the second example
        with tempfile.TemporaryDirectory() as temp_dir_2:
            # Encode a different password
            custom_password = "CustomEnvPasswordWithComplexity456!@#"
            custom_encoded = encode_password_for_env(custom_password)
            print(f"Custom password: {custom_password}")
            print(f"Custom Base58 encoded: {custom_encoded}")
            
            # Set custom environment variable
            os.environ["CUSTOM_MASTER_PASSWORD"] = custom_encoded
            
            # Create KeyCustodian with custom environment variable name
            custodian_2 = KeyCustodian.init_from_environment(
                "CUSTOM_MASTER_PASSWORD",
                temp_dir_2
            )
            
            print(f"Successfully created KeyCustodian with custom env var name")
            print(f"Credential count: {custodian_2.credential_count}")
            
            # Test functionality
            key_id_2 = custodian_2.create_credential(
                name="Custom Env Var Test",
                credentials={"test": "data", "custom": True},
            )
            
            retrieved_2 = custodian_2.read_credential(key_id_2)
            print(f"Custom credential data: {retrieved_2['credentials']}")
        
        # Example 3: Error handling demonstration
        print("\n" + "="*60)
        print("EXAMPLE 3: Error handling demonstration")
        print("="*60)
        
        # Test with missing environment variable
        print("Testing with missing environment variable...")
        try:
            # Temporarily remove the environment variable
            if "MASTER_PASSWORD" in os.environ:
                del os.environ["MASTER_PASSWORD"]
            
            KeyCustodian.init_from_environment(
                "MASTER_PASSWORD",
                temp_dir
            )
            print("ERROR: Should have raised an exception!")
        except Exception as e:
            print(f"Expected error: {e}")
        
        # Test with invalid Base58 data
        print("\nTesting with invalid Base58 data...")
        try:
            os.environ["MASTER_PASSWORD"] = "invalid-base58!@#"
            KeyCustodian.init_from_environment(
                "MASTER_PASSWORD",
                temp_dir
            )
            print("ERROR: Should have raised an exception!")
        except Exception as e:
            print(f"Expected error: {e}")
        
        # Restore the valid environment variable
        os.environ["MASTER_PASSWORD"] = encoded_password
        
        # Example 4: Practical usage pattern
        print("\n" + "="*60)
        print("EXAMPLE 4: Practical usage pattern")
        print("="*60)
        
        print("In a real application, you would:")
        print("1. Set the environment variable in your shell or deployment:")
        print("   export MASTER_PASSWORD='your-base58-encoded-password'")
        print("2. Use the KeyCustodian in your code:")
        print("   custodian = KeyCustodian.from_env_master_password('/path/to/data')")
        print("3. The password is automatically decoded and used for encryption")
        
        # Show how to encode a password for environment variable use
        print(f"\nTo encode a password for environment variable use:")
        print(f"from splurge_key_custodian.base58 import Base58")
        print(f"encoded = Base58.encode('your-password'.encode('utf-8'))")
        print(f"print(f'export MASTER_PASSWORD=\"' + encoded + '\"')")
        
        # Demonstrate this
        demo_password = "DemoPasswordForEnvWithComplexity123!@#"
        demo_encoded = encode_password_for_env(demo_password)
        print(f"\nDemo: password '{demo_password}' -> '{demo_encoded}'")
        print(f"Command: export MASTER_PASSWORD='{demo_encoded}'")


if __name__ == "__main__":
    main() 