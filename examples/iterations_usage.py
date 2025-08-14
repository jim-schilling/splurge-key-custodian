#!/usr/bin/env python3
"""Example demonstrating the iterations parameter in KeyCustodian."""

import tempfile
import shutil
from splurge_key_custodian.key_custodian import KeyCustodian
from splurge_key_custodian.constants import Constants

def main():
    """Demonstrate iterations parameter usage."""
    print("KeyCustodian Iterations Parameter Example")
    print("=" * 50)
    
    # Create a temporary directory for testing
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Master password (length-only policy: at least 32 characters)
        master_password = "ThisIsAValidTestPasswordAtLeast32Chars!!!!"
        
        print("1. Creating KeyCustodian with default iterations (1,000,000)...")
        custodian_default = KeyCustodian(
            master_password=master_password,
            data_dir=temp_dir
        )
        print(f"   - Iterations: {custodian_default._iterations}")
        
        # Create a credential with default iterations
        key_id = custodian_default.create_credential(
            name="test-credential",
            credentials={"username": "testuser", "password": "testpass"}
        )
        print(f"   - Created credential with key ID: {key_id}")
        
        print("\n2. Creating KeyCustodian with custom iterations (100,000)...")
        # Use a different directory to avoid conflicts
        temp_dir2 = tempfile.mkdtemp()
        try:
            custodian_custom = KeyCustodian(
                master_password=master_password,
                data_dir=temp_dir2,
                iterations=Constants.MIN_ITERATIONS()
            )
            print(f"   - Iterations: {custodian_custom._iterations}")
            
            # Create a credential with custom iterations
            key_id2 = custodian_custom.create_credential(
                name="test-credential-2",
                credentials={"username": "testuser2", "password": "testpass2"}
            )
            print(f"   - Created credential with key ID: {key_id2}")
            
        finally:
            shutil.rmtree(temp_dir2, ignore_errors=True)
        
        print("\n3. Testing iterations validation...")
        try:
            # This should fail - iterations too low
            KeyCustodian(
                master_password=master_password,
                data_dir=temp_dir,
                iterations=Constants.MIN_ITERATIONS() - 1
            )
            print("   - ERROR: Should have failed!")
        except Exception as e:
            print(f"   - Correctly rejected low iterations: {e}")
        
        print("\n4. Reading credential with default iterations...")
        credential = custodian_default.read_credential(key_id)
        print(f"   - Retrieved credential: {credential}")
        
        print("\n5. Testing init_from_environment with iterations...")
        import os
        from splurge_key_custodian.base58 import Base58
        
        # Set up environment variable
        env_var = "TEST_MASTER_PASSWORD"
        encoded_password = Base58.encode(master_password.encode("utf-8"))
        os.environ[env_var] = encoded_password
        
        # Use a fresh directory for environment test
        temp_dir3 = tempfile.mkdtemp()
        try:
            custodian_env = KeyCustodian.init_from_environment(
                env_variable=env_var,
                data_dir=temp_dir3,
                iterations=Constants.MIN_ITERATIONS()
            )
            print(f"   - Created from environment with iterations: {custodian_env._iterations}")
        finally:
            # Clean up environment variable and directory
            if env_var in os.environ:
                del os.environ[env_var]
            shutil.rmtree(temp_dir3, ignore_errors=True)
        
        print(f"\nExample completed successfully!")
        
    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
