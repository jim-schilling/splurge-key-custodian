#!/usr/bin/env python3
"""Example usage of the Hybrid Key Custodian with separate credential files."""

import os
import tempfile
from splurge_key_custodian import KeyCustodian, Base58


def main():
    """Demonstrate the hybrid key custodian functionality."""
    
    # Create a temporary directory for this example
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"Using temporary directory: {temp_dir}")
        
        # Initialize the hybrid key custodian (password must be at least 32 characters)
        master_password = "MySecureMasterPasswordThatIsAtLeast32CharsLong!!!!"
        custodian = KeyCustodian(
            master_password,
            temp_dir
        )
        
        print("Initialized KeyCustodian")
        print(f"Data directory: {custodian.data_directory}")
        print(f"Master key ID: {custodian.master_key_id}")
        print(f"Credential count: {custodian.credential_count}")
        print()
        
        # Create some credentials
        print("Creating credentials...")
        
        # API credentials
        api_key_id = custodian.create_credential(
            name="Production API",
            credentials={
                "username": "api_user",
                "password": "secure_password_123",
                "api_key": "sk-1234567890abcdef"
            },
            meta_data={
                "service": "production_api",
                "environment": "prod",
                "version": "v1.0"
            }
        )
        print(f"Created API credential with ID: {api_key_id}")
        
        # Database credentials
        db_key_id = custodian.create_credential(
            name="Database Access",
            credentials={
                "host": "db.example.com",
                "port": 5432,
                "database": "myapp_prod",
                "username": "db_user",
                "password": "db_secure_password"
            },
            meta_data={
                "service": "postgresql",
                "environment": "prod",
                "connection_pool": 10
            }
        )
        print(f"Created database credential with ID: {db_key_id}")
        
        # Redis credentials
        redis_key_id = custodian.create_credential(
            name="Redis Cache",
            credentials={
                "host": "redis.example.com",
                "port": 6379,
                "password": "redis_password",
                "database": 0
            },
            meta_data={
                "service": "redis",
                "environment": "prod",
                "max_memory": "2gb"
            }
        )
        print(f"Created Redis credential with ID: {redis_key_id}")
        
        print(f"Total credentials: {custodian.credential_count}")
        print()
        
        # List all credentials
        print("Listing all credentials:")
        all_credentials = custodian.list_credentials()
        for cred in all_credentials:
            print(f"  - {cred['name']} (ID: {cred['key_id']})")
        print()
        
        # Read specific credentials
        print("Reading credentials...")
        
        # Read API credentials
        api_data = custodian.read_credential(api_key_id)
        print(f"API credentials: {api_data['credentials']}")
        print(f"API metadata: {api_data['meta_data']}")
        print()
        
        # Read database credentials
        db_data = custodian.read_credential(db_key_id)
        print(f"Database host: {db_data['credentials']['host']}")
        print(f"Database port: {db_data['credentials']['port']}")
        print()
        
        # Find credentials by name
        print("Finding credentials by name...")
        
        redis_info = custodian.find_credential_by_name("Redis Cache")
        if redis_info:
            print(f"Found Redis credential: {redis_info}")
            redis_data = custodian.read_credential(redis_info['key_id'])
            print(f"Redis host: {redis_data['credentials']['host']}")
        print()
        
        # Update a credential
        print("Updating credential...")
        custodian.update_credential(
            key_id=api_key_id,
            name="Updated Production API",  # Change the name
            credentials={
                "username": "api_user_v2",
                "password": "new_secure_password_456",
                "api_key": "sk-abcdef1234567890"
            },
            meta_data={
                "service": "production_api",
                "environment": "prod",
                "version": "v2.0",
                "updated": True
            }
        )
        print("Updated API credential")
        
        # Read the updated credential
        updated_api_data = custodian.read_credential(api_key_id)
        print(f"Updated API credentials: {updated_api_data['credentials']}")
        print(f"Updated API metadata: {updated_api_data['meta_data']}")
        print()
        
        # Try to create duplicate name (should fail)
        print("Testing name uniqueness...")
        try:
            custodian.create_credential(
                name="Updated Production API",  # This name already exists
                credentials={"test": "data"}
            )
        except Exception as e:
            print(f"Expected error for duplicate name: {e}")
        print()
        
        # Delete a credential
        print("Deleting credential...")
        custodian.delete_credential(redis_key_id)
        print(f"Deleted Redis credential. Total credentials: {custodian.credential_count}")
        
        # Verify it's gone
        try:
            custodian.read_credential(redis_key_id)
        except Exception as e:
            print(f"Expected error for deleted credential: {e}")
        print()
        
        # Create backup
        backup_dir = os.path.join(temp_dir, "backup")
        custodian.backup_credentials(backup_dir)
        print(f"Created backup in: {backup_dir}")
        
        # Show final state
        print("Final credential list:")
        final_credentials = custodian.list_credentials()
        for cred in final_credentials:
            print(f"  - {cred['name']} (ID: {cred['key_id']})")
        
        print("\nHybrid approach demonstration completed successfully!")


def demonstrate_env_password():
    """Demonstrate using environment variable for master password."""
    
    print("\n" + "="*50)
    print("Demonstrating environment variable master password")
    print("="*50)
    
    # Encode password to Base58
    password = "MySecurePasswordWithComplexity123!@#"
    encoded_password = Base58.encode(password.encode('utf-8'))
    
    # Set environment variable
    os.environ["MASTER_PASSWORD"] = encoded_password
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create KeyCustodian from environment variable
        custodian = KeyCustodian.init_from_environment(
            "MASTER_PASSWORD",
            temp_dir
        )
        
        print(f"Created KeyCustodian from environment variable")
        print(f"Data directory: {custodian.data_directory}")
        
        # Create a test credential
        key_id = custodian.create_credential(
            name="Test Credential",
            credentials={"test": "value"},
            meta_data={"source": "env_demo"}
        )
        
        # Read it back
        data = custodian.read_credential(key_id)
        print(f"Test credential data: {data}")
        
        print("Environment variable demonstration completed!")


if __name__ == "__main__":
    main()
    demonstrate_env_password() 