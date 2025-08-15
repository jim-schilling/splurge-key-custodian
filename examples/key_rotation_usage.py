#!/usr/bin/env python3
"""Example demonstrating key rotation functionality."""

import json
import os
import tempfile
from pathlib import Path

from splurge_key_custodian.key_custodian import KeyCustodian


def main() -> None:
    """Demonstrate key rotation functionality."""
    
    # Create a temporary directory for this example
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir) / "key-custodian-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        
        print("🔐 Key Rotation Example")
        print("=" * 50)
        
        # Initial master password
        master_password = "MySecureMasterPassword123!@#ExtraLongEnough"
        
        # Create KeyCustodian instance
        print(f"📁 Using data directory: {data_dir}")
        custodian = KeyCustodian(master_password, str(data_dir))
        
        # Create some test credentials
        print("\n📝 Creating test credentials...")
        
        # Credential 1
        key_id1 = custodian.create_credential(
            name="GitHub Account",
            credentials={
                "username": "johndoe",
                "password": "secure-github-password",
                "two_factor_enabled": True
            },
            meta_data={
                "service": "github",
                "created_by": "example_script"
            }
        )
        print(f"  ✅ Created credential: GitHub Account (ID: {key_id1})")
        
        # Credential 2
        key_id2 = custodian.create_credential(
            name="AWS Access",
            credentials={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-west-2"
            },
            meta_data={
                "service": "aws",
                "environment": "production",
                "created_by": "example_script"
            }
        )
        print(f"  ✅ Created credential: AWS Access (ID: {key_id2})")
        
        # Credential 3
        key_id3 = custodian.create_credential(
            name="Database Connection",
            credentials={
                "host": "db.example.com",
                "port": 5432,
                "database": "myapp",
                "username": "dbuser",
                "password": "db-password-123"
            },
            meta_data={
                "service": "postgresql",
                "environment": "staging",
                "created_by": "example_script"
            }
        )
        print(f"  ✅ Created credential: Database Connection (ID: {key_id3})")
        
        # List all credentials
        print(f"\n📋 Current credentials ({custodian.credential_count} total):")
        credentials = custodian.list_credentials()
        for cred in credentials:
            print(f"  - {cred['name']} (ID: {cred['key_id']})")
        
        # Demonstrate bulk credential rotation
        print("\n🔄 Performing bulk credential rotation...")
        rotation_id = custodian.rotate_all_credentials(
            create_backup=True,
            backup_retention_days=7,
            batch_size=2
        )
        print(f"  ✅ Bulk rotation completed (ID: {rotation_id})")
        
        # Demonstrate master key rotation (same password, new encryption key)
        print("🔄 Performing master key rotation (same password, new key)...")
        
        rotation_id2 = custodian.rotate_master_key(
            new_iterations=1500000,  # Increase iterations for better security
            create_backup=True,
            backup_retention_days=7
        )
        print(f"  ✅ Master key rotation completed (ID: {rotation_id2})")
        
        # Verify credentials are still accessible with same master password
        print("\n🔍 Verifying credentials are accessible with same master password...")
        
        # Create new custodian instance with same password but new iterations
        print(f"  📝 Creating new KeyCustodian with same master password...")
        new_custodian = KeyCustodian(master_password, str(data_dir), iterations=1500000)
        print(f"  ✅ New KeyCustodian created successfully")
        
        # Read all credentials to verify they work
        print(f"  📋 Reading credentials with same master password...")
        for cred in new_custodian.list_credentials():
            try:
                credential_data = new_custodian.read_credential(cred['key_id'])
                print(f"  ✅ Successfully read: {cred['name']}")
                print(f"     Username: {credential_data['credentials'].get('username', 'N/A')}")
            except Exception as e:
                print(f"  ❌ Failed to read: {cred['name']} - {e}")
                print(f"     Error type: {type(e).__name__}")
        
        # View rotation history
        print("\n📜 Rotation history:")
        history = new_custodian.get_rotation_history(limit=5)
        for entry in history:
            print(f"  - {entry.rotation_type} rotation ({entry.created_at.strftime('%Y-%m-%d %H:%M:%S')})")
            print(f"    ID: {entry.rotation_id}")
            print(f"    Affected credentials: {len(entry.affected_credentials)}")
            if entry.metadata:
                print(f"    Metadata: {json.dumps(entry.metadata, indent=6)}")
            print()
        
        # Demonstrate rollback (commented out for safety)
        print("\n⚠️  Rollback demonstration (commented out for safety):")
        print("  # To rollback the master key rotation:")
        print(f"  # new_custodian.rollback_rotation(rotation_id='{rotation_id2}')")
        print("  # This would restore the previous master key and re-encrypt all credentials")
        
        # Clean up expired backups
        print("\n🧹 Cleaning up expired backups...")
        cleaned_count = new_custodian.cleanup_expired_backups()
        print(f"  ✅ Cleaned up {cleaned_count} expired backup(s)")
        
        print("\n✅ Key rotation example completed successfully!")
        print("\n💡 Key takeaways:")
        print("  - Bulk rotation re-encrypts all credentials with new individual keys")
        print("  - Master key rotation changes the encryption key but keeps the same password")
        print("  - All operations create backups for potential rollback")
        print("  - Rotation history is maintained for audit purposes")
        print("  - Expired backups are automatically cleaned up")
        print("  - After master key rotation, use the SAME master password to access credentials")
        print("  - Note: Master password change is available but requires careful handling of iterations")


if __name__ == "__main__":
    main()
