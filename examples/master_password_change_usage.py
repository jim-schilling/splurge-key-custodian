#!/usr/bin/env python3
"""Example demonstrating master password change functionality."""

import json
import os
import tempfile
from pathlib import Path

from splurge_key_custodian.key_custodian import KeyCustodian


def main():
    """Demonstrate master password change functionality."""
    print("🔐 Master Password Change Example")
    print("=" * 50)
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir) / "key-custodian-data"
        
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
                "created_by": "admin"
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
                "environment": "production"
            }
        )
        print(f"  ✅ Created credential: AWS Access (ID: {key_id2})")
        
        # List current credentials
        print(f"\n📋 Current credentials ({len(custodian.list_credentials())} total):")
        for cred in custodian.list_credentials():
            print(f"  - {cred['name']} (ID: {cred['key_id']})")
        
        # Demonstrate master password change
        print("\n🔄 Performing master password change...")
        new_master_password = "NewSecureMasterPassword456!@#ExtraLongEnough"
        
        rotation_id = custodian.change_master_password(
            new_master_password=new_master_password,
            new_iterations=1500000,  # Increase iterations for better security
            create_backup=True,
            backup_retention_days=7
        )
        print(f"  ✅ Master password change completed (ID: {rotation_id})")
        
        # Verify credentials are accessible with new master password
        print("\n🔍 Verifying credentials are accessible with new master password...")
        
        # Create new custodian instance with new password
        print(f"  📝 Creating new KeyCustodian with new master password...")
        new_custodian = KeyCustodian(new_master_password, str(data_dir), iterations=1500000)
        print(f"  ✅ New KeyCustodian created successfully")
        
        # Read all credentials to verify they work
        print(f"  📋 Reading credentials with new master password...")
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
        print("  # To rollback the master password change:")
        print(f"  # new_custodian.rollback_rotation(rotation_id='{rotation_id}')")
        print("  # This would restore the previous master key and re-encrypt all credentials")
        
        # Clean up expired backups
        print("\n🧹 Cleaning up expired backups...")
        cleaned_count = new_custodian.cleanup_expired_backups()
        print(f"  ✅ Cleaned up {cleaned_count} expired backup(s)")
        
        print("\n✅ Master password change example completed successfully!")
        print("\n💡 Key takeaways:")
        print("  - Master password change re-encrypts all credentials with a new master key")
        print("  - The new master key is derived from the new password with a new salt")
        print("  - All operations create backups for potential rollback")
        print("  - Rotation history is maintained for audit purposes")
        print("  - After master password change, use the NEW master password to access credentials")
        print("  - Make sure to use the same iterations when creating the new KeyCustodian instance")


if __name__ == "__main__":
    main()
