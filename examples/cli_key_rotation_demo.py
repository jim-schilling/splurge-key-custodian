#!/usr/bin/env python3
"""Demonstration of CLI key rotation commands."""

import json
import os
import subprocess
import tempfile
from pathlib import Path


def run_cli_command(cmd_args, check=True):
    """Run a CLI command and return the result."""
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr


def main():
    """Demonstrate CLI key rotation functionality."""
    print("🔐 CLI Key Rotation Demonstration")
    print("=" * 50)
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir) / "key-custodian-data"
        data_dir.mkdir(parents=True, exist_ok=True)
        
        # Master password (meets complexity requirements)
        master_password = "MySecureMasterPassword123!@#ExtraLongEnough"
        
        print(f"📁 Using data directory: {data_dir}")
        print(f"🔑 Master password: {master_password[:10]}...")
        
        # 1. Create a test credential
        print("\n1️⃣ Creating test credential...")
        create_cmd = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "save",
            "-n", "GitHub Account",
            "-c", '{"username": "johndoe", "password": "secret123"}',
            "-m", '{"service": "github"}'
        ]
        
        returncode, stdout, stderr = run_cli_command(create_cmd)
        if returncode == 0:
            print("  ✅ Credential created successfully")
            response = json.loads(stdout)
            print(f"     Key ID: {response.get('key_id', 'N/A')}")
        else:
            print(f"  ❌ Failed to create credential: {stderr}")
            return
        
        # 2. List credentials
        print("\n2️⃣ Listing credentials...")
        list_cmd = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "list"
        ]
        
        returncode, stdout, stderr = run_cli_command(list_cmd)
        if returncode == 0:
            print("  ✅ Credentials listed successfully")
            response = json.loads(stdout)
            print(f"     Count: {response.get('count', 0)}")
            for name in response.get('names', []):
                print(f"     - {name}")
        else:
            print(f"  ❌ Failed to list credentials: {stderr}")
            return
        
        # 3. Rotate master key (same password, new encryption key)
        print("\n3️⃣ Rotating master key...")
        rotate_cmd = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "rotate-master",
            "-ni", "1500000",
            "-br", "7"
        ]
        
        returncode, stdout, stderr = run_cli_command(rotate_cmd)
        if returncode == 0:
            print("  ✅ Master key rotation completed successfully")
            response = json.loads(stdout)
            print(f"     Rotation ID: {response.get('rotation_id', 'N/A')}")
        else:
            print(f"  ❌ Failed to rotate master key: {stderr}")
            return
        
        # 4. Verify credentials still work after rotation
        print("\n4️⃣ Verifying credentials after rotation...")
        list_cmd_after_rotation = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "-i", "1500000",  # Use the same iterations as the rotation
            "list"
        ]
        
        returncode, stdout, stderr = run_cli_command(list_cmd_after_rotation)
        if returncode == 0:
            print("  ✅ Credentials still accessible after rotation")
            response = json.loads(stdout)
            print(f"     Count: {response.get('count', 0)}")
        else:
            print(f"  ❌ Failed to access credentials after rotation: {stderr}")
            return
        
        # 5. View rotation history
        print("\n5️⃣ Viewing rotation history...")
        history_cmd = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "-i", "1500000",  # Use the same iterations
            "history",
            "-l", "5"
        ]
        
        returncode, stdout, stderr = run_cli_command(history_cmd)
        if returncode == 0:
            print("  ✅ Rotation history retrieved successfully")
            response = json.loads(stdout)
            print(f"     History entries: {len(response.get('history', []))}")
            for entry in response.get('history', []):
                print(f"     - {entry.get('rotation_type')} rotation: {entry.get('rotation_id')}")
        else:
            print(f"  ❌ Failed to retrieve rotation history: {stderr}")
        
        # 6. Clean up expired backups
        print("\n6️⃣ Cleaning up expired backups...")
        cleanup_cmd = [
            "python", "splurge_key_custodian/cli.py",
            "-p", master_password,
            "-d", str(data_dir),
            "-i", "1500000",  # Use the same iterations
            "cleanup-backups"
        ]
        
        returncode, stdout, stderr = run_cli_command(cleanup_cmd)
        if returncode == 0:
            print("  ✅ Backup cleanup completed")
            response = json.loads(stdout)
            print(f"     Cleaned up: {response.get('cleaned_count', 0)} backup(s)")
        else:
            print(f"  ❌ Failed to cleanup backups: {stderr}")
        
        print("\n✅ CLI key rotation demonstration completed successfully!")
        print("\n💡 Key takeaways:")
        print("  - Master key rotation works seamlessly from the CLI")
        print("  - Credentials remain accessible with the same password")
        print("  - Rotation history is properly maintained")
        print("  - All operations create backups for safety")
        print("  - The CLI provides a user-friendly interface for key rotation")


if __name__ == "__main__":
    main()
