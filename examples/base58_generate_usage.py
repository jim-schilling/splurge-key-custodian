#!/usr/bin/env python3
"""Example demonstrating the base58 generate command."""

import subprocess
import sys


def main():
    """Demonstrate the base58 generate command."""
    print("Base58 Generate Command Example")
    print("=" * 40)
    
    # Example 1: Generate a single 32-character base58-like random string
    print("\n1. Generate a single 32-character base58-like random string:")
    print("   python -m splurge_key_custodian.cli --advanced base58 -g")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "splurge_key_custodian.cli", 
            "--advanced", "base58", "-g"
        ], capture_output=True, text=True, check=True)
        print(f"   Output: {result.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"   Error: {e}")
        print(f"   stderr: {e.stderr}")
    
    # Example 2: Generate multiple strings
    print("\n2. Generate multiple 32-character base58-like random strings:")
    for i in range(3):
        try:
            result = subprocess.run([
                sys.executable, "-m", "splurge_key_custodian.cli", 
                "--advanced", "base58", "-g"
            ], capture_output=True, text=True, check=True)
            print(f"   String {i+1}: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"   Error generating string {i+1}: {e}")
    
    # Example 3: Show the character composition
    print("\n3. Character composition of generated strings:")
    print("   Each 32-character string contains:")
    print("   - 7 uppercase letters (A-Z, excluding O)")
    print("   - 17 lowercase letters (a-z, excluding l)")
    print("   - 3 special characters (!@#$%^&*()_+-=[],.?;)")
    print("   - 5 numeric characters (1-9, excluding 0)")
    print("   - All characters are cryptographically shuffled")
    
    # Example 4: Show help
    print("\n4. Help for the base58 command:")
    print("   python -m splurge_key_custodian.cli --advanced base58 --help")
    
    try:
        result = subprocess.run([
            sys.executable, "-m", "splurge_key_custodian.cli", 
            "--advanced", "base58", "--help"
        ], capture_output=True, text=True, check=True)
        print("   Help output:")
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                print(f"   {line}")
    except subprocess.CalledProcessError as e:
        print(f"   Error getting help: {e}")


if __name__ == "__main__":
    main()
