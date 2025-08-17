# Splurge Key Custodian - CLI Examples

This document provides practical examples for using the Splurge Key Custodian command-line interface, with a focus on key rotation and master password change operations.

## Quick Start

### Basic Setup

```bash
# Create a data directory
mkdir -p ~/key-custodian-data

# Set your master password (recommended for security)
export MASTER_PASSWORD="MySecureMasterPassword123!@#ExtraLongEnough"
```

### Advanced Features

The CLI includes advanced features that require the `-x` or `--advanced` flag:

```bash
# Enable advanced features for base58 operations
python -m splurge_key_custodian -x base58 -e "Hello World"
python -m splurge_key_custodian --advanced base58 -g 32
```

## Complete Workflow Examples

### Basic CRUD Operations

#### 1. Create Credentials

```bash
# Create a basic credential
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}'

# Create a credential with metadata
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "Database Access" \
  -c '{"host": "db.example.com", "port": 5432, "username": "db_user", "password": "db_pass"}' \
  -m '{"service": "postgresql", "environment": "production"}'

# Create using environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data create \
  -n "AWS Access" \
  -c '{"access_key": "AKIA...", "secret_key": "..."}' \
  -m '{"service": "aws", "region": "us-east-1"}'
```

#### 2. List All Credentials

```bash
# List all credentials with basic info
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# List using environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data list
```

#### 3. Read/Decrypt Credentials

```bash
# Read a credential by name
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data read \
  -n "GitHub Account"

# Read a credential by key ID (from list command)
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data read \
  -k "12345678-1234-1234-1234-123456789abc"

# Read using environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data read \
  -n "Database Access"
```

#### 4. Update Credentials

```bash
# Update credential data
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data update \
  -k "credential-key-id" \
  -c '{"username": "new_user", "password": "new_password"}'

# Update credential name
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data update \
  -k "credential-key-id" \
  -n "Updated GitHub Account"

# Update metadata
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data update \
  -k "credential-key-id" \
  -m '{"service": "github", "environment": "production", "updated": true}'
```

#### 5. Delete Credentials

```bash
# Delete a credential by key ID
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data delete \
  -k "credential-key-id"

# Delete using environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data delete \
  -k "credential-key-id"
```

#### 6. Backup Operations

```bash
# Create a backup of all credentials
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data backup \
  -o /path/to/backup.zip

# Backup using environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data backup \
  -o /path/to/backup.zip
```

### Advanced Operations

#### 1. Base58 Encoding/Decoding

```bash
# Encode text to Base58
python -m splurge_key_custodian -x base58 -e "Hello World"
# Output: JxF12TrwUP45BMd

# Decode Base58 to text
python -m splurge_key_custodian -x base58 -d "JxF12TrwUP45BMd"
# Output: Hello World

# Generate cryptographically random Base58-like string (default 32 chars)
python -m splurge_key_custodian -x base58 -g

# Generate specific length (min: 32, max: 128)
python -m splurge_key_custodian -x base58 -g 64

# Using --advanced flag (alternative to -x)
python -m splurge_key_custodian --advanced base58 -g 48
```

#### 2. Base58 Binary Data Handling

```bash
# Encode binary data (will be treated as UTF-8)
python -m splurge_key_custodian -x base58 -e "Binary data with \x00\x01\x02"

# Decode to binary (outputs raw bytes to stdout)
python -m splurge_key_custodian -x base58 -d "encoded_binary_data" > output.bin
```

#### 3. Advanced Base58 Examples

```bash
# Generate multiple random strings for testing
for i in {1..5}; do
  python -m splurge_key_custodian -x base58 -g 32
done

# Encode a complex JSON string
python -m splurge_key_custodian -x base58 -e '{"key": "value", "number": 123}'

# Decode and pipe to jq for JSON processing
python -m splurge_key_custodian -x base58 -d "encoded_json_string" | jq .
```

### Complete End-to-End Example

```bash
# 1. Create multiple credentials
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}' \
  -m '{"service": "github", "environment": "personal"}'

python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "AWS Production" \
  -c '{"access_key": "AKIA...", "secret_key": "..."}' \
  -m '{"service": "aws", "environment": "production"}'

# 2. List all credentials
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# 3. Read a specific credential
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data read \
  -n "GitHub Account"

# 4. Update a credential
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data update \
  -k "credential-key-id-from-list" \
  -c '{"username": "johndoe", "password": "new_secret456"}' \
  -m '{"service": "github", "environment": "personal", "updated": "2024-01-01"}'

# 5. Verify the update
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data read \
  -n "GitHub Account"

# 6. Create a backup
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data backup \
  -o ~/key-custodian-backup.zip
```

## Key Rotation Examples

### 1. Master Key Rotation (Same Password, New Encryption Key)

This operation rotates the master encryption key while keeping the same master password. This is useful for security maintenance without changing user passwords.

```bash
# Basic master key rotation with default settings
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-master

# Master key rotation with increased iterations for better security
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-master \
  -ni 1500000

# Master key rotation with custom backup retention (14 days)
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-master \
  -ni 1500000 \
  -br 14

# Using environment variable for password
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data rotate-master \
  -ni 1500000
```

**What happens:**
- All credentials are re-encrypted with a new master key
- The master key is derived from the same password but with a new salt
- You continue to use the same master password to access credentials
- A backup is created before the rotation
- The operation is atomic - it either completes successfully or is fully rolled back

### 2. Master Password Change

This operation changes both the master password and the encryption key. This is useful when you want to change the master password.

```bash
# Basic master password change
python -m splurge_key_custodian -p "old-master-password" -d ~/key-custodian-data change-password \
  -np "NewSecureMasterPassword456!@#ExtraLongEnough"

# Master password change with increased iterations
python -m splurge_key_custodian -p "old-master-password" -d ~/key-custodian-data change-password \
  -np "NewSecureMasterPassword456!@#ExtraLongEnough" \
  -ni 1500000

# Master password change with custom backup retention
python -m splurge_key_custodian -p "old-master-password" -d ~/key-custodian-data change-password \
  -np "NewSecureMasterPassword456!@#ExtraLongEnough" \
  -ni 1500000 \
  -br 14

# Using environment variable for old password
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data change-password \
  -np "NewSecureMasterPassword456!@#ExtraLongEnough"
```

**What happens:**
- All credentials are re-encrypted with a new master key
- The new master key is derived from the new password with a new salt
- You must use the new master password to access credentials
- A backup is created before the change
- The operation is atomic - it either completes successfully or is fully rolled back

### 3. Bulk Credential Rotation

This operation re-encrypts all individual credential keys while keeping the same master key. This is useful for rotating credential encryption keys.

```bash
# Basic bulk rotation with default settings
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-credentials

# Bulk rotation with custom iterations
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-credentials \
  -i 1500000

# Bulk rotation with custom batch size (for large credential sets)
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-credentials \
  -bs 50

# Bulk rotation with all custom settings
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-credentials \
  -i 1500000 \
  -bs 25 \
  -br 14
```

**What happens:**
- Each credential gets a new individual encryption key
- The master key remains the same
- You continue to use the same master password
- A backup is created before the rotation
- The operation is atomic - it either completes successfully or is fully rolled back

## Rotation Management

### View Rotation History

```bash
# View all rotation history
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data history

# View last 10 rotation entries
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data history \
  -l 10

# View rotation history with environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data history
```

### Rollback Operations

```bash
# Rollback a specific rotation (use with caution!)
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rollback \
  -r "rotation-id-from-history"

# Rollback with environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data rollback \
  -r "rotation-id-from-history"
```

### Cleanup Expired Backups

```bash
# Clean up expired rotation backups
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data cleanup-backups

# Cleanup with environment variable
python -m splurge_key_custodian -e MASTER_PASSWORD -d ~/key-custodian-data cleanup-backups
```

## Complete Workflow Examples

### Example 1: Security Maintenance Workflow

```bash
# 1. Create some test credentials first
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}' \
  -m '{"service": "github"}'

python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "AWS Access" \
  -c '{"access_key": "AKIA...", "secret_key": "..."}' \
  -m '{"service": "aws"}'

# 2. Verify credentials exist
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# 3. Rotate master key for security maintenance
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-master \
  -ni 1500000

# 4. Verify credentials still work with same password
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# 5. View rotation history
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data history

# 6. Clean up expired backups
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data cleanup-backups
```

### Example 2: Master Password Change Workflow

```bash
# 1. Create credentials with initial password
python -m splurge_key_custodian -p "initial-password" -d ~/key-custodian-data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}'

# 2. Verify credentials work
python -m splurge_key_custodian -p "initial-password" -d ~/key-custodian-data list

# 3. Change master password
python -m splurge_key_custodian -p "initial-password" -d ~/key-custodian-data change-password \
  -np "NewSecureMasterPassword456!@#ExtraLongEnough" \
  -ni 1500000

# 4. Verify credentials work with new password
python -m splurge_key_custodian -p "NewSecureMasterPassword456!@#ExtraLongEnough" -d ~/key-custodian-data list

# 5. View rotation history
python -m splurge_key_custodian -p "NewSecureMasterPassword456!@#ExtraLongEnough" -d ~/key-custodian-data history
```

### Example 3: Bulk Rotation Workflow

```bash
# 1. Create multiple credentials
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "Credential 1" \
  -c '{"username": "user1", "password": "pass1"}'

python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "Credential 2" \
  -c '{"username": "user2", "password": "pass2"}'

python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data create \
  -n "Credential 3" \
  -c '{"username": "user3", "password": "pass3"}'

# 2. Verify all credentials exist
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# 3. Perform bulk rotation
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data rotate-credentials \
  -i 1500000 \
  -bs 10

# 4. Verify all credentials still work
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data list

# 5. View rotation history
python -m splurge_key_custodian -p "my-master-password" -d ~/key-custodian-data history
```

## Troubleshooting

### Common Issues

1. **Password Complexity Error**
   ```
   ValidationError: Master password must be at least 32 characters long
   ```
   **Solution**: Use a longer password with mixed case, numbers, and special characters.

2. **Decryption Failed Error**
   ```
   EncryptionError: Key decryption failed: Decryption failed
   ```
   **Solution**: Ensure you're using the correct master password and iterations.

3. **Backup Not Found Error**
   ```
   RotationRollbackError: No backup found for rotation
   ```
   **Solution**: The backup may have expired or been cleaned up. Check rotation history.

### Getting Help

```bash
# View help for all commands
python -m splurge_key_custodian --help

# View help for specific command
python -m splurge_key_custodian rotate-master --help
python -m splurge_key_custodian change-password --help
python -m splurge_key_custodian rotate-credentials --help

# View help for advanced commands
python -m splurge_key_custodian -x base58 --help
python -m splurge_key_custodian --advanced base58 --help
```

## Security Best Practices

1. **Use Environment Variables**: Store master passwords in environment variables rather than command line arguments
2. **Regular Rotation**: Perform master key rotation regularly for security maintenance
3. **Backup Management**: Keep backups for the recommended retention period
4. **Strong Passwords**: Use strong, complex passwords that meet all requirements
5. **Secure Storage**: Store the data directory in a secure location with appropriate permissions
6. **Audit Trail**: Regularly review rotation history for security auditing
7. **Atomic Operations**: All rotation operations are atomic, ensuring data integrity
8. **Advanced Features**: Use advanced features (`-x`/`--advanced`) only when needed and understand their purpose

## Command Reference

| Command | Purpose | Key Options | Advanced Required |
|---------|---------|-------------|-------------------|
| `create` | Create a new credential | `-n, --name`, `-c, --credentials`, `-m, --meta-data` | No |
| `read` | Read/decrypt a credential | `-k, --key-id`, `-n, --name` | No |
| `list` | List all credentials | None | No |
| `update` | Update a credential | `-k, --key-id`, `-n, --name`, `-c, --credentials`, `-m, --meta-data` | No |
| `delete` | Delete a credential | `-k, --key-id` | No |
| `backup` | Create backup of all data | `-o, --output` | No |
| `rotate-master` | Rotate master key (same password) | `-ni`, `--no-backup`, `-br` | No |
| `change-password` | Change master password | `-np`, `-ni`, `--no-backup`, `-br` | No |
| `rotate-credentials` | Rotate all credential keys | `-i`, `-bs`, `--no-backup`, `-br` | No |
| `history` | View rotation history | `-l` | No |
| `rollback` | Rollback rotation | `-r` | No |
| `cleanup-backups` | Clean expired backups | None | No |
| `base58` | Base58 encode/decode operations | `-e, --encode`, `-d, --decode`, `-g, --generate` | **Yes** |

**Option Legend:**
- `-n, --name`: Credential name
- `-c, --credentials`: JSON string containing credential data
- `-m, --meta-data`: JSON string containing metadata
- `-k, --key-id`: Unique credential identifier
- `-o, --output`: Output file path for backups
- `-ni, --new-iterations`: New iterations for key derivation
- `-np, --new-password`: New master password
- `-i, --iterations`: Iterations for key derivation
- `-bs, --batch-size`: Batch size for bulk operations
- `-br, --backup-retention`: Backup retention days
- `-l, --limit`: Limit for history display
- `-r, --rotation-id`: Rotation ID for rollback
- `--no-backup`: Skip backup creation (not recommended)
- `-x, --advanced`: Enable advanced features (required for base58)
- `-e, --encode`: Text to encode to Base58
- `-d, --decode`: Base58 string to decode
- `-g, --generate`: Generate random Base58-like string (length optional, default: 32)

## Testing the CLI

You can test the CLI key rotation functionality using the provided demonstration script:

```bash
# Run the CLI demonstration
python examples/cli_key_rotation_demo.py
```

This script demonstrates:
- Creating credentials via CLI
- Performing master key rotation
- Verifying credentials remain accessible
- Viewing rotation history
- Cleaning up expired backups

The demonstration uses a temporary directory and shows the complete workflow of key rotation operations. 