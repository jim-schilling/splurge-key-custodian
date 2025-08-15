# Splurge Key Custodian - File Based

A secure file-based key management system that stores cryptographic keys in JSON files with atomic key rotation capabilities.

## Features

- **Hybrid file-based storage**: Uses separate credential files and a central index for optimal performance and recovery
- **Atomic operations**: All file operations create temporary files, then atomically replace originals
- **Secure encryption**: All credentials are encrypted with Fernet (AES-256-CBC with HMAC-SHA256) using a master password with 64-byte salt and configurable iterations (default: 500,000, minimum: 100,000)
- **Advanced security features**:
  - Constant-time comparison to prevent timing attacks
  - Secure memory zeroing for sensitive data cleanup
  - Input sanitization
  - Context manager support for automatic resource cleanup
- **Unique naming**: Credential names must be unique across all stored credentials
- **Flexible data structure**: Store any JSON-serializable data as credentials and metadata
- **Master key encryption**: Uses a master key derived from your password to encrypt individual credentials
- **Index rebuilding**: Automatic recovery from credential files if index is corrupted or missing
- **Backup support**: Built-in backup functionality for disaster recovery
- **Environment variable support**: Load master password from environment variables with Base58 encoding
- **Comprehensive CLI**: Full command-line interface with input validation and error handling
- **Extensive testing**: 400+ tests with 90%+ code coverage across unit, integration, and functional tests
- **Key rotation**: Comprehensive key rotation capabilities with atomic operations, backup and rollback support

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package installer)

### Install from source

```bash
git clone https://github.com/splurge/splurge-key-custodian.git
cd splurge-key-custodian
pip install -e .
```

### Install dependencies for development

```bash
pip install -e ".[dev]"
```

## Quick Start

### Python API

```python
from splurge_key_custodian import KeyCustodian

# Initialize the key custodian with default iterations (100,000)
custodian = KeyCustodian(
    master_password="A very long passphrase of at least 32 characters",
    data_dir="/path/to/credentials"
)

# Or initialize with custom iterations (minimum 100,000)
custodian = KeyCustodian(
    master_password="A very long passphrase of at least 32 characters",
    data_dir="/path/to/credentials",
    iterations=200000
)

# Create a new credential
key_id = custodian.create_credential(
    name="Production API",
    credentials={"username": "api_user", "password": "secure_password"},
    meta_data={"service": "production_api", "environment": "prod"}
)

# Read the credential
credential_data = custodian.read_credential(key_id)

# Find credential by name
credential_info = custodian.find_credential_by_name("Production API")

# List all credentials
all_credentials = custodian.list_credentials()
```

## Command Line Interface

The library provides a command-line interface for all operations:

```bash
# Basic usage
python -m splurge_key_custodian [options] <command> [command-options]

# Create credentials
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}' \
  -m '{"service": "github"}'

# List credentials
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data list

# Read a specific credential
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data read \
  -k "credential-key-id"

# Update a credential
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data update \
  -k "credential-key-id" \
  -c '{"username": "johndoe", "password": "new-secret123"}'

# Delete a credential
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data delete \
  -k "credential-key-id"

# Backup all data
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data backup \
  -o /path/to/backup.zip
```

### Key Rotation CLI Examples

#### Master Key Rotation (Same Password, New Encryption Key)

```bash
# Rotate master key with default iterations (500,000)
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-master

# Rotate master key with custom iterations
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-master \
  -ni 1500000

# Rotate master key without creating backup (not recommended)
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-master \
  --no-backup

# Rotate master key with custom backup retention
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-master \
  -ni 1500000 \
  -br 14
```

#### Master Password Change

```bash
# Change master password with default iterations
python -m splurge_key_custodian -p "old-master-password" -d /path/to/data change-password \
  -np "new-master-password"

# Change master password with custom iterations
python -m splurge_key_custodian -p "old-master-password" -d /path/to/data change-password \
  -np "new-master-password" \
  -ni 1500000

# Change master password without backup (not recommended)
python -m splurge_key_custodian -p "old-master-password" -d /path/to/data change-password \
  -np "new-master-password" \
  --no-backup

# Change master password with custom backup retention
python -m splurge_key_custodian -p "old-master-password" -d /path/to/data change-password \
  -np "new-master-password" \
  -ni 1500000 \
  -br 14
```

#### Bulk Credential Rotation

```bash
# Rotate credential keys with default settings
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-credentials

# Rotate credential keys with custom iterations
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-credentials \
  -i 1500000

# Rotate credential keys with custom batch size
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-credentials \
  -bs 50

# Rotate credential keys without backup (not recommended)
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-credentials \
  --no-backup

# Rotate credential keys with custom settings
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rotate-credentials \
  -i 1500000 \
  -bs 25 \
  -br 14
```

#### Rotation Management

```bash
# View rotation history
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data history

# View last 10 rotation entries
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data history \
  -l 10

# Rollback a specific rotation (use with caution!)
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data rollback \
  -r "rotation-id-here"

# Clean up expired backups
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data cleanup-backups
```

#### Using Environment Variables for Passwords

```bash
# Set master password as environment variable
export MASTER_PASSWORD="my-secure-master-password"

# Use environment variable for master password
python -m splurge_key_custodian -e MASTER_PASSWORD -d /path/to/data rotate-master

# Use environment variable for master password change
python -m splurge_key_custodian -e MASTER_PASSWORD -d /path/to/data change-password \
  -np "new-master-password"
```

#### Complete Workflow Example

```bash
# 1. Create initial credentials
python -m splurge_key_custodian -p "initial-password" -d /path/to/data create \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secret123"}'

# 2. Rotate master key (same password, new encryption key)
python -m splurge_key_custodian -p "initial-password" -d /path/to/data rotate-master \
  -ni 1500000

# 3. Verify credentials still work with same password
python -m splurge_key_custodian -p "initial-password" -d /path/to/data list

# 4. Change master password
python -m splurge_key_custodian -p "initial-password" -d /path/to/data change-password \
  -np "new-secure-password" \
  -ni 1500000

# 5. Verify credentials work with new password
python -m splurge_key_custodian -p "new-secure-password" -d /path/to/data list

# 6. View rotation history
python -m splurge_key_custodian -p "new-secure-password" -d /path/to/data history

# 7. Clean up expired backups
python -m splurge_key_custodian -p "new-secure-password" -d /path/to/data cleanup-backups
```

### CLI Command Reference

| Command | Description | Key Options |
|---------|-------------|-------------|
| `rotate-master` | Rotate master key (same password, new encryption key) | `-ni, --new-iterations`, `--no-backup`, `-br, --backup-retention` |
| `change-password` | Change master password and rotate master key | `-np, --new-password`, `-ni, --new-iterations`, `--no-backup`, `-br, --backup-retention` |
| `rotate-credentials` | Rotate credential keys (bulk rotation) | `-i, --iterations`, `-bs, --batch-size`, `--no-backup`, `-br, --backup-retention` |
| `rollback` | Rollback a specific rotation operation | `-r, --rotation-id` |
| `history` | View rotation history | `-l, --limit` |
| `cleanup-backups` | Clean up expired rotation backups | None |

### Important Notes

- **Atomic Operations**: All key rotation operations are atomic - they either complete successfully or are fully rolled back, preventing partial failures.
- **Backup Creation**: All rotation operations create backups by default. Use `--no-backup` only in testing environments.
- **Iterations**: Higher iterations provide better security but slower performance. Default is 1,000,000.
- **Batch Size**: For bulk rotation, larger batch sizes are faster but use more memory. Default is 25.
- **Backup Retention**: Backups are automatically cleaned up after the retention period. Default is 30 days.
- **Password Complexity**: New master passwords must meet complexity requirements (32+ characters, mixed case, numbers, special characters).
- **Rollback Safety**: Rollback operations restore the previous state but may not be available if backups have expired.

## Configuration

Iteration and password requirements are enforced internally.

## File Structure

The system uses a hybrid approach with separate files for optimal performance and recovery:

- `key-custodian-master.json`: Contains master key metadata
- `key-custodian-index.json`: Contains credential name mappings (key_id → name)
- `<key_id>.credential.json`: Individual credential files containing encrypted data

During file operations, the system uses:
- `*.temp`: Temporary files during write operations
- `*.archive`: Backup of original files before replacement

### Example File Structure

```
/path/to/credentials/
├── key-custodian-master.json
├── key-custodian-index.json
├── 12345678-1234-1234-1234-123456789abc.credential.json
├── 87654321-4321-4321-4321-876543210def.credential.json
└── backup/
    ├── key-custodian-master.json
    ├── key-custodian-index.json
    └── *.credential.json
```

## API Reference

### KeyCustodian

The main class for key management operations.

#### Constructor

```python
KeyCustodian(master_password: str, data_dir: str, *, iterations: Optional[int] = None)
```

- `master_password`: Master password for encrypting/decrypting keys. Policy: at least 32 characters.
- `data_dir`: Directory to store key files
- `iterations`: Number of iterations for key derivation (default: 500,000, minimum: 100,000)

**Password Requirements:**
- **Length**: From 32 to 512 characters long
- **Character Classes**: Must contain at least one character from each of the following classes:
  - Uppercase letters (A-Z, except I, O)
  - Lowercase letters (a-z, except l)
  - Numbers (1-9, except 0)
  - Symbols (!@#$%^&*_+-=[];,.?)

**Example valid passwords:**
- `"This is a long passphrase with at least thirty-two characters"`

**Example invalid passwords:**
- `"short"` (too short)

#### Context Manager Support

The KeyCustodian supports context manager usage for automatic resource cleanup:

```python
with KeyCustodian("password", "/path/to/data") as custodian:
    key_id = custodian.create_credential(
        name="Test",
        credentials={"test": "data"}
    )
    # Automatic cleanup of sensitive data when exiting context
```

#### Class Methods

##### init_from_environment()

Create a KeyCustodian instance using a Base58-encoded master password from an environment variable.

```python
@classmethod
init_from_environment(
    cls,
    env_variable: str,
    data_dir: str,
    *,
    iterations: Optional[int] = None
) -> "KeyCustodian"
```

**Parameters:**
- `env_variable`: Name of the environment variable containing the Base58-encoded master password
- `data_dir`: Directory to store key files
- `iterations`: Number of iterations for key derivation (default: 1,000,000, minimum: 100,000)

**Returns:** KeyCustodian instance

**Raises:** 
- `ValidationError`: If environment variable is not set or invalid
- `Base58ValidationError`: If the master password is not valid Base58

**Example:**
```python
import os
from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.base58 import Base58

# Encode your password to Base58
password = "A very long passphrase of at least 32 characters"
encoded_password = Base58.encode(password.encode('utf-8'))

# Set environment variable
os.environ["MASTER_PASSWORD"] = encoded_password

# Create KeyCustodian from environment variable
custodian = KeyCustodian.init_from_environment(
    "CUSTOM_MASTER_PASSWORD",
    "/path/to/data"
)
```

#### Methods

##### create_credential()

Create a new credential entry.

```python
create_credential(
    *,
    name: str,
    credentials: Dict[str, Any],
    meta_data: Optional[Dict[str, Any]] = None,
) -> str
```

**Parameters:**
- `name`: Name for the credential (must be unique)
- `credentials`: User-defined credentials dictionary
- `meta_data`: User-defined metadata dictionary

**Returns:** Key ID of the created credential

**Raises:** `ValidationError` if parameters are invalid or name already exists

**Note:** The `name` field must be unique across all credentials. Attempting to create a credential with a duplicate name will raise a `ValidationError`.

##### read_credential()

Read a credential by ID.

```python
read_credential(key_id: str) -> Dict[str, Any]
```

**Parameters:**
- `key_id`: ID of the credential to read

**Returns:** Dictionary containing credentials and meta_data

**Raises:** `KeyNotFoundError` if credential is not found

##### update_credential()

Update a credential.

```python
update_credential(
    key_id: str,
    *,
    name: Optional[str] = None,
    credentials: Optional[Dict[str, Any]] = None,
    meta_data: Optional[Dict[str, Any]] = None,
) -> None
```

**Parameters:**
- `key_id`: ID of the credential to update
- `name`: New name for the credential (must be unique if provided)
- `credentials`: New credentials dictionary
- `meta_data`: New metadata dictionary

**Raises:** `KeyNotFoundError` if credential is not found, `ValidationError` if parameters are invalid or name already exists

##### list_credentials()

List all credentials with their metadata.

```python
list_credentials() -> List[Dict[str, Any]]
```

**Returns:** List of credential metadata dictionaries

##### find_credential_by_name()

Find a credential by name.

```python
find_credential_by_name(name: str) -> Optional[Dict[str, Any]]
```

**Parameters:**
- `name`: Name of the credential to find

**Returns:** Credential metadata dictionary if found, None otherwise

##### delete_credential()

Delete a credential from the store.

```python
delete_credential(key_id: str) -> None
```

**Parameters:**
- `key_id`: ID of the credential to delete

**Raises:** `KeyNotFoundError` if credential is not found

##### backup_credentials()

Create a backup of all credential files.

```python
backup_credentials(backup_dir: str) -> None
```

**Parameters:**
- `backup_dir`: Directory to store backups

##### rebuild_index()

Manually rebuild the credentials index from credential files.

```python
rebuild_index() -> None
```

**Note:** This method is useful for recovery scenarios where the index file is corrupted or missing. The system automatically rebuilds the index during initialization if needed.

##### cleanup()

Manually cleanup sensitive data from memory.

```python
cleanup() -> None
```

**Note:** This method is automatically called when using the context manager. It securely zeros sensitive data including master passwords.

#### Key Rotation Methods

The KeyCustodian provides comprehensive key rotation capabilities for security maintenance.

##### rotate_master_key()

Rotate the master encryption key by generating a new key from the same master password. This operation re-encrypts all credentials with a new master key derived from the same password but with a new salt.

```python
rotate_master_key(
    *,
    new_iterations: Optional[int] = None,
    create_backup: bool = True,
    backup_retention_days: Optional[int] = None
) -> str
```

**Parameters:**
- `new_iterations`: New iterations for key derivation (optional, defaults to current or 1,000,000)
- `create_backup`: Whether to create a backup before rotation (default: True)
- `backup_retention_days`: Days to retain backup (optional, defaults to 30)

**Returns:** Rotation ID for tracking the operation

**Raises:** `KeyRotationError` if rotation fails, `ValidationError` if parameters are invalid

**Example:**
```python
# Rotate master key (same password, new encryption key)
rotation_id = custodian.rotate_master_key(
    new_iterations=1500000,  # Increase iterations for better security
    create_backup=True,
    backup_retention_days=7
)
print(f"Master key rotation completed: {rotation_id}")

# Access with same password but new iterations
new_custodian = KeyCustodian("same-password", "/path/to/data", iterations=1500000)
```

##### change_master_password()

Change the master password and rotate the master key. This operation re-encrypts all credentials with a new master key derived from the new master password.

```python
change_master_password(
    *,
    new_master_password: str,
    new_iterations: Optional[int] = None,
    create_backup: bool = True,
    backup_retention_days: Optional[int] = None
) -> str
```

**Parameters:**
- `new_master_password`: New master password (must meet complexity requirements)
- `new_iterations`: New iterations for key derivation (optional, defaults to current or 1,000,000)
- `create_backup`: Whether to create a backup before rotation (default: True)
- `backup_retention_days`: Days to retain backup (optional, defaults to 30)

**Returns:** Rotation ID for tracking the operation

**Raises:** `KeyRotationError` if rotation fails, `ValidationError` if parameters are invalid

**Example:**
```python
# Change master password
rotation_id = custodian.change_master_password(
    new_master_password="NewSecureMasterPassword456!@#",
    new_iterations=1500000,  # Increase iterations for better security
    create_backup=True,
    backup_retention_days=7
)
print(f"Master password change completed: {rotation_id}")

# Access with new password
new_custodian = KeyCustodian("new-password", "/path/to/data", iterations=1500000)
```

##### rotate_all_credentials()

Rotate encryption keys for all credentials. This operation re-encrypts all credentials with new individual keys while keeping the same master key.

```python
rotate_all_credentials(
    *,
    iterations: Optional[int] = None,
    create_backup: bool = True,
    backup_retention_days: Optional[int] = None,
    batch_size: Optional[int] = None
) -> str
```

**Parameters:**
- `iterations`: Iterations for key derivation (optional)
- `create_backup`: Whether to create a backup before rotation (default: True)
- `backup_retention_days`: Days to retain backup (optional, defaults to 30)
- `batch_size`: Number of credentials to rotate in each batch (optional, defaults to 50)

**Returns:** Rotation ID for tracking the operation

**Raises:** `KeyRotationError` if rotation fails, `ValidationError` if parameters are invalid

**Example:**
```python
# Rotate all credential keys
rotation_id = custodian.rotate_all_credentials(
    create_backup=True,
    backup_retention_days=7,
    batch_size=25
)
print(f"Bulk credential rotation completed: {rotation_id}")
```

##### rollback_rotation()

Rollback a key rotation operation using backup data.

```python
rollback_rotation(
    *,
    rotation_id: str
) -> None
```

**Parameters:**
- `rotation_id`: ID of the rotation to rollback

**Raises:** `RotationRollbackError` if rollback fails, `ValidationError` if parameters are invalid

**Example:**
```python
# Rollback a rotation
try:
    custodian.rollback_rotation(rotation_id="rotation-uuid-here")
    print("Rotation rollback completed successfully")
except RotationRollbackError as e:
    print(f"Rollback failed: {e}")
```

##### get_rotation_history()

Get rotation history for audit and tracking purposes.

```python
get_rotation_history(
    *,
    limit: Optional[int] = None
) -> List[RotationHistory]
```

**Parameters:**
- `limit`: Maximum number of history entries to return (optional)

**Returns:** List of rotation history entries

**Raises:** `RotationHistoryError` if history retrieval fails

**Example:**
```python
# Get recent rotation history
history = custodian.get_rotation_history(limit=10)
for entry in history:
    print(f"{entry.rotation_type} rotation: {entry.rotation_id}")
    print(f"  Created: {entry.created_at}")
    print(f"  Affected credentials: {len(entry.affected_credentials)}")
```

##### cleanup_expired_backups()

Clean up expired rotation backups to free up storage space.

```python
cleanup_expired_backups() -> int
```

**Returns:** Number of backups cleaned up

**Example:**
```python
# Clean up expired backups
cleaned_count = custodian.cleanup_expired_backups()
print(f"Cleaned up {cleaned_count} expired backup(s)")
```

#### Properties

- `data_directory`: Get the data directory path
- `credential_count`: Get the total number of credentials in the store
- `master_key_id`: Get the master key ID

## Data Models

### CredentialFile

Individual credential file structure for the hybrid approach.

```python
class CredentialFile:
    key_id: str                    # Unique identifier (UUID-based)
    name: str                      # Credential name (stored unencrypted for index rebuilding)
    salt: str                      # Base58 encoded salt for encryption
    data: str                      # Base58 encoded encrypted credential data
    created_at: datetime           # Creation timestamp
```

### CredentialsIndex

Credentials index file structure for the hybrid approach.

```python
class CredentialsIndex:
    credentials: Dict[str, str]    # key_id → name mapping
    last_updated: datetime         # Last update timestamp
```

### CredentialData

Encrypted credential data structure.

```python
class CredentialData:
    credentials: Dict[str, Any]    # User-defined credentials dictionary
    meta_data: Dict[str, Any]      # User-defined metadata dictionary
```

### MasterKey

Master key for encrypting/decrypting other keys.

```python
class MasterKey:
    key_id: str                    # Unique identifier (UUID-based)
    credentials: str               # Base58 encoded encrypted master key
    salt: str                      # Base58 encoded salt for PBKDF2
    created_at: datetime           # Creation timestamp
```

## Security Features

### Advanced Security Measures

1. **Constant-time comparison**: Prevents timing attacks during password validation
2. **Secure memory zeroing**: Automatically cleans up sensitive data from memory
3. **Input sanitization**: Validates and sanitizes all input to prevent injection attacks
4. **Context manager support**: Automatic cleanup of sensitive data when exiting context

## CLI Features

### Input Validation

The CLI includes comprehensive input validation:

- **Character sanitization**: Blocks dangerous characters while allowing legitimate special characters
- **Length limits**: Configurable input length restrictions
- **JSON validation**: Ensures valid JSON for credential data
- **Password policy**: Enforces minimum length requirements

### Error Handling

- **Structured error messages**: Clear, actionable error messages
- **Graceful failure**: Proper error handling and cleanup
- **User-friendly output**: Formatted output for better readability

### CLI Examples

```bash
# Save credentials with special characters in name
python -m splurge_key_custodian -p "password" -d /path/to/data save \
  -n "My Account ($100) & Admin" \
  -c '{"username": "user", "password": "pass"}'

# Save with metadata
python -m splurge_key_custodian -p "password" -d /path/to/data save \
  -n "Database Access" \
  -c '{"host": "db.example.com", "port": 5432}' \
  -m '{"environment": "production", "backup": true}'

# Read and display formatted output
python -m splurge_key_custodian -p "password" -d /path/to/data read -n "My Account"
```

## Security Considerations

1. **Master Password**: Keep your master password secure and never store it in plain text
2. **File Permissions**: Ensure key files have appropriate file system permissions
3. **Backup Security**: Secure your backup files with appropriate access controls
4. **Key Rotation**: Regularly rotate keys according to your security policy
5. **Expiration**: Use key expiration to enforce key lifecycle management
6. **Index Recovery**: The system can automatically rebuild the index from credential files if needed
7. **Memory Security**: Use context managers to ensure sensitive data is cleaned up
8. **Input Validation**: All input is validated and sanitized to prevent injection attacks

## Examples

### Basic Usage

```python
from splurge_key_custodian import KeyCustodian

# Initialize
custodian = KeyCustodian("secure-password", "/path/to/credentials")

# Create credentials
api_credentials = custodian.create_credential(
    name="API Production",
    credentials={"username": "api_user", "password": "secure_password"},
    meta_data={"service": "production_api", "environment": "prod"}
)

database_credentials = custodian.create_credential(
    name="Database Access",
    credentials={"host": "db.example.com", "port": 5432, "username": "db_user", "password": "db_pass"},
    meta_data={"service": "postgresql", "environment": "prod"}
)

# Read credentials
api_data = custodian.read_credential(api_credentials)
db_data = custodian.read_credential(database_credentials)
```

### Context Manager Usage

```python
# Automatic cleanup with context manager
with KeyCustodian("password", "/path/to/data") as custodian:
    key_id = custodian.create_credential(
        name="Temporary Credential",
        credentials={"temp": "data"}
    )
    data = custodian.read_credential(key_id)
    # Automatic cleanup when exiting context
```

<!-- Configuration Management example removed (legacy). -->

### Name Uniqueness Enforcement

```python
# Create first credential
custodian.create_credential(
    name="My Service",
    credentials={"username": "user1", "password": "pass1"}
)

# This will raise ValidationError: "Credential with name 'My Service' already exists"
try:
    custodian.create_credential(
        name="My Service",  # Duplicate name!
        credentials={"username": "user2", "password": "pass2"}
    )
except ValidationError as e:
    print(f"Error: {e}")
```

### Finding Credentials by Name

```python
# Find a credential by name
credential_info = custodian.find_credential_by_name("API Production")
if credential_info:
    print(f"Found credential: {credential_info['key_id']}")
    # Read the full credential data
    data = custodian.read_credential(credential_info['key_id'])
    print(f"Username: {data['credentials']['username']}")
else:
    print("Credential not found")
```

### Updating Credentials

```python
# Update credential name (must be unique)
custodian.update_credential(
    key_id="existing-key-id",
    name="Updated API Production"  # New unique name
)

# Update credential data
custodian.update_credential(
    key_id="existing-key-id",
    credentials={"username": "new_user", "password": "new_password"},
    meta_data={"service": "updated_api", "version": "2.0"}
)
```

### Backup and Recovery

```python
# Create backup
custodian.backup_credentials("/path/to/backup")

# List all credentials
all_credentials = custodian.list_credentials()
for cred in all_credentials:
    print(f"{cred['key_id']}: {cred['name']} (created: {cred['created_at']})")

# Manual index rebuild (if needed)
custodian.rebuild_index()
```

### Key Rotation

```python
# Rotate master key (same password, new encryption key)
rotation_id = custodian.rotate_master_key(
    new_iterations=1500000,  # Increase iterations for better security
    create_backup=True,
    backup_retention_days=7
)
print(f"Master key rotation completed: {rotation_id}")

# Change master password
rotation_id = custodian.change_master_password(
    new_master_password="NewSecureMasterPassword456!@#",
    new_iterations=1500000,  # Increase iterations for better security
    create_backup=True,
    backup_retention_days=7
)
print(f"Master password change completed: {rotation_id}")

# Rotate all credential keys (keep same master password)
rotation_id = custodian.rotate_all_credentials(
    create_backup=True,
    backup_retention_days=7,
    batch_size=25
)
print(f"Bulk credential rotation completed: {rotation_id}")

# View rotation history
history = custodian.get_rotation_history(limit=10)
for entry in history:
    print(f"{entry.rotation_type} rotation: {entry.rotation_id}")
    print(f"  Created: {entry.created_at}")
    print(f"  Affected credentials: {len(entry.affected_credentials)}")

# Rollback a rotation (use with caution!)
# custodian.rollback_rotation(rotation_id="your-rotation-id")

# Clean up expired backups
cleaned_count = custodian.cleanup_expired_backups()
print(f"Cleaned up {cleaned_count} expired backup(s)")
```

**Important Note**: When performing master key rotation with custom iterations, you must use the same iterations when creating a new KeyCustodian instance to access the rotated credentials. For example:

```python
# Rotate with custom iterations
rotation_id = custodian.rotate_master_key(
    new_master_password="new-password",
    new_iterations=2000000
)

# Access with new password AND same iterations
new_custodian = KeyCustodian("new-password", "/path/to/data", iterations=2000000)
```

### Environment Variable Usage

```python
import os
from splurge_key_custodian import KeyCustodian
from splurge_key_custodian.base58 import Base58

# Encode password to Base58
password = "my-secure-password"
encoded_password = Base58.encode(password.encode('utf-8'))

# Set environment variable
os.environ["MASTER_PASSWORD"] = encoded_password

# Create custodian from environment
custodian = KeyCustodian.init_from_environment("MASTER_PASSWORD", "/path/to/credentials")

# Use normally
key_id = custodian.create_credential(
    name="Test Credential",
    credentials={"test": "data"}
)
```

## Testing

The project includes comprehensive testing with over 400 tests and 90%+ code coverage.

### Test Organization

```
tests/
├── unit/           # Unit tests for individual components
├── integration/    # Integration tests for component interactions
├── functional/     # Functional tests for end-to-end workflows
└── test_utility.py # Shared test utilities and fixtures
```

### Running Tests

Use the provided test runner script for easy test execution:

```bash
# Run all tests (default)
python tests/run_tests.py

# Run specific test suites
python tests/run_tests.py unit
python tests/run_tests.py integration
python tests/run_tests.py functional

# Run with additional pytest arguments
python tests/run_tests.py unit -k "test_generate_random_key"
python tests/run_tests.py integration --tb=short

# Show help
python tests/run_tests.py help
```

### Test Coverage

All test runs include:
- pytest-cov with HTML report generation
- Verbose mode (-v)
- Fail fast (-x) to stop on first failure
- **90%+ code coverage** across all modules

### Manual Test Execution

You can also run tests directly with pytest:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=splurge_key_custodian

# Run specific test directories
pytest tests/unit/
pytest tests/integration/
pytest tests/functional/

# Run specific test file
pytest tests/unit/test_crypto_utils.py
```

### Test Categories

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test component interactions and workflows
- **Functional Tests**: Test end-to-end functionality and CLI operations
- **Security Tests**: Test security features and edge cases
<!-- Performance tests for caching removed (legacy). -->

## Development

### Code Style

This project follows PEP 8 and uses:
- Black for code formatting
- Ruff for linting
- MyPy for type checking
- Comprehensive docstrings and type annotations

### Running Examples

```bash
# Run basic usage example
python examples/basic_usage.py

# Run environment variable example
python examples/env_master_password_usage.py

# Run iterations example
python examples/iterations_usage.py

# Run key rotation example
python examples/key_rotation_usage.py
python examples/master_password_change_usage.py
python examples/cli_key_rotation_demo.py
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/splurge/splurge-key-custodian.git
cd splurge-key-custodian

# Install development dependencies
pip install -e ".[dev]"

# Run tests
python tests/run_tests.py

# Run linting
ruff check .

# Run type checking
mypy splurge_key_custodian/
```

<!-- Recent Improvements section removed to avoid legacy feature references. -->

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Security

If you discover a security vulnerability, please report it privately to the maintainers.
