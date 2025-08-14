# Splurge Key Custodian - File Based

A secure file-based key management system that stores cryptographic keys in JSON files with atomic key rotation capabilities.

## Features

- **Hybrid file-based storage**: Uses separate credential files and a central index for optimal performance and recovery
- **Atomic operations**: All file operations create temporary files, then atomically replace originals
- **Secure encryption**: All credentials are encrypted with Fernet (AES-256-CBC with HMAC-SHA256) using a master password with 64-byte salt and configurable iterations (default: 1,000,000, minimum: 100,000)
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

# Initialize the key custodian with default iterations (1,000,000)
custodian = KeyCustodian(
    master_password="A very long passphrase of at least 32 characters",
    data_dir="/path/to/credentials"
)

# Or initialize with custom iterations (minimum 100,000)
custodian = KeyCustodian(
    master_password="A very long passphrase of at least 32 characters",
    data_dir="/path/to/credentials",
    iterations=100000
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

### Command Line Interface

```bash
# Save credentials with master password
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data save -n "My Account" \
  -c '{"username": "user", "password": "pass"}'

# Save credentials with environment master password
python -m splurge_key_custodian -ep SPLURGE_MASTER_PASSWORD -d /path/to/data save -n "My Account" \
  -c '{"username": "user", "password": "pass"}'

# Read credentials
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data read -n "My Account"

# List all credentials
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data list

# Validate master password
python -m splurge_key_custodian -p "my-master-password" -d /path/to/data master

# Base58 encode/decode (requires --advanced flag)
python -m splurge_key_custodian --advanced base58 -e "Hello, World!"
python -m splurge_key_custodian --advanced base58 -d "JxF12TrwUP45BMd"
python -m splurge_key_custodian --advanced base58 -g
```

## Configuration

Configuration has been simplified. Iteration and password requirements are enforced internally.

<!-- Configuration Options removed (legacy). -->

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
- `iterations`: Number of iterations for key derivation (default: 1,000,000, minimum: 100,000)

**Password Requirements:**
- **Minimum length**: 32 characters

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
