# Splurge Key Custodian CLI

A command-line interface for the Splurge Key Custodian File system, providing secure credential management with encryption and decryption capabilities.

## Features

- **Secure Credential Storage**: Store credentials encrypted with a master password
- **Master Password Support**: Use plain text or Base58-encoded environment variable
- **JSON Output**: All commands return structured JSON responses
- **Comprehensive Error Handling**: Detailed error messages with proper exit codes
- **Base58 Encoding**: Built-in Base58 encoding utility

## Installation

The CLI is part of the Splurge Key Custodian File package. Ensure you have the package installed:

```bash
pip install -e .
```

## Usage

You can run the CLI in two ways:

### Method 1: Direct CLI Script (Recommended)
```bash
python cli.py [options] [command]
```

### Method 2: Module Execution
```bash
python -m splurge_key_custodian.cli [options] [command]
```

### Global Options

All commands (except `base58`) require authentication and a data directory:

- `-p, --password`: Master password for encryption/decryption
- `-ep, --env-password`: Use master password from `MASTER_PASSWORD` environment variable (Base58 encoded)
- `-d, --data-dir`: Data directory for storing key files
- `-i, --iterations`: Number of iterations for key derivation (minimum: 100,000, default: 1,000,000)

**Note**: You must specify either `-p` or `-ep`, but not both.

### Commands

#### 1. Save Credentials (`save`)

Store encrypted credentials with metadata.

**Required Arguments:**
- `-n, --name`: Name for the credential entry
- `-c, --credentials`: JSON string containing credential data

**Optional Arguments:**
- `-m, --meta-data`: JSON string containing metadata (default: `{}`)

**Example:**
```bash
# Save with master password
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d /path/to/data save \
  -n "My Account" \
  -c '{"username": "user", "password": "pass"}' \
  -m '{"service": "web", "notes": "primary account"}'

# Save with environment password
export MASTER_PASSWORD="JxF12TrwUP45BMd"  # Base58 encoded
python cli.py -ep -d /path/to/data save \
  -n "My Account" \
  -c '{"username": "user", "password": "pass"}'

# Save with custom iterations
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d /path/to/data -i 100000 save \
  -n "My Account" \
  -c '{"username": "user", "password": "pass"}'
```

**Response:**
```json
{
  "success": true,
  "key_id": "e1d271d9-a0fe-43b9-ae2d-8a002a1510c5",
  "name": "My Account",
  "message": "Credential 'My Account' saved successfully"
}
```

#### 2. Read Credentials (`read`)

Retrieve and decrypt credentials by name.

**Required Arguments:**
- `-n, --name`: Name of the credential entry to read

**Example:**
```bash
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d /path/to/data read -n "My Account"
```

**Response:**
```json
{
  "success": true,
  "key_id": "e1d271d9-a0fe-43b9-ae2d-8a002a1510c5",
  "name": "My Account",
  "credentials": {
    "username": "user",
    "password": "pass"
  },
  "meta_data": {
    "service": "web",
    "notes": "primary account"
  }
}
```

#### 3. List Credentials (`list`)

List all credential entry names.

**Example:**
```bash
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d /path/to/data list
```

**Response:**
```json
{
  "success": true,
  "count": 2,
  "names": [
    "My Account",
    "API Production"
  ]
}
```

#### 4. Validate Master Password (`master`)

Validate the master password and get system information.

**Example:**
```bash
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d /path/to/data master
```

**Response:**
```json
{
  "success": true,
  "master_key_id": "7259bc82-5a35-457d-9756-fb2e48a682db",
  "credential_count": 2,
  "message": "Master password validated successfully"
}
```

#### 5. Base58 Encode/Decode (`base58`)

Encode plaintext to Base58 format, decode Base58 to plaintext, or generate cryptographically secure random strings.

**Required Arguments:**
- `--encode`: Plaintext string to encode to Base58, OR
- `--decode`: Base58 string to decode to plaintext, OR
- `--generate`: Generate a 32-character cryptographically random Base58-like string

**Examples:**
```bash
# Encode plaintext to Base58
python cli.py -x base58 -e "Hello World"

# Decode Base58 to plaintext
python cli.py -x base58 -d "JxF12TrwUP45BMd"

# Generate a 32-character cryptographically random Base58-like string
python cli.py -x base58 -g 32
```

**Encode Response:**
```json
{
  "success": true,
  "operation": "encode",
  "plaintext": "Hello World",
  "base58": "JxF12TrwUP45BMd"
}
```

**Decode Response:**
```json
{
  "success": true,
  "operation": "decode",
  "base58": "JxF12TrwUP45BMd",
  "plaintext": "Hello World"
}
```

**Generate Response:**
The generate command outputs the random string directly to stdout (not JSON):
```
d2JCZ.MVcg3it]zKc_s9vjhsvy3o3Kmp
```

**Note:** The generated string is a 32-character "Base58-like" string that includes:
- 7 uppercase letters (A-Z, excluding O)
- 17 lowercase letters (a-z, excluding l) 
- 3 special characters (!@#$%^&*()_+-=[],.?;)
- 5 numeric characters (1-9, excluding 0)
- All characters are cryptographically shuffled for security

## Environment Password Setup

To use the environment password feature:

1. **Encode your master password:**
   ```bash
   python cli.py -x base58 -e "YourSecureMasterPasswordWithComplexity123!@#"
   ```

2. **Set the environment variable:**
   ```bash
   export MASTER_PASSWORD="JxF12TrwUP45BMd"  # Use the output from step 1
   ```

3. **Use the CLI with `-ep` flag:**
   ```bash
   python cli.py -ep -d /path/to/data list
   ```

## Error Handling

All commands return JSON responses with consistent error formatting:

**Success Response:**
```json
{
  "success": true,
  "data": "..."
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "Error description",
  "message": "User-friendly message"
}
```

**Common Error Scenarios:**

1. **Wrong Master Password:**
   ```json
   {
     "success": false,
     "error": "Failed to decrypt master key: Decryption failed",
     "message": "Failed to read credential 'My Account'"
   }
   ```

2. **Missing Required Arguments:**
   ```json
   {
     "success": false,
     "error": "Either -p/--password or -ep/--env-password must be specified",
     "message": "Validation error"
   }
   ```

3. **Invalid JSON:**
   ```json
   {
     "success": false,
     "error": "Invalid JSON in credentials: Expecting value: line 1 column 1 (char 0)",
     "message": "Failed to save credential 'Test'"
   }
   ```

4. **Credential Not Found:**
   ```json
   {
     "success": false,
     "error": "Credential with name 'NonExistent' not found",
     "message": "Failed to read credential 'NonExistent'"
   }
   ```

## Exit Codes

- `0`: Success
- `1`: Error (validation, encryption, file operation, etc.)

## Master Password Requirements

The master password must meet the following complexity requirements:

- **Length**: From 32 to 512 characters long
- **Character Classes**: Must contain at least one character from each of the following classes:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Symbols (!@#$%^&*_+-=[];,.?)

**Valid Password Examples:**
- `"MySecureMasterPasswordWithComplexity123!@#"`
- `"ThisIsAValidTestPasswordWithAllRequirements123!@#"`

**Invalid Password Examples:**
- `"short"` (too short, missing character classes)
- `"MySecurePasswordWithoutNumbers"` (missing numbers and symbols)
- `"mysecurepasswordwithnumbers123"` (missing uppercase and symbols)

## Security Considerations

1. **Master Password**: Keep your master password secure and never share it. Ensure it meets the complexity requirements above.
2. **Environment Variables**: When using environment passwords, ensure the environment variable is not logged or exposed
3. **Data Directory**: Ensure the data directory has appropriate permissions
4. **JSON Input**: Be careful with JSON input to avoid injection attacks
5. **Temporary Files**: The system creates temporary files during operations; ensure they're cleaned up
6. **Key Derivation Iterations**: The iterations parameter controls the computational cost of key derivation. Higher values provide better security but slower performance. The minimum of 100,000 iterations provides a good balance for testing and fast usage.

## Examples

### Complete Workflow

```bash
# 1. Create a data directory
mkdir -p ~/.key-custodian

# 2. Save a credential
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d ~/.key-custodian save \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secure123", "email": "john@example.com"}' \
  -m '{"service": "github", "notes": "Primary GitHub account"}'

# 2a. Save a credential with custom iterations (optional)
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d ~/.key-custodian -i 100000 save \
  -n "GitHub Account" \
  -c '{"username": "johndoe", "password": "secure123", "email": "john@example.com"}' \
  -m '{"service": "github", "notes": "Primary GitHub account"}'

# 3. List all credentials
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d ~/.key-custodian list

# 4. Read a specific credential
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d ~/.key-custodian read -n "GitHub Account"

# 5. Validate the setup
python cli.py -p "MySecureMasterPasswordWithComplexity123!@#" -d ~/.key-custodian master
```

### Using Environment Password

```bash
# 1. Encode your password
python cli.py base58 -e "MySecureMasterPasswordWithComplexity123!@#"

# 2. Set environment variable (use the base58 output)
export MASTER_PASSWORD="JxF12TrwUP45BMd"

# 3. Use CLI without password parameter
python cli.py -ep -d ~/.key-custodian list
```

## Testing

Run the test script to see all functionality in action:

```bash
python test_cli.py
```

This will demonstrate all commands with proper examples and error handling. 