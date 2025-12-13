#!/usr/bin/env python3
"""
HashiCorp Vault Secret Puller
Reads YAML configuration and pulls secrets from Vault based on specified paths.

Features:
- Supports both individual and grouped secret formats
- Auto-detects and handles base64 encoding for binary secrets (JKS, certs, etc.)
- Batch mode for efficient Vault API calls
- Template placeholder replacement ({{ .Environment }}, {{ .Region }})
- Secure hash-based logging (no sensitive data in logs)

Security Model:
- Secrets are pulled from Vault and temporarily stored as files in CI/CD environment
- Files are ephemeral (exist only during GitHub Actions workflow execution ~minutes)
- GitHub Actions runners are destroyed immediately after workflow completion
- Secure logging prevents sensitive data from appearing in logs (uses SHA-256 hashes)
- This is the standard pattern for secret management in CI/CD (Kubernetes, Terraform, etc.)

CodeQL Security Notes:
- File storage is intentionally allowed (required for ARM template parameter injection)
- Files are temporary and exist only in ephemeral, isolated CI/CD runners
- All logging uses hash-based identifiers instead of actual secret names/values
- Attack surface: An attacker would need to compromise the GitHub Actions runner
  DURING the workflow execution (minutes) to access files
"""

import yaml
import subprocess
import sys
import os
import json
import base64
import re
import hashlib
from typing import List, Dict, Optional, Tuple


def is_base64(s: str) -> bool:
    """Check if a string is valid base64 encoded.

    Args:
        s: String to check

    Returns:
        True if string is valid base64, False otherwise
    """
    try:
        # Remove whitespace
        s = s.strip()

        # Base64 strings should only contain these characters
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False

        # Must be multiple of 4 characters
        if len(s) % 4 != 0:
            return False

        # Try to decode
        decoded = base64.b64decode(s, validate=True)

        # Try to encode back and compare
        reencoded = base64.b64encode(decoded).decode('utf-8')

        # If it round-trips, it's valid base64
        return reencoded.strip() == s.strip()
    except Exception:
        return False


def is_likely_binary(data: bytes) -> bool:
    """Check if data is likely binary (not text).

    Args:
        data: Bytes to check

    Returns:
        True if data appears to be binary, False if it's text
    """
    # Check for null bytes (strong indicator of binary)
    if b'\x00' in data:
        return True

    # Check if it's valid UTF-8 text
    try:
        data.decode('utf-8')
        # Additional check: if it decodes but has lots of weird characters
        text = data.decode('utf-8')
        non_printable = sum(1 for c in text if ord(c) < 32 and c not in '\n\r\t')
        if len(text) > 0 and (non_printable / len(text)) > 0.1:
            return True  # More than 10% control chars = likely binary
        return False  # Valid text
    except UnicodeDecodeError:
        return True  # Not valid UTF-8, probably binary


def ensure_base64_for_binary(secret_value: str, secret_name: str) -> Tuple[str, bool]:
    """Ensure binary secrets are base64 encoded for Container Apps.

    Container Apps expect binary files (JKS, certs, etc.) to be base64 encoded
    when stored as secrets and mounted as volumes.

    This function:
    1. Checks if the value is already base64
    2. If not, checks if it's binary data
    3. If binary, encodes it to base64

    Args:
        secret_value: The secret value from Vault
        secret_name: Name of the secret (for logging)

    Returns:
        Tuple of (processed_value, was_encoded)
        - processed_value: The value (base64 encoded if it was binary)
        - was_encoded: True if we encoded it, False if already base64 or is text
    """
    # First, check if it's already base64
    if is_base64(secret_value):
        print(f"   ✅ Already base64 (hash: {get_secret_hash(secret_name)})")
        return secret_value, False

    # Try to interpret as bytes (might be binary from Vault)
    try:
        # Convert string to bytes
        if isinstance(secret_value, str):
            value_bytes = secret_value.encode('latin-1')  # Preserve binary data
        else:
            value_bytes = bytes(secret_value)

        # Check if it's binary data
        if is_likely_binary(value_bytes):
            # Binary data - encode to base64
            encoded = base64.b64encode(value_bytes).decode('utf-8')
            print(f"   🔄 Encoded binary to base64 (hash: {get_secret_hash(secret_name)}, {len(value_bytes)} bytes → {len(encoded)} chars)")
            return encoded, True
        else:
            # Text data - return as-is
            print(f"   📝 Text secret (hash: {get_secret_hash(secret_name)})")
            return secret_value, False

    except Exception as e:
        print(f"   ⚠️  Could not process secret (hash: {get_secret_hash(secret_name)}): {type(e).__name__}")
        return secret_value, False


def replace_placeholders(path: str, environment: str, region: str) -> str:
    """Replace template placeholders in Vault path.

    Args:
        path: Vault path with potential placeholders
        environment: Environment name (dev, staging, production)
        region: Region name (centralus, eastus, etc.)

    Returns:
        Path with placeholders replaced
    """
    path = path.replace('{{ .Environment }}', environment)
    path = path.replace('{{ .Region }}', region)
    return path


def get_secret_hash(secret_name: str, vault_path: str = "") -> str:
    """Generate a hash identifier for logging without exposing secret names.

    Args:
        secret_name: Name of the secret
        vault_path: Optional vault path

    Returns:
        8-character hash identifier
    """
    combined = f"{vault_path}:{secret_name}"
    return hashlib.sha256(combined.encode()).hexdigest()[:8]


def safe_log_operation(operation: str, success: bool, count: int = 1, metadata: Dict = None):
    """Log secret operations with metadata only (no sensitive data).

    Args:
        operation: Operation name (e.g., 'pull', 'push')
        success: Whether operation succeeded
        count: Number of items processed
        metadata: Additional non-sensitive metadata
    """
    meta = metadata or {}
    status = "✅" if success else "❌"
    print(f"{status} {operation}: {count} secret(s) processed", end="")

    if meta:
        details = ", ".join([f"{k}={v}" for k, v in meta.items()])
        print(f" ({details})")
    else:
        print()


def normalize_secrets_config(secrets_config: List[Dict]) -> List[Dict]:
    """Normalize secrets configuration to support both individual and grouped formats.

    Supports two formats:
    1. Individual format (legacy):
       - name: "secret-name"
         path: "vault/path"
         key: "key-name"

    2. Grouped format (new):
       - path: "vault/path"
         keys:
           - "key-name"  # when name == key
           - name: "output-name"
             key: "vault-key"  # when name != key

    Args:
        secrets_config: Raw secrets configuration from YAML

    Returns:
        Normalized list where all secrets are in individual format
    """
    normalized = []

    for secret in secrets_config:
        # Check if this is grouped format (has 'keys' field)
        if 'keys' in secret:
            path = secret.get('path')
            if not path:
                print(f"⚠️  Warning: Grouped secret missing 'path' field")
                continue

            keys = secret.get('keys', [])
            for key_entry in keys:
                # Handle simple string format: keys: ["key1", "key2"]
                if isinstance(key_entry, str):
                    normalized.append({
                        'name': key_entry,
                        'path': path,
                        'key': key_entry
                    })
                # Handle object format: keys: [{name: "name", key: "key"}]
                elif isinstance(key_entry, dict):
                    name = key_entry.get('name')
                    key = key_entry.get('key')
                    if name and key:
                        normalized.append({
                            'name': name,
                            'path': path,
                            'key': key
                        })
                    else:
                        print(f"⚠️  Warning: Invalid key entry in grouped secret config")

        # Individual format (legacy) - just pass through
        elif 'name' in secret and 'path' in secret and 'key' in secret:
            normalized.append(secret)

        else:
            print(f"⚠️  Warning: Invalid secret configuration format")

    return normalized


def pull_secret(path: str, key: str, output_file: str) -> bool:
    """Pull a single secret from Vault using CLI.

    Args:
        path: Vault path (e.g., PROD/secret/api-service/common)
        key: Key within the secret (e.g., jfrog-username)
        output_file: Where to save the secret value

    Returns:
        True if successful, False otherwise
    """
    try:
        # Use 'vault read' for KV v1 (direct API access)
        result = subprocess.run(
            ['vault', 'read', f'-field={key}', path],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            secret_value = result.stdout

            # Auto-detect and handle base64 encoding for binary secrets
            secret_name = os.path.basename(output_file)
            processed_value, was_encoded = ensure_base64_for_binary(secret_value, secret_name)

            # Save secret to file
            # CodeQL[py/clear-text-storage-sensitive-data] - Intentional temporary file storage
            # Justification: Required for ARM template parameter injection in CI/CD pipeline
            # - Files exist only in ephemeral GitHub Actions runner (destroyed after workflow)
            # - Files never persist to permanent storage
            # - Attack window: ~minutes during workflow execution
            # - Standard practice for Kubernetes/Terraform secret handling in CI/CD
            with open(output_file, 'w') as f:  # lgtm[py/clear-text-storage-sensitive-data]
                f.write(processed_value)
            print(f"✅ Pulled secret (hash: {get_secret_hash(secret_name)})")
            return True
        else:
            print(f"⚠️  Secret not found in Vault")
            return False

    except Exception as e:
        print(f"❌ Error pulling secret: {type(e).__name__}")
        return False


def pull_secrets_batch(path: str, keys: List[str], output_dir: str) -> Dict[str, bool]:
    """Pull multiple secrets from same Vault path in one API call.

    Args:
        path: Vault path
        keys: List of keys to extract from the path
        output_dir: Directory to save secrets

    Returns:
        Dictionary mapping key names to success status
    """
    results = {}

    try:
        # Use 'vault read' for KV v1 (direct API access, no mount detection)
        # For KV v2, would use 'vault kv get'
        cmd = ['vault', 'read', '-format=json', path]
        print(f"🔍 Executing batch read from Vault ({len(keys)} secrets)")

        # Get entire secret object at once
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)
            # For KV v1: data is directly in 'data' field (not data.data like v2)
            secret_data = data.get('data', {})

            # Extract each requested key
            for key in keys:
                if key in secret_data:
                    secret_value = str(secret_data[key])

                    # Auto-detect and handle base64 encoding
                    processed_value, was_encoded = ensure_base64_for_binary(secret_value, key)

                    # CodeQL[py/clear-text-storage-sensitive-data] - Intentional temporary file storage
                    # Same justification as pull_secret() - required for ARM template injection
                    output_file = os.path.join(output_dir, key)
                    with open(output_file, 'w') as f:  # lgtm[py/clear-text-storage-sensitive-data]
                        f.write(processed_value)
                    print(f"✅ Pulled secret (hash: {get_secret_hash(key)})")
                    results[key] = True
                else:
                    print(f"⚠️  Key not found in Vault response")
                    results[key] = False
        else:
            print(f"⚠️  Could not access Vault path (batch operation failed)")
            print(f"   Return code: {result.returncode}")
            for key in keys:
                results[key] = False

    except Exception as e:
        print(f"❌ Error pulling batch: {type(e).__name__}")
        for key in keys:
            results[key] = False

    return results


def main():
    """Main entry point."""
    if len(sys.argv) < 4:
        print("Usage: pull_vault_secrets.py <values_path> <environment> <region> [--batch]")
        sys.exit(1)

    values_path = sys.argv[1]
    environment = sys.argv[2]
    region = sys.argv[3]
    use_batch = '--batch' in sys.argv

    # Debug: Show Vault configuration
    print("=== Vault Configuration ===")
    print(f"VAULT_ADDR: {os.environ.get('VAULT_ADDR', '(not set)')}")
    print(f"VAULT_NAMESPACE: {os.environ.get('VAULT_NAMESPACE', '(not set)')}")
    print(f"VAULT_TOKEN: {'***' if os.environ.get('VAULT_TOKEN') else '(not set)'}")
    print(f"Environment: {environment}")
    print(f"Region: {region}")
    print("===========================\n")

    # Create output directory
    os.makedirs('secrets', exist_ok=True)

    # Load single self-contained config file
    # New structure: environments/{region}/{environment}.yaml
    config_file = f"{values_path}/environments/{region}/{environment}.yaml"

    if not os.path.exists(config_file):
        print(f"❌ Configuration file not found: {config_file}")
        print(f"\nExpected structure: {values_path}/environments/{{region}}/{{environment}}.yaml")
        print(f"Example: {values_path}/environments/centralus/production.yaml")
        sys.exit(1)

    print(f"Loading configuration from: {config_file}")

    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"❌ Error reading configuration file: {e}")
        sys.exit(1)

    # Extract vault configuration
    vault_config = config.get('vault', {})
    secrets_config = vault_config.get('secrets', [])

    if not secrets_config:
        print("⚠️  No vault.secrets configuration found in config file")
        print(f"   File: {config_file}")
        print("\nExpected format (individual):")
        print("  vault:")
        print("    secrets:")
        print("      - name: secret-name")
        print("        path: vault/path/to/secret")
        print("        key: key-name")
        print("\nOr grouped format:")
        print("  vault:")
        print("    secrets:")
        print("      - path: vault/path/to/secret")
        print("        keys:")
        print("          - key1")
        print("          - key2")
        sys.exit(0)

    # Normalize secrets config to support both individual and grouped formats
    secrets_config = normalize_secrets_config(secrets_config)

    print(f"\nFound {len(secrets_config)} secrets to pull from Vault")

    # File-based mode: Pull secrets to temporary files for ARM template injection
    # Files are ephemeral (exist only during GitHub Actions workflow execution)
    if use_batch:
        secrets_by_path = {}
        for secret in secrets_config:
            name = secret.get('name')
            path = secret.get('path')
            key = secret.get('key')

            if not all([name, path, key]):
                print(f"⚠️  Skipping invalid secret configuration")
                continue

            # Replace placeholders
            path = replace_placeholders(path, environment, region)

            if path not in secrets_by_path:
                secrets_by_path[path] = []
            secrets_by_path[path].append({'name': name, 'key': key})

        # Pull each path in batch
        success_count = 0
        for path, secrets in secrets_by_path.items():
            keys = [s['key'] for s in secrets]
            results = pull_secrets_batch(path, keys, 'secrets')

            # Rename files from key to name if different
            for secret in secrets:
                if results.get(secret['key'], False):
                    if secret['key'] != secret['name']:
                        os.rename(
                            f"secrets/{secret['key']}",
                            f"secrets/{secret['name']}"
                        )
                    success_count += 1
    else:
        # Pull secrets individually
        success_count = 0
        for secret in secrets_config:
            name = secret.get('name')
            path = secret.get('path')
            key = secret.get('key')

            if not all([name, path, key]):
                print(f"⚠️  Skipping invalid secret configuration")
                continue

            # Replace placeholders in path
            path = replace_placeholders(path, environment, region)

            # Pull secret
            output_file = f"secrets/{name}"
            if pull_secret(path, key, output_file):
                success_count += 1

    print(f"\n✅ Successfully pulled {success_count}/{len(secrets_config)} secrets from Vault")

    if success_count < len(secrets_config):
        print(f"⚠️  Warning: {len(secrets_config) - success_count} secrets failed to pull")
        sys.exit(1)


if __name__ == '__main__':
    main()
