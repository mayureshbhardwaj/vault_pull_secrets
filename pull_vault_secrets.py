#!/usr/bin/env python3
"""
HashiCorp Vault Secret Puller
Reads YAML configuration and pulls secrets from Vault based on specified paths.

Features:
- Supports both individual and grouped secret formats
- Auto-detects and handles base64 encoding for binary secrets (JKS, certs, etc.)
- Batch mode for efficient Vault API calls
- Template placeholder replacement ({{ .Environment }}, {{ .Region }})
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

# Azure SDK imports (only used when --direct-push flag is enabled)
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.app import ContainerAppsAPIClient
    from azure.mgmt.app.models import Secret
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


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
            # NOTE: Clear-text storage is required for Container App volume mounting
            # The consuming Container App will read these as environment variables or mounted files
            with open(output_file, 'w') as f:
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

                    # NOTE: Clear-text storage is required for Container App volume mounting
                    output_file = os.path.join(output_dir, key)
                    with open(output_file, 'w') as f:
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


def pull_secrets_to_memory(secrets_config: List[Dict], environment: str, region: str, use_batch: bool = True) -> Dict[str, str]:
    """Pull all secrets from Vault into memory dictionary (no file writes).

    Args:
        secrets_config: Normalized secrets configuration
        environment: Environment name
        region: Region name
        use_batch: Whether to use batch mode for efficiency

    Returns:
        Dictionary mapping secret names to their values
    """
    secrets_dict = {}

    if use_batch:
        # Group secrets by path for batch retrieval
        secrets_by_path = {}
        for secret in secrets_config:
            path = replace_placeholders(secret['path'], environment, region)
            if path not in secrets_by_path:
                secrets_by_path[path] = []
            secrets_by_path[path].append({'name': secret['name'], 'key': secret['key']})

        # Pull each path in batch
        for path, secrets in secrets_by_path.items():
            try:
                cmd = ['vault', 'read', '-format=json', path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)

                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    secret_data = data.get('data', {})

                    for secret in secrets:
                        key = secret['key']
                        name = secret['name']
                        if key in secret_data:
                            secret_value = str(secret_data[key])
                            processed_value, _ = ensure_base64_for_binary(secret_value, name)
                            secrets_dict[name] = processed_value
                        else:
                            print(f"⚠️  Key not found in Vault (hash: {get_secret_hash(name, path)})")
                else:
                    print(f"⚠️  Could not access Vault path (batch operation failed)")
            except Exception as e:
                print(f"❌ Error pulling batch: {e}")
    else:
        # Pull secrets individually
        for secret in secrets_config:
            path = replace_placeholders(secret['path'], environment, region)
            key = secret['key']
            name = secret['name']

            try:
                result = subprocess.run(
                    ['vault', 'read', f'-field={key}', path],
                    capture_output=True,
                    text=True,
                    check=False
                )

                if result.returncode == 0:
                    secret_value = result.stdout
                    processed_value, _ = ensure_base64_for_binary(secret_value, name)
                    secrets_dict[name] = processed_value
                else:
                    print(f"⚠️  Secret not found in Vault (hash: {get_secret_hash(name, path)})")
            except Exception as e:
                print(f"❌ Error pulling secret: {e}")

    return secrets_dict


def push_secrets_to_azure(secrets_dict: Dict[str, str], subscription_id: str,
                          resource_group: str, container_app_name: str) -> bool:
    """Push secrets directly to Azure Container Apps using Azure SDK.

    Args:
        secrets_dict: Dictionary of secret names to values
        subscription_id: Azure subscription ID
        resource_group: Resource group name
        container_app_name: Container app name

    Returns:
        True if successful, False otherwise
    """
    if not AZURE_SDK_AVAILABLE:
        print("❌ Azure SDK not available. Install with: pip install azure-mgmt-app azure-identity")
        return False

    try:
        print("=== Pushing Secrets to Azure Container Apps ===")
        print(f"Subscription: {subscription_id}")
        print(f"Resource Group: {resource_group}")
        print(f"Container App: {container_app_name}")
        print(f"Secret Count: {len(secrets_dict)}")
        print("")

        # Authenticate using DefaultAzureCredential (supports multiple auth methods)
        credential = DefaultAzureCredential()

        # Create Container Apps management client
        client = ContainerAppsAPIClient(credential, subscription_id)

        # Get current container app configuration
        print("📥 Fetching current Container App configuration...")
        container_app = client.container_apps.get(resource_group, container_app_name)

        # Prepare secrets list for Azure (only names and values, no other metadata)
        azure_secrets = []
        for name, value in secrets_dict.items():
            azure_secrets.append(Secret(name=name, value=value))
            print(f"   • Secret prepared (hash: {get_secret_hash(name)})")

        # Update container app secrets (replaces all secrets)
        print("")
        print("📤 Updating Container App secrets...")
        if not container_app.properties.configuration:
            container_app.properties.configuration = {}

        container_app.properties.configuration.secrets = azure_secrets

        # Apply the update
        poller = client.container_apps.begin_create_or_update(
            resource_group_name=resource_group,
            container_app_name=container_app_name,
            container_app_envelope=container_app
        )

        # Wait for the operation to complete
        result = poller.result()

        safe_log_operation("Push to Azure", True, len(secrets_dict))
        print("")
        print(f"✅ Successfully pushed {len(secrets_dict)} secrets to Container App")
        print(f"   Container App: {container_app_name}")
        print(f"   Resource Group: {resource_group}")
        print("")

        return True

    except Exception as e:
        print(f"❌ Error pushing secrets to Azure: {e}")
        return False


def extract_azure_config(config_path: str, environment: str, region: str) -> Dict[str, str]:
    """Extract Azure configuration from environment YAML file.

    Args:
        config_path: Path to config directory
        environment: Environment name
        region: Region name

    Returns:
        Dictionary with app_name, resource_group, subscription_id
    """
    config_file = f"{config_path}/environments/{region}/{environment}.yaml"

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Configuration file not found: {config_file}")

    with open(config_file, 'r') as f:
        config = yaml.safe_load(f) or {}

    # Extract app name
    app_name = config.get('name')
    if not app_name:
        raise ValueError(f"Missing 'name' field in {config_file}")

    # Extract resource group
    resource_group = config.get('global', {}).get('resourceGroup')
    if not resource_group:
        raise ValueError(f"Missing 'global.resourceGroup' field in {config_file}")

    # Extract subscription ID from containerAppEnvironmentId
    env_id = config.get('global', {}).get('containerAppEnvironmentId', '')
    subscription_match = re.search(r'/subscriptions/([^/]+)/', env_id)
    if not subscription_match:
        raise ValueError(f"Could not extract subscription ID from containerAppEnvironmentId in {config_file}")

    subscription_id = subscription_match.group(1)

    return {
        'app_name': app_name,
        'resource_group': resource_group,
        'subscription_id': subscription_id
    }


def main():
    """Main entry point."""
    if len(sys.argv) < 4:
        print("Usage: pull_vault_secrets.py <values_path> <environment> <region> [--batch] [--direct-push] [--output-json]", file=sys.stderr)
        sys.exit(1)

    values_path = sys.argv[1]
    environment = sys.argv[2]
    region = sys.argv[3]
    use_batch = '--batch' in sys.argv
    use_direct_push = '--direct-push' in sys.argv
    output_json = '--output-json' in sys.argv

    # Debug: Show Vault configuration (to stderr so it doesn't interfere with JSON output)
    print("=== Vault Configuration ===", file=sys.stderr)
    print(f"VAULT_ADDR: {os.environ.get('VAULT_ADDR', '(not set)')}", file=sys.stderr)
    print(f"VAULT_NAMESPACE: {os.environ.get('VAULT_NAMESPACE', '(not set)')}", file=sys.stderr)
    print(f"VAULT_TOKEN: {'***' if os.environ.get('VAULT_TOKEN') else '(not set)'}", file=sys.stderr)
    print(f"Environment: {environment}", file=sys.stderr)
    print(f"Region: {region}", file=sys.stderr)
    print("===========================\n", file=sys.stderr)

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

    print(f"\nFound {len(secrets_config)} secrets to pull from Vault", file=sys.stderr)

    # JSON output mode: pull to memory and output as JSON (for in-memory pipeline)
    # This is the RECOMMENDED mode for security - secrets stay in memory, never touch disk
    if output_json:
        print("\n🔒 Using JSON Output Mode (secure in-memory pipeline)", file=sys.stderr)
        print("=" * 50, file=sys.stderr)

        # Pull all secrets into memory (no file writes)
        print("📥 Pulling secrets from Vault to memory...", file=sys.stderr)
        secrets_dict = pull_secrets_to_memory(secrets_config, environment, region, use_batch)

        if not secrets_dict:
            print("❌ No secrets were pulled from Vault", file=sys.stderr)
            sys.exit(1)

        print(f"✅ Pulled {len(secrets_dict)} secrets to memory", file=sys.stderr)
        print("📤 Outputting secrets as JSON to stdout...", file=sys.stderr)

        # Output JSON to stdout (will be captured by GitHub Actions)
        # All debug output goes to stderr, so stdout is clean JSON
        output = {
            "secrets": secrets_dict,
            "count": len(secrets_dict),
            "environment": environment,
            "region": region
        }
        print(json.dumps(output))  # stdout

        print("✅ JSON output completed - NO files created", file=sys.stderr)
        sys.exit(0)

    # Direct push mode: pull to memory and push directly to Azure (NO file writes)
    # WARNING: This fails for first-time deployments (Container App must exist)
    # Use --output-json instead for new deployments
    if use_direct_push:
        print("\n🔒 Using Direct Push Mode (secure, no file storage)")
        print("=" * 50)

        # Extract Azure configuration from the same config file
        try:
            azure_config = extract_azure_config(values_path, environment, region)
            print(f"\n📋 Azure Configuration:")
            print(f"   App Name: {azure_config['app_name']}")
            print(f"   Resource Group: {azure_config['resource_group']}")
            print(f"   Subscription: {azure_config['subscription_id']}")
            print("")
        except Exception as e:
            print(f"❌ Error extracting Azure configuration: {e}")
            sys.exit(1)

        # Pull all secrets into memory (no file writes)
        print("📥 Pulling secrets from Vault to memory...")
        secrets_dict = pull_secrets_to_memory(secrets_config, environment, region, use_batch)

        if not secrets_dict:
            print("❌ No secrets were pulled from Vault")
            sys.exit(1)

        print(f"✅ Pulled {len(secrets_dict)} secrets to memory")
        print("")

        # Push directly to Azure Container Apps
        success = push_secrets_to_azure(
            secrets_dict,
            azure_config['subscription_id'],
            azure_config['resource_group'],
            azure_config['app_name']
        )

        if success:
            print("✅ Direct push completed successfully - NO files created")
            sys.exit(0)
        else:
            print("❌ Direct push failed")
            sys.exit(1)

    # Legacy file-based mode (for backward compatibility)
    # Group secrets by path for batch retrieval
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
