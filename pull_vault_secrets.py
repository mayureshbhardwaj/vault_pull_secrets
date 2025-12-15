#!/bin/bash
#
# Test Vault Secret Pulling Locally
#
# Usage:
#   ./test-vault-locally.sh
#
# Prerequisites:
#   1. Vault CLI installed: brew install vault (macOS) or download from hashicorp.com
#   2. Network access to Vault server (https://eccsm.uhc.com/)
#   3. Valid Vault credentials (role ID and secret ID)
#

set -e

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://eccsm.uhc.com/}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-OPTUM/APP/GP-COMMON-HUB/PROD}"

echo "=== Vault Local Test ==="
echo "VAULT_ADDR: ${VAULT_ADDR}"
echo "VAULT_NAMESPACE: ${VAULT_NAMESPACE}"
echo ""

# Check if vault CLI is installed
if ! command -v vault &> /dev/null; then
    echo "❌ Vault CLI is not installed"
    echo ""
    echo "Install it:"
    echo "  macOS: brew install vault"
    echo "  Linux: Download from https://www.vaultproject.io/downloads"
    echo "  Windows: Download from https://www.vaultproject.io/downloads"
    exit 1
fi

echo "✅ Vault CLI version: $(vault version)"
echo ""

# Set environment variables
export VAULT_ADDR
export VAULT_NAMESPACE

# Check if already authenticated
if [ -n "$VAULT_TOKEN" ]; then
    echo "ℹ️  Using existing VAULT_TOKEN"
else
    echo "ℹ️  No VAULT_TOKEN found"
    echo ""
    echo "To authenticate with AppRole:"
    echo "  export VAULT_ROLE_ID='your-role-id'"
    echo "  export VAULT_SECRET_ID='your-secret-id'"
    echo "  VAULT_TOKEN=\$(vault write -field=token auth/approle/login role_id=\$VAULT_ROLE_ID secret_id=\$VAULT_SECRET_ID)"
    echo "  export VAULT_TOKEN"
    echo ""

    if [ -n "$VAULT_ROLE_ID" ] && [ -n "$VAULT_SECRET_ID" ]; then
        echo "🔐 Authenticating with AppRole..."
        VAULT_TOKEN=$(vault write -field=token auth/approle/login \
            role_id="$VAULT_ROLE_ID" \
            secret_id="$VAULT_SECRET_ID")
        export VAULT_TOKEN
        echo "✅ Authentication successful"
    else
        echo "⚠️  Please set VAULT_ROLE_ID and VAULT_SECRET_ID environment variables"
        exit 1
    fi
fi

echo ""
echo "=== Testing Vault Access ==="
echo ""

# Test paths from dev.yaml
echo "Testing: secret/GPS-CLOUD/dev/frontend"
vault kv get -format=json secret/GPS-CLOUD/dev/frontend || echo "❌ Failed to access"
echo ""

echo "Testing: secret/CICD/JFROG_SAAS"
vault kv get -format=json secret/CICD/JFROG_SAAS || echo "❌ Failed to access"
echo ""

echo "=== Test Complete ==="
echo ""
echo "If you see errors above, check:"
echo "  1. VAULT_NAMESPACE is correct (currently: ${VAULT_NAMESPACE})"
echo "  2. Your AppRole has access to these paths"
echo "  3. The paths exist in Vault"
echo "  4. You're using the correct KV engine version (v1 vs v2)"
