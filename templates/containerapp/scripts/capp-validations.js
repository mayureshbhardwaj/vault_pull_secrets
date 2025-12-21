#!/usr/bin/env node

/**
 * Container App Pipeline Validations
 *
 * Validates Container App configuration files during CI/CD pipelines.
 * - vitals.yaml: Contains only metadata.projectKey
 * - containerapp/config/environments/{region}/{env}.yaml: Contains app, global, and vault sections
 */

const fs = require('fs');

/**
 * Get nested object value using dot notation path
 * @param {Object} obj - Source object
 * @param {string} path - Dot-notation path (e.g., "metadata.projectKey")
 * @returns {*} Value at path or undefined
 */
function getNested(obj, path) {
  return path.split('.').reduce((o, key) => (o && o[key] !== undefined ? o[key] : undefined), obj);
}

/**
 * Validate and detect environment configuration
 * For Container Apps, we check if the environment config file exists
 *
 * @param {string} environment - Environment to validate (dev/nonprod, stage, prod)
 */
function validateEnv(environment) {
  // Normalize 'nonprod' to 'dev' for Container Apps
  let normalizedEnv = environment;
  if (environment === 'nonprod') {
    normalizedEnv = 'dev';
    console.warn("::warning title=Environment Normalization::Using 'dev' environment (nonprod mapped to dev)");
  }

  const validEnvironments = ['dev', 'stage', 'prod'];

  if (!validEnvironments.includes(normalizedEnv)) {
    console.error(`❌ Invalid environment: ${environment}. Must be one of: ${validEnvironments.join(', ')}`);
    process.exit(1);
  }

  console.log(`✅ Using environment: ${normalizedEnv}`);
  console.log(`DETECTED_ENV_NAME=${normalizedEnv}`);

  // Write to GitHub Actions output
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `DETECTED_ENV_NAME=${normalizedEnv}\n`);
  }
}

/**
 * Validate mandatory fields in vitals.yaml
 *
 * @param {string} jsonString - JSON string of vitals.yaml content
 * @param {string} keysArg - Comma-separated list of required keys (dot notation)
 * @param {string} label - Label for error messages
 * @param {string} shouldValidate - "true" to enable validation
 */
function validateMandatory(jsonString, keysArg, label, shouldValidate) {
  if (shouldValidate !== 'true') {
    console.log(`⏭️  Skipping ${label} validation (disabled)`);
    return;
  }

  if (!jsonString || jsonString.trim() === '') {
    console.error(`❌ ${label}: No data provided for validation`);
    process.exit(1);
  }

  let json;
  try {
    json = JSON.parse(jsonString);
  } catch (err) {
    console.error(`❌ ${label}: Invalid JSON - ${err.message}`);
    process.exit(1);
  }

  const keys = keysArg.split(',').map(k => k.trim()).filter(k => k);
  const missing = [];

  console.log(`🔍 Validating ${label}...`);

  for (const key of keys) {
    // Support environment variable replacement in key paths
    const resolvedKey = key
      .replace('ENV_NAME', process.env.DETECTED_ENV_NAME || 'dev');

    const value = getNested(json, resolvedKey);

    if (value === undefined || value === null || value === '') {
      missing.push(resolvedKey);
      console.log(`  ❌ Missing: ${resolvedKey}`);
    } else {
      console.log(`  ✅ Found: ${resolvedKey} = ${typeof value === 'object' ? JSON.stringify(value) : value}`);
    }
  }

  if (missing.length > 0) {
    console.error(`\n❌ ${label} validation failed!`);
    console.error(`Missing required fields: ${missing.join(', ')}`);
    process.exit(1);
  }

  console.log(`✅ ${label} validation passed - all ${keys.length} required fields present\n`);
}

/**
 * Validate vitals.yaml structure
 * For Container Apps, vitals.yaml only contains metadata.projectKey
 *
 * @param {string} jsonString - JSON string of vitals.yaml content
 * @param {string} shouldValidate - "true" to enable validation
 */
function validateVitalsYaml(jsonString, shouldValidate) {
  if (shouldValidate !== 'true') {
    console.log(`⏭️  Skipping vitals.yaml structure validation (disabled)`);
    return;
  }

  if (!jsonString || jsonString.trim() === '') {
    console.error(`❌ Vitals.yaml validation: No data provided`);
    process.exit(1);
  }

  let vitals;
  try {
    vitals = JSON.parse(jsonString);
  } catch (err) {
    console.error(`❌ Vitals.yaml validation: Invalid JSON - ${err.message}`);
    process.exit(1);
  }

  console.log(`🔍 Validating vitals.yaml structure...`);

  const errors = [];

  // Check for metadata section
  if (!vitals.metadata || typeof vitals.metadata !== 'object') {
    errors.push('Missing or invalid "metadata" section');
  } else {
    // Check required metadata fields
    if (!vitals.metadata.projectKey) {
      errors.push('metadata.projectKey is required');
    } else {
      console.log(`  ✅ Found metadata.projectKey: ${vitals.metadata.projectKey}`);
    }
  }

  if (errors.length > 0) {
    console.error(`\n❌ Vitals.yaml validation failed!`);
    errors.forEach(err => console.error(`  - ${err}`));
    process.exit(1);
  }

  console.log(`✅ Vitals.yaml validation passed\n`);
}

/**
 * Validate Container App environment configuration structure
 * These configs are in containerapp/config/environments/{region}/{env}.yaml
 *
 * @param {string} jsonString - JSON string of containerapp config content
 * @param {string} shouldValidate - "true" to enable validation
 */
function validateContainerAppConfig(jsonString, shouldValidate) {
  if (shouldValidate !== 'true') {
    console.log(`⏭️  Skipping container app config validation (disabled)`);
    return;
  }

  if (!jsonString || jsonString.trim() === '') {
    console.error(`❌ Container app config validation: No data provided`);
    process.exit(1);
  }

  let config;
  try {
    config = JSON.parse(jsonString);
  } catch (err) {
    console.error(`❌ Container app config validation: Invalid JSON - ${err.message}`);
    process.exit(1);
  }

  console.log(`🔍 Validating container app configuration structure...`);

  const errors = [];

  // Check for global section (resource configuration)
  if (!config.global || typeof config.global !== 'object') {
    errors.push('Missing or invalid "global" section');
  } else {
    console.log(`  ✅ Found global section`);
    if (config.global.resourceGroup) {
      console.log(`  ✅ Found global.resourceGroup: ${config.global.resourceGroup}`);
    }
    if (config.global.containerAppEnvironmentId) {
      console.log(`  ✅ Found global.containerAppEnvironmentId`);
    }
  }

  // Check for app section (Container App specific)
  if (!config.app || typeof config.app !== 'object') {
    errors.push('Missing or invalid "app" section (required for Container Apps)');
  } else {
    console.log(`  ✅ Found app section`);

    // Check for common Container App fields
    if (config.app.name) {
      console.log(`  ✅ Found app.name: ${config.app.name}`);
    } else {
      errors.push('app.name is required');
    }

    if (config.app.containers) {
      console.log(`  ✅ Found app.containers (${Array.isArray(config.app.containers) ? config.app.containers.length : 'invalid'} containers)`);
    } else {
      errors.push('app.containers is required');
    }
  }

  // Check for vault section (optional but recommended)
  if (config.vault && typeof config.vault === 'object') {
    console.log(`  ✅ Found vault section`);
    if (config.vault.secrets) {
      console.log(`  ✅ Found vault.secrets (${Array.isArray(config.vault.secrets) ? config.vault.secrets.length : 'invalid'} secret paths)`);
    }
  }

  if (errors.length > 0) {
    console.error(`\n❌ Container app config validation failed!`);
    errors.forEach(err => console.error(`  - ${err}`));
    process.exit(1);
  }

  console.log(`✅ Container app config validation passed\n`);
}

/**
 * Validate that sensitive secret names are properly structured
 * Container Apps should use Azure Key Vault references, not inline secrets
 * This validates secrets in the container app config (not vitals.yaml)
 *
 * @param {string} jsonString - JSON string of containerapp config content
 * @param {string} shouldValidate - "true" to enable validation
 */
function validateSecretReferences(jsonString, shouldValidate) {
  if (shouldValidate !== 'true') {
    console.log(`⏭️  Skipping secret reference validation (disabled)`);
    return;
  }

  if (!jsonString || jsonString.trim() === '') {
    console.log(`⏭️  No data for secret reference validation`);
    return;
  }

  let config;
  try {
    config = JSON.parse(jsonString);
  } catch (err) {
    console.error(`❌ Secret reference validation: Invalid JSON - ${err.message}`);
    process.exit(1);
  }

  console.log(`🔍 Validating secret references...`);

  const warnings = [];
  const secrets = config.app?.secrets || [];

  if (!Array.isArray(secrets)) {
    console.error(`❌ app.secrets must be an array`);
    process.exit(1);
  }

  for (const secret of secrets) {
    if (!secret.name) {
      console.error(`❌ Secret missing required "name" field`);
      process.exit(1);
    }

    // Check if using Key Vault reference (recommended)
    if (secret.keyVaultUrl) {
      console.log(`  ✅ ${secret.name} - Uses Key Vault reference (recommended)`);
    } else if (secret.value) {
      // Inline value - should only be used for non-sensitive data
      warnings.push(`${secret.name} - Uses inline value (not recommended for sensitive data)`);
    } else {
      console.log(`  ℹ️  ${secret.name} - Will be populated at runtime`);
    }
  }

  if (warnings.length > 0) {
    console.warn(`\n⚠️  Secret reference warnings:`);
    warnings.forEach(w => console.warn(`  - ${w}`));
    console.warn(`Consider using Azure Key Vault references for sensitive data\n`);
  }

  console.log(`✅ Secret reference validation completed (${secrets.length} secrets checked)\n`);
}

/**
 * Display usage information
 */
function showUsage() {
  console.log(`
Container App Pipeline Validations

Usage:
  node capp-validations.js <command> [arguments]

Commands:
  validate-env <environment>
    Validate environment name (dev/nonprod, stage, prod)
    Example: node capp-validations.js validate-env dev

  validate-vitals
    Validate vitals.yaml (contains only metadata.projectKey)
    Requires environment variables:
      - PIPELINE_DATA_VITALS: JSON string of vitals.yaml
      - ARGS_VITALS: Comma-separated list of required fields (optional)
      - DO_VALIDATE_VITALS: "true" to enable field validation (optional)
      - DO_VALIDATE_STRUCTURE: "true" to validate structure (optional, defaults to true)

    Example:
      export PIPELINE_DATA_VITALS='{"metadata":{"projectKey":"myapp"}}'
      export ARGS_VITALS="metadata.projectKey"
      export DO_VALIDATE_VITALS="true"
      node capp-validations.js validate-vitals

  validate-containerapp-config
    Validate container app environment config files
    (containerapp/config/environments/{region}/{env}.yaml)
    Requires environment variables:
      - PIPELINE_DATA_CAPP_CONFIG: JSON string of containerapp config
      - ARGS_CAPP_CONFIG: Comma-separated list of required fields (optional)
      - DO_VALIDATE_CAPP_CONFIG: "true" to enable field validation (optional)
      - DO_VALIDATE_CAPP_STRUCTURE: "true" to validate structure (optional, defaults to true)
      - DO_VALIDATE_SECRETS: "true" to validate secrets (optional)

    Example:
      export PIPELINE_DATA_CAPP_CONFIG='{"app":{"name":"myapp"},"global":{"resourceGroup":"rg-myapp"}}'
      export ARGS_CAPP_CONFIG="app.name,global.resourceGroup"
      export DO_VALIDATE_CAPP_CONFIG="true"
      node capp-validations.js validate-containerapp-config

Environment Variables:
  DETECTED_ENV_NAME - Detected environment (set by validate-env)
  GITHUB_OUTPUT - GitHub Actions output file (auto-detected)
  `);
}

// Main execution
const [,, command, ...args] = process.argv;

try {
  switch (command) {
    case 'validate-env':
      if (!args[0]) {
        console.error('❌ Error: Environment argument required');
        console.log('Usage: node capp-validations.js validate-env <environment>');
        process.exit(1);
      }
      validateEnv(args[0]);
      break;

    case 'validate-vitals':
      console.log('=== Vitals.yaml Validation ===\n');

      // Validate required fields in vitals.yaml
      validateMandatory(
        process.env.PIPELINE_DATA_VITALS || '',
        process.env.ARGS_VITALS || '',
        'vitals.yaml',
        process.env.DO_VALIDATE_VITALS || 'false'
      );

      // Validate vitals.yaml structure (only metadata.projectKey)
      validateVitalsYaml(
        process.env.PIPELINE_DATA_VITALS || '',
        process.env.DO_VALIDATE_STRUCTURE || 'true'
      );

      console.log('=== ✅ Vitals.yaml validation passed ===\n');
      break;

    case 'validate-containerapp-config':
      console.log('=== Container App Configuration Validation ===\n');

      // Validate required fields in container app config
      validateMandatory(
        process.env.PIPELINE_DATA_CAPP_CONFIG || '',
        process.env.ARGS_CAPP_CONFIG || '',
        'Container App Config',
        process.env.DO_VALIDATE_CAPP_CONFIG || 'false'
      );

      // Validate container app config structure
      validateContainerAppConfig(
        process.env.PIPELINE_DATA_CAPP_CONFIG || '',
        process.env.DO_VALIDATE_CAPP_STRUCTURE || 'true'
      );

      // Validate secret references in container app config
      validateSecretReferences(
        process.env.PIPELINE_DATA_CAPP_CONFIG || '',
        process.env.DO_VALIDATE_SECRETS || 'false'
      );

      console.log('=== ✅ Container app config validation passed ===\n');
      break;

    // Legacy command for backward compatibility
    case 'validate-fields':
      console.warn('⚠️  Warning: "validate-fields" is deprecated. Use "validate-vitals" or "validate-containerapp-config" instead.\n');
      console.log('=== Vitals.yaml Validation (Legacy) ===\n');

      validateMandatory(
        process.env.PIPELINE_DATA_VITALS || '',
        process.env.ARGS_VITALS || '',
        'vitals.yaml',
        process.env.DO_VALIDATE_VITALS || 'false'
      );

      validateVitalsYaml(
        process.env.PIPELINE_DATA_VITALS || '',
        process.env.DO_VALIDATE_STRUCTURE || 'true'
      );

      console.log('=== ✅ Validation passed ===\n');
      break;

    case 'help':
    case '--help':
    case '-h':
      showUsage();
      break;

    default:
      if (!command) {
        console.error('❌ Error: No command specified\n');
      } else {
        console.error(`❌ Error: Unknown command '${command}'\n`);
      }
      showUsage();
      process.exit(1);
  }
} catch (err) {
  console.error(`\n❌ Validation failed: ${err.message}`);
  if (err.stack && process.env.DEBUG === 'true') {
    console.error(err.stack);
  }
  process.exit(1);
}
