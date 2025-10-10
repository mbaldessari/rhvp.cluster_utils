# Integration Tests

This directory contains integration tests that use a real HashiCorp Vault container to test the vault_load_secrets functionality end-to-end.

## Prerequisites

- Podman
- Python 3.8+
- `requests` and `pyyaml` Python packages

## Quick Start

```bash
# Run integration tests
make integration-test

# Or run all tests (unit + integration)
make test-all
```

## Manual Testing

### Start/Stop Vault Container

```bash
# Start Vault container
./tests/integration/vault-helper.sh start

# Check status
./tests/integration/vault-helper.sh status

# Stop Vault container
./tests/integration/vault-helper.sh stop
```

### Run Individual Tests

```bash
# Install requirements
pip install -r tests/integration/requirements.txt

# Run direct Python module test
cd tests/integration
python test_vault_direct.py

# Run Ansible playbook integration test
cd tests/integration
python test_vault_integration.py
```

## Test Structure

### Files

- `test-values-secret-v3.yaml` - Sample v3.0 values file for testing
- `test_vault_direct.py` - Direct Python module integration test
- `test_vault_integration.py` - Full Ansible playbook integration test
- `test_vault_simple.py` - Basic Vault functionality test
- `vault-helper.sh` - Helper script for container management
- `requirements.txt` - Python dependencies

### Test Configuration

The tests use a Vault container configured with:
- **Address**: `http://localhost:8200`
- **Root Token**: `myroot`
- **Mode**: Development mode (in-memory storage)
- **KV Engine**: v2 enabled at `secret/` path

### What the Tests Verify

1. **Container Setup**: Vault container starts and becomes healthy
2. **Policy Creation**: Password generation policies are created in Vault
3. **Secret Injection**: Secrets are properly injected into Vault paths
4. **Target Handling**: Secrets are created in correct target paths (hub, spoke)
5. **Password Generation**: Generated passwords follow policy constraints
6. **Value Types**: Static values, numbers, and booleans are stored correctly
7. **Target Overrides**: Per-secret target overrides work correctly

### Sample Test Data

The test uses this v3.0 configuration:

```yaml
version: "3.0"
secretstore: "vault"

policies:
  test-basic:
    length: 8
    charset: "alphanumeric"
  test-strong:
    length: 16
    charset: "alphanumeric_symbols"

settings:
  targets: ["hub", "test-spoke"]

secrets:
  integration-test-database:
    username: "test-db-user"
    password: "generate:test-basic"
    host: "localhost"
    port: 5432

  integration-test-api:
    targets: ["hub"]  # Override global targets
    endpoint: "https://api.test.example.com"
    token: "generate:test-strong"
    timeout: 30

  integration-test-static:
    static_value: "this-is-a-test-value"
    number_value: 42
    boolean_value: true
```

## Troubleshooting

### Podman Issues

```bash
# Check if Podman is running
podman info

# Check if containers are running
podman ps

# View Vault logs
./tests/integration/vault-helper.sh logs
```

### Connection Issues

```bash
# Test Vault connection
curl http://localhost:8200/v1/sys/health

# Check Vault status via helper
./tests/integration/vault-helper.sh status
```

### Port Conflicts

If port 8200 is already in use, you can modify the port in the test files by updating the podman run command in the test setup to use a different port:

```bash
# Change from -p "8200:8200" to:
-p "8201:8200"
```

Then update the `VAULT_ADDR` in test files accordingly.

## Make Targets

- `make integration-test-setup` - Install Python dependencies
- `make integration-test` - Run basic integration tests
- `make integration-test-full` - Run all integration tests
- `make test-all` - Run unit tests + integration tests

## CI/CD Considerations

These integration tests require Podman and may not be suitable for all CI environments. Consider:

- Running only on specific branches or tags
- Using conditional execution based on environment variables
- Providing alternative test commands that skip integration tests when Podman is unavailable