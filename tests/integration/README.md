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

#### Vault Integration Tests
- `test-values-secret-v3.yaml` - Sample v3.0 values file for testing
- `test_vault_direct.py` - Direct Python module integration test
- `test_vault_integration.py` - Full Ansible playbook integration test
- `test_vault_simple.py` - Basic Vault functionality test
- `test_vault_error_integration.py` - Error handling integration test

#### AWS Integration Tests
- `test_aws_secrets_integration.py` - AWS Secrets Manager integration tests using LocalStack
- `aws-test-data/` - Test data directory with sample AWS configuration files

#### Kubernetes Integration Tests
- `test_kubernetes_integration.py` - Kubernetes secretstore integration tests using Kind
- `test-values-secret-v3-kubernetes.yaml` - Sample v3.0 values file for Kubernetes testing

#### Common Files
- `requirements.txt` - Python dependencies for all integration tests

### Test Configuration

**Container Management**: All integration tests automatically manage their own containers using direct Python subprocess calls. Each test suite starts and stops its own containers, so no manual container management or shell scripts are required.

#### Vault Test Configuration
The Vault tests use a Vault container configured with:
- **Address**: `http://localhost:8200`
- **Root Token**: `myroot`
- **Mode**: Development mode (in-memory storage)
- **KV Engine**: v2 enabled at `secret/` path

#### AWS Test Configuration
The AWS tests use LocalStack to simulate AWS Secrets Manager:
- **Address**: `http://localhost:4566`
- **Container**: `localstack/localstack:latest`
- **Services**: AWS Secrets Manager enabled
- **Mode**: Development mode (no persistence)

#### Kubernetes Test Configuration
The Kubernetes tests use Kind (Kubernetes in Docker):
- **Cluster Name**: `vault-secrets-test`
- **Tool**: `kind` command-line tool
- **Namespaces**: Automatically creates test namespaces (test-namespace, production, test-secrets)
- **Kubeconfig**: Temporary kubeconfig file for testing

### What the Tests Verify

#### Vault Test Scenarios
1. **Container Setup**: Vault container starts and becomes healthy
2. **Policy Creation**: Password generation policies are created in Vault
3. **Secret Injection**: Secrets are properly injected into Vault paths
4. **Target Handling**: Secrets are created in correct target paths (hub, spoke)
5. **Password Generation**: Generated passwords follow policy constraints
6. **Value Types**: Static values, numbers, and booleans are stored correctly
7. **Target Overrides**: Per-secret target overrides work correctly
8. **Error Handling**: Missing optional files are handled gracefully

#### AWS Test Scenarios
1. **LocalStack Setup**: LocalStack container starts and Secrets Manager becomes available
2. **AWS CLI Integration**: AWS CLI commands work with LocalStack endpoint
3. **Secret Creation**: Secrets are properly created in AWS Secrets Manager format
4. **Field Processing**: File and INI field instructions are processed correctly
5. **Optional Fields**: Missing optional files don't cause test failures
6. **Metadata Handling**: Secret names, descriptions, and tags are applied correctly

#### Kubernetes Test Scenarios
1. **Kind Cluster Setup**: Kind cluster starts and becomes ready
2. **Namespace Creation**: Required test namespaces are created automatically
3. **Secret Creation**: Kubernetes secrets are created with correct data and metadata
4. **Multi-Namespace**: Secrets are created in multiple namespaces as specified
5. **Secret Types**: Different Kubernetes secret types (Opaque, basic-auth) work correctly
6. **Labels and Annotations**: Secret metadata is applied correctly

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

### Container Runtime Issues

```bash
# Check if Docker/Podman is running (Vault tests use Podman, others use Docker)
podman info
docker info

# Check if containers are running
podman ps    # For Vault tests
docker ps    # For AWS/K8s tests

# View container logs
podman logs vault-test      # Vault integration tests
docker logs localstack-test # AWS integration tests
```

### Service-Specific Issues

**Vault Connection Issues:**
```bash
# Test Vault connection
curl http://localhost:8200/v1/sys/health

# Check Vault container status
podman ps -f name=vault-test
```

**AWS/LocalStack Issues:**
```bash
# Test LocalStack connection
curl http://localhost:4566/_localstack/health

# Check LocalStack container status
docker ps -f name=localstack-test

# Test AWS CLI connectivity
aws secretsmanager list-secrets --endpoint-url http://localhost:4566
```

**Kubernetes/Kind Issues:**
```bash
# Check if Kind is available
kind --version

# List Kind clusters
kind get clusters

# Check cluster status
kubectl cluster-info --context kind-vault-secrets-test
```

### Port Conflicts

If default ports are already in use, you can modify them in the test files:

- **Vault (8200)**: Update `cls.vault_addr` in test classes
- **LocalStack (4566)**: Update `cls.localstack_port` in AWS test classes
- **Kind**: Uses random ports for API server, no conflicts expected

## Make Targets

- `make integration-test-setup` - Install Python dependencies
- `make integration-test` - Run basic integration tests
- `make integration-test-full` - Run all integration tests
- `make test-all` - Run unit tests + integration tests

## CI/CD Considerations

These integration tests require container runtimes and may not be suitable for all CI environments:

### Prerequisites by Test Suite
- **Vault tests**: Require Podman
- **AWS tests**: Require Docker and AWS CLI
- **Kubernetes tests**: Require Docker, Kind, and kubectl

### CI Environment Considerations
- Running only on specific branches or tags
- Using conditional execution based on environment variables
- Providing alternative test commands that skip integration tests when required tools are unavailable
- Each test suite automatically checks for required dependencies and skips if unavailable

### Example CI Skip Logic
```python
# Tests automatically skip if prerequisites are missing
try:
    subprocess.run(["podman", "--version"], capture_output=True, check=True)
except (subprocess.CalledProcessError, FileNotFoundError):
    print("Podman is not available. Skipping integration tests.")
    sys.exit(0)
```