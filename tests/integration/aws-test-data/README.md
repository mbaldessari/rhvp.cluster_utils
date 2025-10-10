# AWS Secrets Manager Integration Test Data

This directory contains test data files for AWS Secrets Manager integration testing using LocalStack.

## Test Files

### values-secret-aws-basic.yaml

Basic AWS Secrets Manager configuration demonstrating:

- Simple secrets with multiple fields
- Default tags and region configuration
- Custom secret names

### values-secret-aws-advanced.yaml

Advanced AWS Secrets Manager configuration demonstrating:

- Secret prefixes and naming
- KMS key configuration
- Automatic rotation settings
- Replication across regions
- Complex field types including certificates

### test-file.txt

Sample text file for testing `file://` field instructions.

### test-config.ini

Sample INI configuration file for testing `ini://` field instructions with multiple sections.

## Usage

These files are used by the integration tests in `test_aws_secrets_integration.py`. The tests will:

1. Start a LocalStack container simulating AWS Secrets Manager
2. Load these configuration files
3. Test secret creation and field value extraction
4. Verify AWS CLI command generation
5. Clean up the LocalStack environment

## Running Tests

To run the AWS integration tests:

```bash
# From the collection root directory
make integration-test-aws

# Or directly
cd tests/integration
python test_aws_secrets_integration.py
```

## Prerequisites

- Docker (for LocalStack)
- AWS CLI
- Python packages: boto3, pyyaml

The tests will automatically skip if Docker or AWS CLI are not available.
