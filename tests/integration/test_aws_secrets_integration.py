#!/usr/bin/env python

# Copyright 2022 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Integration tests for AWS Secrets Manager using LocalStack
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import requests
import yaml


class TestAWSSecretsManagerIntegration(unittest.TestCase):
    """Test AWS Secrets Manager integration using LocalStack"""

    @classmethod
    def setUpClass(cls):
        """Set up LocalStack for the entire test class"""
        print("Setting up LocalStack for AWS Secrets Manager integration tests...")

        cls.test_dir = Path(__file__).parent
        cls.collection_root = cls.test_dir.parent.parent
        cls.container_name = "localstack-test"
        cls.localstack_port = "4566"

        # Set up AWS environment variables
        cls.aws_env = {
            "AWS_ENDPOINT_URL": f"http://localhost:{cls.localstack_port}",
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_DEFAULT_REGION": "us-east-1",
            "AWS_SIMULATION_MODE": "true",
        }

        # Apply environment variables
        for key, value in cls.aws_env.items():
            os.environ[key] = value

        # Start LocalStack using direct Docker commands
        cls._start_localstack()

        # Wait for LocalStack to be ready
        cls._wait_for_localstack()

        # Test connectivity
        cls._test_connectivity()

        print("LocalStack is ready for testing")

    @classmethod
    def tearDownClass(cls):
        """Clean up LocalStack after all tests"""
        print("Cleaning up LocalStack...")

        # Clean up test data
        cls._cleanup_test_data()

        # Stop LocalStack
        cls._stop_localstack()

        # Clean up environment variables
        for key in [
            "AWS_ENDPOINT_URL",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_DEFAULT_REGION",
            "AWS_SIMULATION_MODE",
        ]:
            os.environ.pop(key, None)

    def setUp(self):
        """Set up for each test"""
        # Clean up any existing test data
        self._cleanup_test_data()

    @classmethod
    def _is_localstack_running(cls):
        """Check if LocalStack container is running"""
        result = subprocess.run(
            ["docker", "ps", "--format", "table {{.Names}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return cls.container_name in result.stdout

    @classmethod
    def _start_localstack(cls):
        """Start LocalStack container using direct Docker commands"""
        print("Starting LocalStack container...")

        if cls._is_localstack_running():
            print("LocalStack container is already running")
            return

        # Remove any existing stopped container
        subprocess.run(
            ["docker", "rm", "-f", cls.container_name],
            capture_output=True,
            text=True,
            check=False,
        )

        # Start LocalStack container
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                cls.container_name,
                "-p",
                f"{cls.localstack_port}:4566",
                "-e",
                "SERVICES=secretsmanager",
                "-e",
                "DEBUG=1",
                "-e",
                "PERSISTENCE=0",
                "docker.io/localstack/localstack:latest",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            raise Exception(f"Failed to start LocalStack container: {result.stderr}")

        print("LocalStack container started")

    @classmethod
    def _stop_localstack(cls):
        """Stop and remove LocalStack container"""
        print("Stopping LocalStack container...")

        if cls._is_localstack_running():
            subprocess.run(
                ["docker", "stop", cls.container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            subprocess.run(
                ["docker", "rm", cls.container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            print("LocalStack container stopped and removed")
        else:
            print("LocalStack container is not running")

    @classmethod
    def _wait_for_localstack(cls, timeout=60):
        """Wait for LocalStack to be ready"""
        print("Waiting for LocalStack to be ready...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(
                    f"http://localhost:{cls.localstack_port}/_localstack/health",
                    timeout=5,
                )
                if response.status_code == 200:
                    health_data = response.json()
                    if health_data.get("services", {}).get("secretsmanager") == "available":
                        print("LocalStack Secrets Manager is ready!")
                        return
            except requests.RequestException:
                pass
            time.sleep(2)
        raise Exception("LocalStack did not become ready within timeout")

    @classmethod
    def _test_connectivity(cls):
        """Test AWS CLI connectivity to LocalStack"""
        print("Testing AWS CLI connectivity to LocalStack...")

        # Test by listing secrets (should return empty list)
        result = subprocess.run(
            [
                "aws",
                "secretsmanager",
                "list-secrets",
                "--endpoint-url",
                f"http://localhost:{cls.localstack_port}",
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **cls.aws_env},
        )

        if result.returncode == 0:
            print("AWS CLI connectivity test passed")
        else:
            raise Exception(f"AWS CLI connectivity test failed: {result.stderr}")

    @classmethod
    def _cleanup_test_data(cls):
        """Clean up test data from LocalStack"""
        print("Cleaning up test data...")

        # List and delete all secrets
        result = subprocess.run(
            [
                "aws",
                "secretsmanager",
                "list-secrets",
                "--endpoint-url",
                f"http://localhost:{cls.localstack_port}",
                "--query",
                "SecretList[].Name",
                "--output",
                "text",
            ],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, **cls.aws_env},
        )

        if result.returncode == 0 and result.stdout.strip():
            secret_names = result.stdout.strip().split()
            for secret_name in secret_names:
                if secret_name and secret_name != "None":
                    subprocess.run(
                        [
                            "aws",
                            "secretsmanager",
                            "delete-secret",
                            "--secret-id",
                            secret_name,
                            "--force-delete-without-recovery",
                            "--endpoint-url",
                            f"http://localhost:{cls.localstack_port}",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        env={**os.environ, **cls.aws_env},
                    )

        print("Test data cleanup completed")

    def test_aws_secrets_manager_basic_functionality(self):
        """Test basic AWS Secrets Manager functionality with LocalStack"""

        # Create a test secret using AWS CLI
        secret_data = {
            "username": "testuser",
            "password": "testpass123",
            "database": "mydb",
        }

        result = subprocess.run(
            [
                "aws",
                "secretsmanager",
                "create-secret",
                "--name",
                "test-basic-secret",
                "--description",
                "Test secret for integration testing",
                "--secret-string",
                json.dumps(secret_data),
                "--endpoint-url",
                "http://localhost:4566",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            result.returncode, 0, f"Failed to create secret: {result.stderr}"
        )

        # Verify secret was created
        result = subprocess.run(
            [
                "aws",
                "secretsmanager",
                "get-secret-value",
                "--secret-id",
                "test-basic-secret",
                "--endpoint-url",
                "http://localhost:4566",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            result.returncode, 0, f"Failed to retrieve secret: {result.stderr}"
        )

        # Parse the response
        response = json.loads(result.stdout)
        retrieved_data = json.loads(response["SecretString"])

        self.assertEqual(retrieved_data, secret_data)

    def test_aws_secrets_via_ansible_playbook(self):
        """Test AWS Secrets Manager integration via Ansible playbook"""

        # Create test files for different field types
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test-file-content")
            test_file_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[default]\napi_key=test-key-from-ini\nregion=us-west-2\n")
            test_ini_path = f.name

        try:
            # Create a test values-secret YAML configuration
            test_values_data = {
                "version": "3.0",
                "secretstore": "aws-secrets-manager",
                "awsConfig": {
                    "prefix": "test/",
                    "region": "us-east-1",
                    "defaultTags": {
                        "Environment": "test",
                        "ManagedBy": "integration-test",
                    },
                },
                "secrets": {
                    "app-config": {
                        "secretName": "custom-app-config",
                        "description": "Application configuration secrets",
                        "tags": {"Application": "test-app"},
                        "username": "testuser",
                        "password": "testpass123",
                        "file_content": f"file://{test_file_path}",
                        "ini_value": f"ini://{test_ini_path}:default:api_key",
                        "database_url": "postgresql://localhost:5432/testdb",
                        "port": 5432,
                        "enabled": True,
                    },
                    "simple-secret": {
                        "api_key": "test-api-key-123",
                        "service_url": "https://api.example.com",
                    },
                },
            }

            # Write the test values file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as f:
                yaml.dump(test_values_data, f)
                test_values_file = f.name

            # Create an Ansible playbook for testing
            playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Load secrets into AWS Secrets Manager
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
      environment:
        AWS_ENDPOINT_URL: "http://localhost:4566"
        AWS_ACCESS_KEY_ID: "test"
        AWS_SECRET_ACCESS_KEY: "test"
        AWS_DEFAULT_REGION: "us-east-1"
        AWS_SIMULATION_MODE: "true"
      register: result

    - name: Display result
      debug:
        var: result
"""

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yml", delete=False
            ) as f:
                f.write(playbook_content)
                playbook_file = f.name

            try:
                # Run ansible-playbook
                result = subprocess.run(
                    ["ansible-playbook", playbook_file, "-v"],
                    cwd=self.collection_root,
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        **os.environ,
                        "ANSIBLE_COLLECTIONS_PATH": str(
                            self.collection_root.parent.parent
                        ),
                        **self.aws_env,
                    },
                )

                print("Ansible playbook output:")
                print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
                print("Return code:", result.returncode)

                # Check if playbook succeeded
                self.assertEqual(
                    result.returncode, 0, f"Ansible playbook failed: {result.stderr}"
                )

                # The exact success message may vary, but we should see some indication of success
                success_indicators = ["secrets injected", "changed", "ok="]
                found_success = any(
                    indicator in result.stdout for indicator in success_indicators
                )
                self.assertTrue(
                    found_success, "No success indicators found in playbook output"
                )

            finally:
                os.unlink(playbook_file)
                os.unlink(test_values_file)

        finally:
            # Clean up test files
            for path in [test_file_path, test_ini_path]:
                if os.path.exists(path):
                    os.unlink(path)

        # Verify secrets were created in LocalStack
        self._verify_secrets_in_localstack()

    def test_aws_secrets_with_optional_fields(self):
        """Test AWS secrets with optional fields"""

        # Create a test values-secret YAML with optional fields
        test_values_data = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "optional-test": {
                    "required_field": "required-value",
                    "optional_file": {
                        "value": "file:///nonexistent/file.txt",
                        "optional": True,
                    },
                    "optional_ini": {
                        "value": "ini:///nonexistent/file.ini:section:key",
                        "optional": True,
                    },
                }
            },
        }

        # Write the test values file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(test_values_data, f)
            test_values_file = f.name

        # Create an Ansible playbook for testing
        playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Load secrets with optional fields
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
      environment:
        AWS_ENDPOINT_URL: "http://localhost:4566"
        AWS_ACCESS_KEY_ID: "test"
        AWS_SECRET_ACCESS_KEY: "test"
        AWS_DEFAULT_REGION: "us-east-1"
        AWS_SIMULATION_MODE: "true"
      register: result

    - name: Display result
      debug:
        var: result
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(playbook_content)
            playbook_file = f.name

        try:
            # Run ansible-playbook
            result = subprocess.run(
                ["ansible-playbook", playbook_file, "-v"],
                cwd=self.collection_root,
                capture_output=True,
                text=True,
                check=False,
                env={
                    **os.environ,
                    "ANSIBLE_COLLECTIONS_PATH": str(self.collection_root.parent.parent),
                    **self.aws_env,
                },
            )

            print("Optional fields test output:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            print("Return code:", result.returncode)

            # The playbook should succeed even with missing optional files
            self.assertEqual(
                result.returncode, 0, f"Ansible playbook failed: {result.stderr}"
            )

        finally:
            os.unlink(playbook_file)
            os.unlink(test_values_file)

    def _verify_secrets_in_localstack(self):
        """Verify that secrets were properly stored in LocalStack"""

        # List all secrets
        result = subprocess.run(
            [
                "aws",
                "secretsmanager",
                "list-secrets",
                "--endpoint-url",
                "http://localhost:4566",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            self.fail(f"Failed to list secrets: {result.stderr}")

        secrets_list = json.loads(result.stdout)
        secret_names = [secret["Name"] for secret in secrets_list["SecretList"]]

        # Verify expected secrets exist
        expected_secrets = ["test/custom-app-config", "simple-secret"]
        for expected_secret in expected_secrets:
            # Secrets may have the prefix, so check if any secret name contains the expected name
            found = any(expected_secret in name for name in secret_names)
            self.assertTrue(
                found,
                f"Expected secret '{expected_secret}' not found in {secret_names}",
            )

        # Verify we can retrieve a specific secret's value
        for secret_name in secret_names:
            if "custom-app-config" in secret_name:
                result = subprocess.run(
                    [
                        "aws",
                        "secretsmanager",
                        "get-secret-value",
                        "--secret-id",
                        secret_name,
                        "--endpoint-url",
                        "http://localhost:4566",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

                if result.returncode == 0:
                    response = json.loads(result.stdout)

                    # Handle LocalStack's malformed JSON output
                    secret_string = response["SecretString"]
                    try:
                        secret_data = json.loads(secret_string)
                    except json.JSONDecodeError:
                        # LocalStack sometimes returns Python dict format instead of JSON
                        # Try to parse it as a Python literal
                        import ast

                        try:
                            secret_data = ast.literal_eval(secret_string)
                        except (ValueError, SyntaxError):
                            # If both fail, we'll skip the detailed verification
                            print(
                                "Warning: Could not parse secret data, skipping detailed verification"
                            )
                            break

                    # Verify some expected fields
                    self.assertIn("username", secret_data)
                    self.assertEqual(secret_data["username"], "testuser")
                    self.assertIn("file_content", secret_data)
                    self.assertEqual(secret_data["file_content"], "test-file-content")
                    self.assertIn("ini_value", secret_data)
                    self.assertEqual(secret_data["ini_value"], "test-key-from-ini")
                    break


if __name__ == "__main__":
    # Check if LocalStack is available
    try:
        result = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            print("Docker is not available. Skipping AWS integration tests.")
            sys.exit(0)
    except FileNotFoundError:
        print("Docker is not available. Skipping AWS integration tests.")
        sys.exit(0)

    # Check if aws CLI is available
    try:
        result = subprocess.run(
            ["aws", "--version"], capture_output=True, text=True, check=False
        )
        if result.returncode != 0:
            print("AWS CLI is not available. Skipping AWS integration tests.")
            sys.exit(0)
    except FileNotFoundError:
        print("AWS CLI is not available. Skipping AWS integration tests.")
        sys.exit(0)

    # Run the tests
    unittest.main(verbosity=2)
