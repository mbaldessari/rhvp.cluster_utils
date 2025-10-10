#!/usr/bin/env python3
"""
Direct integration test for vault_load_secrets module with real HashiCorp Vault
"""

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import requests
import yaml

# Add the collection to the Python path for importing
collection_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(collection_root))

# Set up the ansible_collections module path
ansible_collections_path = collection_root.parent.parent
if str(ansible_collections_path) not in sys.path:
    sys.path.insert(0, str(ansible_collections_path))

# Set environment variable for Ansible collections
os.environ["ANSIBLE_COLLECTIONS_PATH"] = str(ansible_collections_path)

from plugins.module_utils.load_secrets_v3 import LoadSecretsV3


class VaultDirectIntegrationTest(unittest.TestCase):
    """Direct integration test using the Python module"""

    @classmethod
    def setUpClass(cls):
        """Set up Vault container and wait for it to be ready"""
        cls.vault_addr = "http://localhost:8200"
        cls.vault_token = "myroot"
        cls.test_dir = Path(__file__).parent

        # Start Vault container using direct podman command
        print("Starting Vault container...")

        # Clean up any existing container with the same name
        subprocess.run(["podman", "stop", "vault-test"], capture_output=True, text=True)
        subprocess.run(["podman", "rm", "vault-test"], capture_output=True, text=True)

        # Create a volume for vault data (if it doesn't exist)
        subprocess.run(
            ["podman", "volume", "create", "vault-data"], capture_output=True, text=True
        )
        # Ignore errors if volume already exists

        # Start the vault container
        result = subprocess.run(
            [
                "podman",
                "run",
                "-d",
                "--name",
                "vault-test",
                "--rm",  # Auto-remove when stopped
                "-p",
                "8200:8200",
                "-e",
                "VAULT_DEV_ROOT_TOKEN_ID=myroot",
                "-e",
                "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
                "-e",
                "VAULT_ADDR=http://0.0.0.0:8200",
                "--cap-add",
                "IPC_LOCK",
                "-v",
                "vault-data:/vault/data",
                "-v",
                f"{cls.test_dir}/vault-config:/vault/config",
                "docker.io/hashicorp/vault:1.15.2",
                "vault",
                "server",
                "-dev",
                "-dev-root-token-id=myroot",
                "-dev-listen-address=0.0.0.0:8200",
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise Exception(f"Failed to start Vault container: {result.stderr}")

        # Wait for Vault to be ready
        cls._wait_for_vault()

    @classmethod
    def tearDownClass(cls):
        """Clean up Vault container"""
        print("Stopping Vault container...")

        # Stop and remove the container (--rm flag will auto-remove it)
        subprocess.run(["podman", "stop", "vault-test"], capture_output=True, text=True)

        # Clean up the volume
        subprocess.run(
            ["podman", "volume", "rm", "vault-data"], capture_output=True, text=True
        )

    @classmethod
    def _wait_for_vault(cls, timeout=30):
        """Wait for Vault to be ready"""
        print("Waiting for Vault to be ready...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{cls.vault_addr}/v1/sys/health", timeout=5)
                if response.status_code in [200, 429, 472, 473]:
                    print("Vault is ready!")
                    return
            except requests.RequestException:
                pass
            time.sleep(2)
        raise Exception("Vault did not become ready within timeout")

    def _vault_request(self, method, path, data=None):
        """Make a request to Vault API"""
        headers = {"X-Vault-Token": self.vault_token}
        url = f"{self.vault_addr}/v1/{path}"

        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        return response

    def _create_mock_module(self):
        """Create a mock Ansible module for testing"""
        module = mock.MagicMock()

        # Mock run_command to execute vault commands via docker exec
        def run_command(cmd, **kwargs):
            # Replace oc exec commands with docker exec commands
            if "oc exec" in cmd:
                # Transform oc exec command to docker exec
                # Extract the vault command part
                if "vault" in cmd:
                    # Find the vault command within the shell command
                    import re

                    vault_cmd_match = re.search(r"vault [^'\"]*", cmd)
                    if vault_cmd_match:
                        vault_cmd = vault_cmd_match.group(0)
                        # Execute the vault command directly using podman exec
                        podman_cmd = [
                            "podman",
                            "exec",
                            "vault-test",
                            "sh",
                            "-c",
                            f"VAULT_ADDR=http://localhost:8200 VAULT_TOKEN={self.vault_token} {vault_cmd}",
                        ]
                        result = subprocess.run(
                            podman_cmd, capture_output=True, text=True
                        )
                        return (result.returncode, result.stdout, result.stderr)

            # For other commands, just return success
            return (0, "", "")

        module.run_command = run_command
        module.fail_json = mock.MagicMock(side_effect=Exception)

        return module

    def test_direct_vault_load_secrets_v3(self):
        """Test loading v3.0 secrets directly using the Python module"""

        # Load test YAML
        test_values_file = self.test_dir / "test-values-secret-v3.yaml"
        with open(test_values_file, "r") as f:
            syaml = yaml.safe_load(f)

        # Create mock module
        module = self._create_mock_module()

        # Create LoadSecretsV3 instance
        # Use fake namespace and pod since we're using podman exec
        secrets_loader = LoadSecretsV3(module, syaml, "test-namespace", "test-pod")

        # Test validation
        secrets_loader.sanitize_values()

        # Test injection
        num_secrets = secrets_loader.inject_secrets()
        self.assertGreater(num_secrets, 0)

        # Verify secrets were stored in Vault
        self._verify_secrets_in_vault()

    def _verify_secrets_in_vault(self):
        """Verify that secrets were properly stored in Vault"""

        # Check that password policies were created
        policies_response = self._vault_request("GET", "sys/policies/password")
        self.assertEqual(policies_response.status_code, 200)

        # Check if our test policies exist
        policies_data = policies_response.json()
        if "data" in policies_data and "keys" in policies_data["data"]:
            policy_names = policies_data["data"]["keys"]
            self.assertIn("test-basic", policy_names)
            self.assertIn("test-strong", policy_names)

        # Verify secrets in vault
        # Test database secret in hub
        hub_db_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-database"
        )
        self.assertEqual(hub_db_response.status_code, 200)

        hub_db_data = hub_db_response.json()["data"]["data"]
        self.assertEqual(hub_db_data["username"], "test-db-user")
        self.assertEqual(hub_db_data["host"], "localhost")
        self.assertEqual(hub_db_data["port"], "5432")
        # Password should be generated
        self.assertIn("password", hub_db_data)
        self.assertIsInstance(hub_db_data["password"], str)
        self.assertEqual(len(hub_db_data["password"]), 8)  # test-basic policy

        # Test database secret in test-spoke
        spoke_db_response = self._vault_request(
            "GET", "secret/data/test-spoke/integration-test-database"
        )
        self.assertEqual(spoke_db_response.status_code, 200)

        spoke_db_data = spoke_db_response.json()["data"]["data"]
        self.assertEqual(spoke_db_data["username"], "test-db-user")
        # Generated passwords should be different
        self.assertNotEqual(hub_db_data["password"], spoke_db_data["password"])

        # Test API secret (should only be in hub due to targets override)
        hub_api_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-api"
        )
        self.assertEqual(hub_api_response.status_code, 200)

        hub_api_data = hub_api_response.json()["data"]["data"]
        self.assertEqual(hub_api_data["endpoint"], "https://api.test.example.com")
        self.assertEqual(hub_api_data["timeout"], "30")
        # Token should be generated with test-strong policy (16 chars)
        self.assertIn("token", hub_api_data)
        self.assertEqual(len(hub_api_data["token"]), 16)

        # API secret should NOT be in test-spoke
        spoke_api_response = self._vault_request(
            "GET", "secret/data/test-spoke/integration-test-api"
        )
        self.assertEqual(spoke_api_response.status_code, 404)

        # Test static secret
        hub_static_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-static"
        )
        self.assertEqual(hub_static_response.status_code, 200)

        hub_static_data = hub_static_response.json()["data"]["data"]
        self.assertEqual(hub_static_data["static_value"], "this-is-a-test-value")
        self.assertEqual(hub_static_data["number_value"], "42")
        self.assertEqual(hub_static_data["boolean_value"], "True")

    def test_vault_connection(self):
        """Simple test to verify Vault connection works"""
        response = self._vault_request("GET", "sys/health")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    # Check if Podman is available and running
    try:
        subprocess.run(["podman", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Podman is not available. Skipping integration tests.")
        sys.exit(0)

    try:
        subprocess.run(["podman", "info"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Podman is not running. Skipping integration tests.")
        sys.exit(0)

    unittest.main(verbosity=2)
