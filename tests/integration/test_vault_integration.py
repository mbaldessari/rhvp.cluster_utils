#!/usr/bin/env python3
"""
Integration test for vault_load_secrets with real HashiCorp Vault
"""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import requests


class VaultIntegrationTest(unittest.TestCase):
    """Integration test that uses a real Vault container"""

    @classmethod
    def setUpClass(cls):
        """Set up Vault container and wait for it to be ready"""
        cls.vault_addr = "http://localhost:8200"
        cls.vault_token = "myroot"
        cls.test_dir = Path(__file__).parent
        cls.collection_root = cls.test_dir.parent.parent

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

        # Configure Vault for testing
        cls._configure_vault()

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
                if response.status_code in [
                    200,
                    429,
                    472,
                    473,
                ]:  # Vault health check responses
                    print("Vault is ready!")
                    return
            except requests.RequestException:
                pass
            time.sleep(2)
        raise Exception("Vault did not become ready within timeout")

    @classmethod
    def _configure_vault(cls):
        """Configure Vault with required settings"""
        headers = {"X-Vault-Token": cls.vault_token}

        # Enable KV v2 secrets engine at 'secret' path (usually enabled by default in dev mode)
        try:
            response = requests.post(
                f"{cls.vault_addr}/v1/sys/mounts/secret",
                json={"type": "kv", "options": {"version": "2"}},
                headers=headers,
            )
            # 400 error is OK if it already exists
            if response.status_code not in [200, 204, 400]:
                print(f"Warning: Failed to enable KV engine: {response.text}")
        except requests.RequestException as e:
            print(f"Warning: Could not configure KV engine: {e}")

    def _vault_request(self, method, path, data=None):
        """Make a request to Vault API"""
        headers = {"X-Vault-Token": self.vault_token}
        url = f"{self.vault_addr}/v1/{path}"

        if method.upper() == "GET":
            response = requests.get(url, headers=headers)
        elif method.upper() == "LIST":
            # LIST method uses a specific request
            response = requests.request("LIST", url, headers=headers)
        elif method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "PUT":
            response = requests.put(url, json=data, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        return response

    def test_vault_load_secrets_v3_integration(self):
        """Test loading v3.0 secrets into real Vault"""
        # Create a temporary test values file
        test_values_file = self.test_dir / "test-values-secret-v3.yaml"

        # Create temporary playbook for testing
        playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    vault_addr: "{self.vault_addr}"
    vault_token: "{self.vault_token}"
  tasks:
    - name: Load secrets into vault
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
        namespace: "test-namespace"
        pod: "test-pod"
      environment:
        VAULT_ADDR: "{{{{ vault_addr }}}}"
        VAULT_TOKEN: "{{{{ vault_token }}}}"
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
                env={
                    **os.environ,
                    "ANSIBLE_COLLECTIONS_PATH": str(self.collection_root.parent.parent),
                    "VAULT_ADDR": self.vault_addr,
                    "VAULT_TOKEN": self.vault_token,
                    "VAULT_DIRECT_MODE": "true",
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
            self.assertIn("secrets injected", result.stdout)

        finally:
            os.unlink(playbook_file)

        # Verify secrets were stored correctly in Vault
        self._verify_secrets_in_vault()

    def _verify_secrets_in_vault(self):
        """Verify that secrets were properly stored in Vault"""
        # Test that policies were created
        policies_response = self._vault_request("LIST", "sys/policies/password")
        self.assertEqual(policies_response.status_code, 200)
        policies_data = policies_response.json()
        policy_names = policies_data.get("data", {}).get("keys", [])
        self.assertIn("test-basic", policy_names)
        self.assertIn("test-strong", policy_names)

        # Test secrets in hub path
        hub_database_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-database"
        )
        self.assertEqual(hub_database_response.status_code, 200)
        hub_db_data = hub_database_response.json()["data"]["data"]

        # Verify static values
        self.assertEqual(hub_db_data["username"], "test-db-user")
        self.assertEqual(hub_db_data["host"], "localhost")
        self.assertEqual(hub_db_data["port"], "5432")
        # Password should be generated (8 characters for test-basic policy)
        self.assertIsInstance(hub_db_data["password"], str)
        self.assertEqual(len(hub_db_data["password"]), 8)

        # Test secrets in test-spoke path
        spoke_database_response = self._vault_request(
            "GET", "secret/data/test-spoke/integration-test-database"
        )
        self.assertEqual(spoke_database_response.status_code, 200)
        spoke_db_data = spoke_database_response.json()["data"]["data"]

        # Should have same static values but different generated password
        self.assertEqual(spoke_db_data["username"], "test-db-user")
        self.assertEqual(spoke_db_data["host"], "localhost")
        self.assertEqual(spoke_db_data["port"], "5432")
        self.assertIsInstance(spoke_db_data["password"], str)
        self.assertEqual(len(spoke_db_data["password"]), 8)
        # Generated passwords should be different between targets
        self.assertNotEqual(hub_db_data["password"], spoke_db_data["password"])

        # Test API secret (should only be in hub due to targets override)
        hub_api_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-api"
        )
        self.assertEqual(hub_api_response.status_code, 200)
        hub_api_data = hub_api_response.json()["data"]["data"]

        self.assertEqual(hub_api_data["endpoint"], "https://api.test.example.com")
        self.assertEqual(hub_api_data["timeout"], "30")
        # Token should be generated (16 characters for test-strong policy)
        self.assertIsInstance(hub_api_data["token"], str)
        self.assertEqual(len(hub_api_data["token"]), 16)

        # API secret should NOT be in test-spoke (due to targets override)
        spoke_api_response = self._vault_request(
            "GET", "secret/data/test-spoke/integration-test-api"
        )
        self.assertEqual(spoke_api_response.status_code, 404)

        # Test static values secret
        hub_static_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-static"
        )
        self.assertEqual(hub_static_response.status_code, 200)
        hub_static_data = hub_static_response.json()["data"]["data"]

        self.assertEqual(hub_static_data["static_value"], "this-is-a-test-value")
        self.assertEqual(
            hub_static_data["number_value"], "42"
        )  # Numbers become strings in vault
        self.assertEqual(
            hub_static_data["boolean_value"], "True"
        )  # Booleans become strings

    def test_vault_connection(self):
        """Simple test to verify Vault connection works"""
        response = self._vault_request("GET", "sys/health")
        self.assertEqual(response.status_code, 200)

        # Test authentication
        response = self._vault_request("GET", "auth/token/lookup-self")
        self.assertEqual(response.status_code, 200)
        token_data = response.json()
        self.assertEqual(token_data["data"]["id"], self.vault_token)


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
