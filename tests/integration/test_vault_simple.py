#!/usr/bin/env python
"""
Simple integration test for Vault container setup
"""

import subprocess
import sys
import time
import unittest
from pathlib import Path

import requests


class VaultSimpleIntegrationTest(unittest.TestCase):
    """Simple integration test to verify Vault container setup"""

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

    def test_vault_connection(self):
        """Test basic Vault connection"""
        response = self._vault_request("GET", "sys/health")
        self.assertEqual(response.status_code, 200)

        health_data = response.json()
        self.assertTrue(health_data["initialized"])
        self.assertFalse(health_data["sealed"])

    def test_vault_authentication(self):
        """Test Vault authentication with root token"""
        response = self._vault_request("GET", "auth/token/lookup-self")
        self.assertEqual(response.status_code, 200)

        token_data = response.json()
        self.assertEqual(token_data["data"]["id"], self.vault_token)

    def test_vault_kv_store(self):
        """Test basic KV store functionality"""
        # Store a test secret
        test_data = {"test_key": "test_value", "number": "42"}
        response = self._vault_request(
            "PUT", "secret/data/test/simple", {"data": test_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Retrieve the secret
        response = self._vault_request("GET", "secret/data/test/simple")
        self.assertEqual(response.status_code, 200)

        retrieved_data = response.json()["data"]["data"]
        self.assertEqual(retrieved_data["test_key"], "test_value")
        self.assertEqual(retrieved_data["number"], "42")

    def test_vault_secret_paths(self):
        """Test that we can create secrets in different paths"""
        # Test hub path
        hub_data = {"username": "hub-user", "password": "hub-pass"}
        response = self._vault_request(
            "PUT", "secret/data/hub/test-secret", {"data": hub_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Test spoke path
        spoke_data = {"username": "spoke-user", "password": "spoke-pass"}
        response = self._vault_request(
            "PUT", "secret/data/test-spoke/test-secret", {"data": spoke_data}
        )
        self.assertIn(response.status_code, [200, 204])

        # Verify we can retrieve from both paths
        response = self._vault_request("GET", "secret/data/hub/test-secret")
        self.assertEqual(response.status_code, 200)
        hub_retrieved = response.json()["data"]["data"]
        self.assertEqual(hub_retrieved["username"], "hub-user")

        response = self._vault_request("GET", "secret/data/test-spoke/test-secret")
        self.assertEqual(response.status_code, 200)
        spoke_retrieved = response.json()["data"]["data"]
        self.assertEqual(spoke_retrieved["username"], "spoke-user")


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
