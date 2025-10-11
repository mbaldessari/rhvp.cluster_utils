#!/usr/bin/env python
"""
Direct integration test for vault_load_secrets module with real HashiCorp Vault
"""

import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import yaml
from vault_test_base import VaultTestBase

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


class VaultDirectIntegrationTest(VaultTestBase):
    """Direct integration test using the Python module"""

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
                            podman_cmd,
                            capture_output=True,
                            text=True,
                            check=False,
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

        # Test ini+base64 secret
        hub_ini_response = self._vault_request(
            "GET", "secret/data/hub/integration-test-ini-base64"
        )
        self.assertEqual(hub_ini_response.status_code, 200)

        hub_ini_data = hub_ini_response.json()["data"]["data"]

        # Verify plain ini:// value (should be plain text)
        self.assertEqual(hub_ini_data["plain_value"], "test_api_key_12345")

        # Verify ini+base64:// values (should be base64 encoded)
        import base64

        # Test auth_token value
        encoded_auth_token = hub_ini_data["encoded_value"]
        decoded_auth_token = base64.b64decode(encoded_auth_token).decode("utf-8")
        self.assertEqual(decoded_auth_token, "dGVzdF9hdXRoX3Rva2VuXzY3ODkw")

        # Test registry_auth with section
        encoded_registry_auth = hub_ini_data["encoded_with_section"]
        decoded_registry_auth = base64.b64decode(encoded_registry_auth).decode("utf-8")
        self.assertEqual(decoded_registry_auth, "dGVzdDp0ZXN0cGFzcw==")

    def test_vault_connection(self):
        """Simple test to verify Vault connection works"""
        response = self._vault_request("GET", "sys/health")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    import unittest

    VaultTestBase.check_podman_availability()
    unittest.main(verbosity=2)
