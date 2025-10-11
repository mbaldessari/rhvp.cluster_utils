#!/usr/bin/env python
"""
Integration test for vault_load_secrets with real HashiCorp Vault
"""

import os
import subprocess
import tempfile

import requests
from vault_test_base import VaultTestBase


class VaultIntegrationTest(VaultTestBase):
    """Integration test that uses a real Vault container"""

    @classmethod
    def _subclass_setup(cls):
        """Configure Vault for testing after base setup"""
        cls._configure_vault()

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

    def test_vault_load_secrets_v3_integration(self):
        """Test loading v3.0 secrets into real Vault"""
        # Copy the test ini file to a temporary location accessible by the test
        test_config_file = "/tmp/test-config.ini"
        with open(self.test_dir / "test-config.ini", "r") as src:
            with open(test_config_file, "w") as dst:
                dst.write(src.read())

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
                check=False,
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
            if os.path.exists(test_config_file):
                os.unlink(test_config_file)

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

        # Test authentication
        response = self._vault_request("GET", "auth/token/lookup-self")
        self.assertEqual(response.status_code, 200)
        token_data = response.json()
        self.assertEqual(token_data["data"]["id"], self.vault_token)


if __name__ == "__main__":
    import unittest

    VaultTestBase.check_podman_availability()
    unittest.main(verbosity=2)
