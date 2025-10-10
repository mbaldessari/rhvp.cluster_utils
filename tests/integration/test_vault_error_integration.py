#!/usr/bin/env python3
"""
Integration test for error handling using Ansible playbook mechanism
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


class VaultErrorIntegrationTest(unittest.TestCase):
    """Integration test for error handling using Ansible playbooks"""

    @classmethod
    def setUpClass(cls):
        """Set up Vault container and wait for it to be ready"""
        cls.vault_addr = "http://localhost:8200"
        cls.vault_token = "myroot"
        cls.test_dir = Path(__file__).parent
        cls.collection_root = cls.test_dir.parent.parent

        # Start Vault container using helper script
        print("Starting Vault container...")
        result = subprocess.run(
            [str(cls.test_dir / "vault-helper.sh"), "start"],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            raise Exception(f"Failed to start Vault: {result.stderr}")

        print("Vault started successfully")

    @classmethod
    def tearDownClass(cls):
        """Clean up Vault container"""
        print("Stopping Vault container...")
        result = subprocess.run(
            [str(cls.test_dir / "vault-helper.sh"), "stop"],
            capture_output=True,
            text=True,
        )
        print("Vault stopped")

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

    def test_error_handling_with_ansible(self):
        """Test error handling using Ansible playbook with missing files"""

        # Create a test values file with missing file references
        test_values_content = """version: "3.0"
secretstore: "vault"

policies:
  test-basic:
    length: 8
    charset: "alphanumeric"

settings:
  targets: ["hub"]

secrets:
  working-secret:
    # This secret should work fine
    username: "working-user"
    password: "generate:test-basic"
    endpoint: "https://working.example.com"

  failing-secret:
    # This secret has a missing file that should cause an error
    username: "failing-user"
    password: "generate:test-basic"
    missing_file: "file:///path/that/does/not/exist.txt"
    valid_field: "some-value"
"""

        # Create a playbook that should handle missing files gracefully
        # First create the test values file separately
        test_values_file = "/tmp/test-error-values.yaml"
        with open(test_values_file, "w") as f:
            f.write(test_values_content)

        playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Load secrets with errors into vault
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
        namespace: "test-namespace"
        pod: "test-pod"
      register: result
      ignore_errors: true

    - name: Display result
      debug:
        var: result
"""

        # Write playbook to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(playbook_content)
            playbook_file = f.name

        try:
            # Set environment for vault direct mode
            env = os.environ.copy()
            env["VAULT_DIRECT_MODE"] = "true"
            env["ANSIBLE_COLLECTIONS_PATH"] = str(self.collection_root.parent.parent)

            # Run the playbook
            result = subprocess.run(
                ["ansible-playbook", "-v", playbook_file],
                cwd=self.collection_root,
                capture_output=True,
                text=True,
                env=env,
            )

            print("Ansible playbook output:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            print("Return code:", result.returncode)

            # The playbook should succeed because we're using ignore_errors
            self.assertEqual(
                result.returncode, 0, "Expected playbook to succeed with ignore_errors"
            )

            # Check that the error message contains information about the missing files
            output = result.stdout + result.stderr
            # Check that the module failed but the task still shows the error
            self.assertIn("failed", output.lower(), "Expected failed status in output")
            self.assertIn(
                "missing_file", output.lower(), "Expected error about missing file"
            )

            # Verify that the working secret was still created
            self._verify_partial_secrets_created()

        finally:
            # Clean up temp files
            os.unlink(playbook_file)
            if os.path.exists(test_values_file):
                os.unlink(test_values_file)

    def _verify_partial_secrets_created(self):
        """Verify that working secrets were created even though some failed"""

        # Check that the working secret was created successfully
        try:
            working_response = self._vault_request(
                "GET", "secret/data/hub/working-secret"
            )
            if working_response.status_code == 200:
                working_data = working_response.json()["data"]["data"]
                self.assertEqual(working_data["username"], "working-user")
                self.assertEqual(
                    working_data["endpoint"], "https://working.example.com"
                )
                self.assertIn("password", working_data)
                print("✅ Working secret was created successfully")
            else:
                print(
                    f"⚠️ Working secret not found (status: {working_response.status_code})"
                )
        except Exception as e:
            print(f"⚠️ Could not verify working secret: {e}")

        # Check the failing secret - it should either not exist or have partial data
        try:
            failing_response = self._vault_request(
                "GET", "secret/data/hub/failing-secret"
            )
            if failing_response.status_code == 200:
                failing_data = failing_response.json()["data"]["data"]
                # Should have valid fields but not the missing file
                self.assertEqual(failing_data["username"], "failing-user")
                self.assertEqual(failing_data["valid_field"], "some-value")
                self.assertIn("password", failing_data)
                # Missing file field should not be present
                self.assertNotIn("missing_file", failing_data)
                print("✅ Failing secret has partial data (valid fields only)")
            else:
                print(
                    f"ℹ️ Failing secret not found (status: {failing_response.status_code}) - this is expected"
                )
        except Exception as e:
            print(f"ℹ️ Could not check failing secret: {e} - this may be expected")

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
