#!/usr/bin/env python
"""
Integration test for Kubernetes secretstore functionality using kind
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


class KubernetesIntegrationTest(unittest.TestCase):
    """Integration test for Kubernetes secretstore using kind"""

    @classmethod
    def setUpClass(cls):
        """Set up kind cluster and wait for it to be ready"""
        cls.test_dir = Path(__file__).parent
        cls.collection_root = cls.test_dir.parent.parent
        cls.cluster_name = "vault-secrets-test"
        cls.kubeconfig_file = cls.test_dir / "kubeconfig-kind"

        # Start kind cluster using direct kind commands
        cls._start_kind_cluster()

        print("Kind cluster started successfully")
        cls._wait_for_cluster()

    @classmethod
    def tearDownClass(cls):
        """Clean up kind cluster"""
        cls._stop_kind_cluster()
        print("Kind cluster stopped")

    @classmethod
    def _cluster_exists(cls):
        """Check if the kind cluster already exists"""
        result = subprocess.run(
            ["kind", "get", "clusters"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0 and cls.cluster_name in result.stdout

    @classmethod
    def _start_kind_cluster(cls):
        """Start kind cluster using direct kind commands"""
        print("Starting kind cluster...")

        my_env = os.environ.copy()
        my_env["KIND_EXPERIMENTAL_PROVIDER"] = "podman"
        # Check if cluster already exists
        if cls._cluster_exists():
            print(f"Cluster {cls.cluster_name} already exists")
            # Export kubeconfig for existing cluster
            result = subprocess.run(
                [
                    "kind",
                    "export",
                    "kubeconfig",
                    "--name",
                    cls.cluster_name,
                    "--kubeconfig",
                    str(cls.kubeconfig_file),
                ],
                capture_output=True,
                env=my_env,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise Exception(f"Failed to export kubeconfig: {result.stderr}")
            return

        # Create cluster
        result = subprocess.run(
            [
                "kind",
                "create",
                "cluster",
                "--name",
                cls.cluster_name,
                "--kubeconfig",
                str(cls.kubeconfig_file),
            ],
            capture_output=True,
            text=True,
            env=my_env,
            check=False,
        )

        if result.returncode != 0:
            raise Exception(f"Failed to create kind cluster: {result.stderr}")

        print("Waiting for cluster to be ready...")
        result = subprocess.run(
            [
                "kubectl",
                f"--kubeconfig={cls.kubeconfig_file}",
                "wait",
                "--for=condition=Ready",
                "nodes",
                "--all",
                "--timeout=300s",
            ],
            capture_output=True,
            text=True,
            env=my_env,
            check=False,
        )

        if result.returncode != 0:
            raise Exception(f"Cluster nodes did not become ready: {result.stderr}")

        # Create test namespaces
        namespaces = ["test-namespace", "production", "test-secrets", "app-namespace"]
        for namespace in namespaces:
            subprocess.run(
                [
                    "kubectl",
                    f"--kubeconfig={cls.kubeconfig_file}",
                    "create",
                    "namespace",
                    namespace,
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        print("✅ Kind cluster started and ready")
        print(f"📋 Cluster name: {cls.cluster_name}")
        print(f"📄 Kubeconfig: {cls.kubeconfig_file}")

    @classmethod
    def _stop_kind_cluster(cls):
        """Stop and remove kind cluster"""
        print("Stopping kind cluster...")

        # Delete cluster
        subprocess.run(
            ["kind", "delete", "cluster", "--name", cls.cluster_name],
            capture_output=True,
            text=True,
            check=False,
        )

        # Remove kubeconfig file
        if cls.kubeconfig_file.exists():
            cls.kubeconfig_file.unlink()

        print("Kind cluster stopped and kubeconfig cleaned")

    @classmethod
    def _wait_for_cluster(cls, timeout=300):
        """Wait for cluster to be ready"""
        print("Waiting for cluster to be ready...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    [
                        "kubectl",
                        "--kubeconfig",
                        str(cls.kubeconfig_file),
                        "get",
                        "nodes",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                if result.returncode == 0 and "Ready" in result.stdout:
                    print("Cluster is ready!")
                    return
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                pass
            time.sleep(5)
        raise Exception("Kind cluster did not become ready within timeout")

    def _kubectl_command(self, *args):
        """Run kubectl command with the test kubeconfig"""
        cmd = ["kubectl", "--kubeconfig", str(self.kubeconfig_file)] + list(args)
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result

    def _get_secret(self, name, namespace="default"):
        """Get a Kubernetes secret"""
        result = self._kubectl_command(
            "get", "secret", name, "-n", namespace, "-o", "json"
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        return None

    def _decode_secret_data(self, secret_data):
        """Decode base64 secret data"""
        decoded = {}
        for key, value in secret_data.items():
            decoded[key] = base64.b64decode(value).decode("utf-8")
        return decoded

    def test_kubernetes_secretstore_integration(self):
        """Test loading secrets into Kubernetes using secretstore"""

        # Create a modified test values file that doesn't require prompts
        test_values_content = """version: "3.0"
secretstore: "kubernetes"

settings:
  namespace: "test-secrets"

secrets:
  database-credentials:
    username: "db-user"
    password: "db-password-123"
    host: "postgres.example.com"
    port: "5432"
    database: "myapp"
    namespaces: ["default", "test-namespace"]
    type: "Opaque"
    labels:
      app: "myapp"
      component: "database"
    annotations:
      created-by: "validated-patterns"
      description: "Database credentials for myapp"

  api-credentials:
    username: "api-user"
    token: "api-token-12345"
    endpoint: "https://api.example.com"
    namespaces: "production"
    type: "kubernetes.io/basic-auth"
    labels:
      app: "myapp"
      component: "api"

  static-config:
    config_value: "test-config"
    environment: "testing"
    debug: true
    max_connections: 100
    # Uses default namespace from settings
    type: "Opaque"
"""

        # Create the test values file separately
        test_values_file = "/tmp/test-k8s-values.yaml"
        with open(test_values_file, "w") as f:
            f.write(test_values_content)

        # Create a playbook to test Kubernetes secretstore
        playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Load secrets into Kubernetes
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
        namespace: "unused-for-k8s"
        pod: "unused-for-k8s"
      environment:
        KUBECONFIG: "{self.kubeconfig_file}"
      register: result

    - name: Display result
      debug:
        var: result
"""

        # Write playbook to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(playbook_content)
            playbook_file = f.name

        try:
            # Set environment for kubernetes mode
            env = os.environ.copy()
            env["ANSIBLE_COLLECTIONS_PATH"] = str(self.collection_root.parent.parent)
            env["KUBECONFIG"] = str(self.kubeconfig_file)

            # Run the playbook
            result = subprocess.run(
                ["ansible-playbook", "-v", playbook_file],
                cwd=self.collection_root,
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            print("Ansible playbook output:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            print("Return code:", result.returncode)

            # The playbook should succeed
            self.assertEqual(
                result.returncode, 0, f"Ansible playbook failed: {result.stderr}"
            )
            self.assertIn("secrets injected", result.stdout.lower())

        finally:
            # Clean up temp files
            os.unlink(playbook_file)
            if os.path.exists(test_values_file):
                os.unlink(test_values_file)

        # Verify secrets were created correctly in Kubernetes
        self._verify_secrets_in_kubernetes()

    def _verify_secrets_in_kubernetes(self):
        """Verify that secrets were properly created in Kubernetes"""

        # Test database credentials in default namespace
        print("Checking database-credentials in default namespace...")
        secret = self._get_secret("database-credentials", "default")
        self.assertIsNotNone(
            secret, "database-credentials secret not found in default namespace"
        )

        # Verify metadata
        metadata = secret["metadata"]
        self.assertEqual(metadata["name"], "database-credentials")
        self.assertEqual(metadata["namespace"], "default")
        self.assertEqual(secret["type"], "Opaque")

        # Verify labels and annotations
        self.assertEqual(metadata["labels"]["app"], "myapp")
        self.assertEqual(metadata["labels"]["component"], "database")
        self.assertEqual(metadata["annotations"]["created-by"], "validated-patterns")
        self.assertEqual(
            metadata["annotations"]["description"], "Database credentials for myapp"
        )

        # Verify secret data
        decoded_data = self._decode_secret_data(secret["data"])
        self.assertEqual(decoded_data["username"], "db-user")
        self.assertEqual(decoded_data["password"], "db-password-123")
        self.assertEqual(decoded_data["host"], "postgres.example.com")
        self.assertEqual(decoded_data["port"], "5432")
        self.assertEqual(decoded_data["database"], "myapp")

        # Test database credentials in test-namespace
        print("Checking database-credentials in test-namespace...")
        secret = self._get_secret("database-credentials", "test-namespace")
        self.assertIsNotNone(
            secret, "database-credentials secret not found in test-namespace"
        )
        decoded_data = self._decode_secret_data(secret["data"])
        self.assertEqual(decoded_data["username"], "db-user")

        # Test API credentials in production namespace
        print("Checking api-credentials in production namespace...")
        secret = self._get_secret("api-credentials", "production")
        self.assertIsNotNone(
            secret, "api-credentials secret not found in production namespace"
        )

        # Verify type and data
        self.assertEqual(secret["type"], "kubernetes.io/basic-auth")
        decoded_data = self._decode_secret_data(secret["data"])
        self.assertEqual(decoded_data["username"], "api-user")
        self.assertEqual(decoded_data["token"], "api-token-12345")
        self.assertEqual(decoded_data["endpoint"], "https://api.example.com")

        # Test static config in default namespace (uses settings.namespace)
        print("Checking static-config in test-secrets namespace...")
        secret = self._get_secret("static-config", "test-secrets")
        self.assertIsNotNone(
            secret, "static-config secret not found in test-secrets namespace"
        )

        decoded_data = self._decode_secret_data(secret["data"])
        self.assertEqual(decoded_data["config_value"], "test-config")
        self.assertEqual(decoded_data["environment"], "testing")
        self.assertEqual(decoded_data["debug"], "True")  # Booleans become strings
        self.assertEqual(
            decoded_data["max_connections"], "100"
        )  # Numbers become strings

        print("✅ All Kubernetes secrets verified successfully!")

    def test_kubernetes_ini_base64_secretstore_integration(self):
        """Test loading secrets with ini+base64:// instructions into Kubernetes"""

        # Copy the test ini file to a temporary location accessible by the test
        test_config_file = "/tmp/test-config.ini"
        with open(self.test_dir / "test-config.ini", "r") as src:
            with open(test_config_file, "w") as dst:
                dst.write(src.read())

        # Load the test values file with ini+base64:// instructions
        test_values_file = str(self.test_dir / "test-values-secret-v3-k8s.yaml")

        # Create a playbook to test Kubernetes secretstore with ini+base64://
        playbook_content = f"""---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Load secrets with ini+base64 into Kubernetes
      rhvp.cluster_utils.vault_load_secrets:
        values_secrets: "{test_values_file}"
        namespace: "unused-for-k8s"
        pod: "unused-for-k8s"
      environment:
        KUBECONFIG: "{self.kubeconfig_file}"
      register: result

    - name: Display result
      debug:
        var: result
"""

        # Write playbook to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(playbook_content)
            playbook_file = f.name

        try:
            # Set environment for kubernetes mode
            env = os.environ.copy()
            env["ANSIBLE_COLLECTIONS_PATH"] = str(self.collection_root.parent.parent)
            env["KUBECONFIG"] = str(self.kubeconfig_file)

            # Run the playbook
            result = subprocess.run(
                ["ansible-playbook", "-v", playbook_file],
                cwd=self.collection_root,
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            print("Ansible playbook output for ini+base64:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            print("Return code:", result.returncode)

            # The playbook should succeed
            self.assertEqual(
                result.returncode, 0, f"Ansible playbook failed: {result.stderr}"
            )
            self.assertIn("secrets injected", result.stdout.lower())

        finally:
            # Clean up temp files
            os.unlink(playbook_file)
            if os.path.exists(test_config_file):
                os.unlink(test_config_file)

        # Verify ini+base64 secrets were created correctly in Kubernetes
        self._verify_ini_base64_secrets_in_kubernetes()

    def _verify_ini_base64_secrets_in_kubernetes(self):
        """Verify that ini+base64:// secrets were properly created in Kubernetes"""

        # Test k8s-test-ini-base64 secret
        print("Checking k8s-test-ini-base64 secret...")
        secret = self._get_secret("k8s-test-ini-base64", "test-secrets")
        self.assertIsNotNone(
            secret, "k8s-test-ini-base64 secret not found in test-secrets namespace"
        )

        # Verify metadata and labels
        metadata = secret["metadata"]
        self.assertEqual(metadata["labels"]["app"], "config-test")
        self.assertEqual(metadata["labels"]["test-type"], "ini-base64")

        # Verify secret data
        decoded_data = self._decode_secret_data(secret["data"])

        # Verify plain ini:// value (should be plain text)
        self.assertEqual(decoded_data["plain_value"], "test_api_key_12345")

        # Verify ini+base64:// values (should be base64 encoded, then base64 decoded by Kubernetes)
        # When we put base64 content into Kubernetes, it gets base64 encoded again by k8s
        # So we need to decode what we expect to find
        import base64

        # Test auth_token value - this should be the original ini value base64 encoded by our code
        encoded_auth_token = decoded_data["encoded_value"]
        # Decode our base64 encoding to get original ini value
        original_auth_token = base64.b64decode(encoded_auth_token).decode("utf-8")
        self.assertEqual(original_auth_token, "dGVzdF9hdXRoX3Rva2VuXzY3ODkw")

        # Test registry_auth with section
        encoded_registry_auth = decoded_data["encoded_with_section"]
        original_registry_auth = base64.b64decode(encoded_registry_auth).decode("utf-8")
        self.assertEqual(original_registry_auth, "dGVzdDp0ZXN0cGFzcw==")

        # Test database connection string
        encoded_db_connection = decoded_data["database_connection"]
        original_db_connection = base64.b64decode(encoded_db_connection).decode("utf-8")
        self.assertEqual(
            original_db_connection,
            "postgresql://testuser:testpass@localhost:5432/testdb",
        )

        # Test k8s-test-registry secret
        print("Checking k8s-test-registry secret...")
        registry_secret = self._get_secret("k8s-test-registry", "test-secrets")
        self.assertIsNotNone(
            registry_secret,
            "k8s-test-registry secret not found in test-secrets namespace",
        )

        # Verify type
        self.assertEqual(registry_secret["type"], "kubernetes.io/dockerconfigjson")

        # Verify registry data - dockerconfigjson secrets should have .dockerconfigjson field
        registry_data = self._decode_secret_data(registry_secret["data"])
        self.assertIn(".dockerconfigjson", registry_data)

        # Parse the docker config JSON
        import json

        docker_config = json.loads(registry_data[".dockerconfigjson"])

        # Verify the structure
        self.assertIn("auths", docker_config)
        self.assertIn("registry.example.com", docker_config["auths"])

        # Verify the auth data
        auth_data = docker_config["auths"]["registry.example.com"]
        self.assertEqual(auth_data["username"], "testuser")  # Plain ini:// value

        # Auth field should contain the base64 encoded credentials from ini file
        # The auth_data field from ini+base64:// is double-base64 encoded
        # Original ini value: dGVzdDp0ZXN0cGFzcw== (base64 "test:testpass")
        # After ini+base64://: ZEdWemREcDBaWE4wY0dGemN3PT0= (base64 of the above)
        self.assertEqual(auth_data["auth"], "ZEdWemREcDBaWE4wY0dGemN3PT0=")

        print("✅ All Kubernetes ini+base64:// secrets verified successfully!")

    def test_kubernetes_cluster_connection(self):
        """Simple test to verify cluster connection works"""
        result = self._kubectl_command("get", "nodes")
        self.assertEqual(
            result.returncode, 0, f"Failed to connect to cluster: {result.stderr}"
        )
        self.assertIn("Ready", result.stdout, "No ready nodes found")

    def test_kubernetes_namespaces(self):
        """Test that required namespaces exist"""
        namespaces = [
            "default",
            "test-namespace",
            "production",
            "test-secrets",
            "app-namespace",
        ]
        for namespace in namespaces:
            result = self._kubectl_command("get", "namespace", namespace)
            self.assertEqual(result.returncode, 0, f"Namespace {namespace} not found")


if __name__ == "__main__":
    # Check if kind and kubectl are available
    try:
        subprocess.run(["kind", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: kind is not available. Kubernetes integration tests cannot run.")
        print("Install kind: https://kind.sigs.k8s.io/docs/user/quick-start/")
        sys.exit(1)

    try:
        subprocess.run(
            ["kubectl", "version", "--client"], capture_output=True, check=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(
            "ERROR: kubectl is not available. Kubernetes integration tests cannot run."
        )
        print("Install kubectl: https://kubernetes.io/docs/tasks/tools/")
        sys.exit(1)

    unittest.main(verbosity=2)
