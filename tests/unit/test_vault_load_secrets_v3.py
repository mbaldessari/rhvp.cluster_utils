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
Simple module to test vault_load_secrets v3
"""

import base64
import json
import os
import unittest
from typing import Any, Dict
from unittest import mock
from unittest.mock import patch

import yaml
from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes
from ansible_collections.rhvp.cluster_utils.plugins.module_utils import load_secrets_v3
from ansible_collections.rhvp.cluster_utils.plugins.modules import vault_load_secrets


def set_module_args(args: Dict[str, Any]) -> None:
    """prepare arguments so that they will be picked up during module creation"""
    args_json = json.dumps({"ANSIBLE_MODULE_ARGS": args})
    basic._ANSIBLE_ARGS = to_bytes(args_json)


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""

    pass


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""

    pass


def exit_json(*args: Any, **kwargs: Any) -> None:
    """function to patch over exit_json; package return data into an exception"""
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args: Any, **kwargs: Any) -> None:
    """function to patch over fail_json; package return data into an exception"""
    kwargs["failed"] = True
    kwargs["args"] = args
    raise AnsibleFailJson(kwargs)


@mock.patch("getpass.getpass")
class TestVaultLoadSecretsV3(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_module_helper = patch.multiple(
            basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)
        self.orig_home = os.environ["HOME"]
        self.testdir_v3 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v3")
        os.environ["HOME"] = self.testdir_v3
        self.test_file = os.path.expanduser("~/test-file-contents")

    def tearDown(self) -> None:
        os.environ["HOME"] = self.orig_home

    def test_module_fail_when_required_args_missing(
        self, getpass: mock.MagicMock
    ) -> None:
        with self.assertRaises(AnsibleFailJson):
            set_module_args({})
            vault_load_secrets.main()

    def test_parse_field_instruction_file_base64(self, getpass: mock.MagicMock) -> None:
        """Test parsing of file+base64:// instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test file+base64:// parsing
        field_type, param, is_optional = secrets._parse_field_instruction(
            "file+base64://path/to/file"
        )
        self.assertEqual(field_type, "file_base64")
        self.assertEqual(param, "path/to/file")
        self.assertFalse(is_optional)

        # Test regular file:// parsing still works
        field_type, param, is_optional = secrets._parse_field_instruction(
            "file://path/to/file"
        )
        self.assertEqual(field_type, "file")
        self.assertEqual(param, "path/to/file")
        self.assertFalse(is_optional)

        # Test ini:// parsing
        field_type, param, is_optional = secrets._parse_field_instruction(
            "ini://~/.aws/credentials:default:aws_access_key_id"
        )
        self.assertEqual(field_type, "ini")
        self.assertEqual(param, "~/.aws/credentials:default:aws_access_key_id")
        self.assertFalse(is_optional)

        # Test static value
        field_type, param, is_optional = secrets._parse_field_instruction(
            "static_value"
        )
        self.assertEqual(field_type, "static")
        self.assertEqual(param, "static_value")
        self.assertFalse(is_optional)

    def test_get_field_value_file_base64(self, getpass):
        """Test getting field value for file+base64:// instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test file+base64:// value retrieval
        instruction = f"file+base64://{self.test_file}"

        # Get the expected base64 content
        with open(self.test_file, "rb") as f:
            file_content = f.read()
        expected_b64 = base64.b64encode(file_content).decode("utf-8")

        result = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertEqual(result, expected_b64)

    def test_validate_field_file_base64(self, getpass):
        """Test validation of file+base64:// field instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test valid file+base64:// instruction
        instruction = f"file+base64://{self.test_file}"
        result = secrets._validate_field(
            "test_secret", "test_field", instruction, "vault"
        )
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test invalid file+base64:// instruction (non-existent file)
        instruction = "file+base64://nonexistent/file"
        result = secrets._validate_field(
            "test_secret", "test_field", instruction, "vault"
        )
        self.assertFalse(result[0])
        self.assertIn("file not found", result[1])

    def test_file_base64_validation(self, getpass):
        """Test file+base64:// validation functionality"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test valid file+base64:// instruction with test file
        instruction = f"file+base64://{self.test_file}"
        result = secrets._validate_field(
            "test_secret", "test_field", instruction, "vault"
        )
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test invalid file+base64:// instruction (non-existent file)
        instruction = "file+base64://nonexistent/file"
        result = secrets._validate_field(
            "test_secret", "test_field", instruction, "vault"
        )
        self.assertFalse(result[0])
        self.assertIn("file not found", result[1])

    def test_file_base64_encoding_behavior(self, getpass):
        """Test that file+base64:// always base64 encodes content"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Get value from file+base64:// method
        file_base64_instruction = f"file+base64://{self.test_file}"
        file_base64_value = secrets._get_field_value(
            "test_secret", "test_field", file_base64_instruction
        )

        # Read the file content directly for comparison
        with open(self.test_file, "rb") as f:
            file_content = f.read()
        expected_b64 = base64.b64encode(file_content).decode("utf-8")

        # Verify the base64 value matches expected encoding
        self.assertEqual(file_base64_value, expected_b64)

        # Verify it's valid base64 by decoding it
        try:
            decoded_bytes = base64.b64decode(file_base64_value)
            # This should succeed without exception
            self.assertIsInstance(decoded_bytes, bytes)
        except Exception as e:
            self.fail(f"file+base64:// output is not valid base64: {e}")

    def test_parse_ini_spec(self, getpass):
        """Test INI specification parsing"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test full format: file:section:key
        file_path, section, key = secrets._parse_ini_spec(
            "~/.aws/credentials:default:aws_access_key_id"
        )
        self.assertEqual(file_path, "~/.aws/credentials")
        self.assertEqual(section, "default")
        self.assertEqual(key, "aws_access_key_id")

        # Test short format: file:key (defaults to 'default' section)
        file_path, section, key = secrets._parse_ini_spec("~/.aws/config:region")
        self.assertEqual(file_path, "~/.aws/config")
        self.assertEqual(section, "default")
        self.assertEqual(key, "region")

        # Test custom section
        file_path, section, key = secrets._parse_ini_spec(
            "/etc/config.ini:database:password"
        )
        self.assertEqual(file_path, "/etc/config.ini")
        self.assertEqual(section, "database")
        self.assertEqual(key, "password")

    def test_parse_ini_spec_errors(self, getpass):
        """Test INI specification parsing error cases"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test invalid format (too few parts)
        with self.assertRaises(ValueError) as cm:
            secrets._parse_ini_spec("onlyfile")
        self.assertIn("Invalid ini specification format", str(cm.exception))

        # Test invalid format (too many parts)
        with self.assertRaises(ValueError) as cm:
            secrets._parse_ini_spec("file:section:key:extra")
        self.assertIn("Invalid ini specification format", str(cm.exception))

        # Test empty file path
        with self.assertRaises(ValueError) as cm:
            secrets._parse_ini_spec(":section:key")
        self.assertIn("File path cannot be empty", str(cm.exception))

        # Test empty key
        with self.assertRaises(ValueError) as cm:
            secrets._parse_ini_spec("file:section:")
        self.assertIn("Key cannot be empty", str(cm.exception))

    def test_read_ini_value(self, getpass):
        """Test reading values from INI files"""
        # Create a test ini file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[default]\n")
            f.write("api_key=test_api_key\n")
            f.write("region=us-east-1\n")
            f.write("\n")
            f.write("[custom]\n")
            f.write("database_url=postgresql://localhost/test\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test reading from default section
            value = secrets._read_ini_value(ini_file_path, "default", "api_key")
            self.assertEqual(value, "test_api_key")

            value = secrets._read_ini_value(ini_file_path, "default", "region")
            self.assertEqual(value, "us-east-1")

            # Test reading from custom section
            value = secrets._read_ini_value(ini_file_path, "custom", "database_url")
            self.assertEqual(value, "postgresql://localhost/test")

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_get_field_value_ini(self, getpass):
        """Test getting field value for ini:// instructions"""
        # Create a test ini file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[default]\n")
            f.write("access_key=AKIAIOSFODNN7EXAMPLE\n")
            f.write("secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
            f.write("\n")
            f.write("[production]\n")
            f.write("database_url=postgresql://prod-server/mydb\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test full format instruction
            instruction = f"ini://{ini_file_path}:default:access_key"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertEqual(result, "AKIAIOSFODNN7EXAMPLE")

            # Test short format instruction
            instruction = f"ini://{ini_file_path}:secret_key"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertEqual(result, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

            # Test custom section
            instruction = f"ini://{ini_file_path}:production:database_url"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertEqual(result, "postgresql://prod-server/mydb")

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_validate_field_ini(self, getpass):
        """Test validation of ini:// field instructions"""
        # Create a test ini file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[default]\ntest_key=test_value\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test valid ini:// instruction
            instruction = f"ini://{ini_file_path}:default:test_key"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertTrue(result[0])
            self.assertEqual(result[1], "")

            # Test invalid ini:// instruction (non-existent file)
            instruction = "ini:///nonexistent/file.ini:default:key"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertFalse(result[0])
            self.assertIn("ini file not found", result[1])

            # Test invalid ini:// instruction (bad format)
            instruction = "ini://invalid_format"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertFalse(result[0])
            self.assertIn("invalid ini specification", result[1])

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_get_backing_store_default(self, getpass):
        """Test that secretstore defaults to 'vault' when not specified"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test default secretstore
        backing_store = secrets._get_backing_store()
        self.assertEqual(backing_store, "vault")

    def test_get_backing_store_explicit(self, getpass):
        """Test that secretstore returns explicit value when specified"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secretstore": "vault", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test explicit secretstore
        backing_store = secrets._get_backing_store()
        self.assertEqual(backing_store, "vault")

    def test_validate_backing_store_vault_supported(self, getpass):
        """Test that 'vault' secretstore is valid"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "vault",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation passes for vault
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

    def test_validate_backing_store_unsupported(self, getpass):
        """Test that unsupported secretstores are rejected"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "consul",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation fails for unsupported secretstore
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("Unsupported secretstore: consul", result[1])
        self.assertIn(
            "Supported values: vault, kubernetes, aws-secrets-manager", result[1]
        )

    def test_validate_backing_store_default_works(self, getpass):
        """Test that validation works when secretstore is not specified (uses default)"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {"test_secret": {"field1": "value1"}}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation passes with default secretstore
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

    # Kubernetes secretstore tests
    def test_kubernetes_backing_store_validation(self, getpass):
        """Test that kubernetes secretstore validates correctly"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation passes for kubernetes
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

    def test_kubernetes_backing_store_rejects_generate(self, getpass):
        """Test that kubernetes secretstore rejects generate: instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"password": "generate:strong"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation fails for generate instruction
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("generate:", result[1])
        self.assertIn("not supported with kubernetes secretstore", result[1])

    def test_kubernetes_backing_store_rejects_vault_fields(self, getpass):
        """Test that kubernetes secretstore rejects vault-specific fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"targets": ["hub"], "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation fails for targets field
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("vault-specific field 'targets'", result[1])

    def test_vault_backing_store_rejects_kubernetes_fields(self, getpass):
        """Test that vault secretstore rejects kubernetes-specific fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "vault",
            "secrets": {"test_secret": {"namespaces": ["default"], "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation fails for namespaces field
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("kubernetes-specific field 'namespaces'", result[1])

    def test_kubernetes_namespaces_validation(self, getpass):
        """Test kubernetes namespaces field validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test single namespace string
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {"namespaces": "app-namespace", "field1": "value1"}
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test multiple namespaces array
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {
                    "namespaces": ["default", "app1", "app2"],
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test empty namespace string
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"namespaces": "", "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("namespaces cannot be empty", result[1])

        # Test empty namespaces array
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"namespaces": [], "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("namespaces list cannot be empty", result[1])

    def test_kubernetes_labels_annotations_validation(self, getpass):
        """Test kubernetes labels and annotations validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test valid labels and annotations
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {
                    "namespaces": "default",
                    "labels": {"app": "myapp", "env": "prod"},
                    "annotations": {"description": "test secret"},
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test invalid labels (non-dict)
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {
                    "namespaces": "default",
                    "labels": "invalid",
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("labels must be a dictionary", result[1])

        # Test invalid annotations (non-dict)
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {
                    "namespaces": "default",
                    "annotations": "invalid",
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("annotations must be a dictionary", result[1])

    def test_kubernetes_secret_type_validation(self, getpass):
        """Test kubernetes secret type validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test valid type
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {
                    "namespaces": "default",
                    "type": "Opaque",
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test empty type
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {
                "test_secret": {"namespaces": "default", "type": "", "field1": "value1"}
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("type must be a non-empty string", result[1])

    def test_get_namespaces_for_secret(self, getpass):
        """Test getting namespaces for kubernetes secrets"""
        # Create a mock module and kubernetes secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secretstore": "kubernetes", "secrets": {}}
        k8s_secrets = load_secrets_v3.LoadSecretsV3Kubernetes(module, syaml)

        # Test single namespace string
        secret_config = {"namespaces": "app-namespace"}
        namespaces = k8s_secrets._get_namespaces_for_secret(secret_config)
        self.assertEqual(namespaces, ["app-namespace"])

        # Test multiple namespaces array
        secret_config = {"namespaces": ["default", "app1", "app2"]}
        namespaces = k8s_secrets._get_namespaces_for_secret(secret_config)
        self.assertEqual(namespaces, ["default", "app1", "app2"])

        # Test default namespace when not specified
        secret_config = {}
        namespaces = k8s_secrets._get_namespaces_for_secret(secret_config)
        self.assertEqual(namespaces, ["validated-patterns-secrets"])

        # Test default namespace from settings
        syaml_with_settings = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "settings": {"namespace": "custom-namespace"},
            "secrets": {},
        }
        k8s_secrets_custom = load_secrets_v3.LoadSecretsV3Kubernetes(
            module, syaml_with_settings
        )
        secret_config = {}
        namespaces = k8s_secrets_custom._get_namespaces_for_secret(secret_config)
        self.assertEqual(namespaces, ["custom-namespace"])

    def test_get_secret_metadata(self, getpass):
        """Test getting secret metadata for kubernetes"""
        # Create a mock module and kubernetes secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secretstore": "kubernetes", "secrets": {}}
        k8s_secrets = load_secrets_v3.LoadSecretsV3Kubernetes(module, syaml)

        # Test secret type
        secret_config = {"type": "kubernetes.io/tls"}
        secret_type = k8s_secrets._get_secret_type(secret_config)
        self.assertEqual(secret_type, "kubernetes.io/tls")

        # Test default type
        secret_config = {}
        secret_type = k8s_secrets._get_secret_type(secret_config)
        self.assertEqual(secret_type, "Opaque")

        # Test labels
        secret_config = {"labels": {"app": "myapp", "env": "prod"}}
        labels = k8s_secrets._get_secret_labels(secret_config)
        self.assertEqual(labels, {"app": "myapp", "env": "prod"})

        # Test default labels
        secret_config = {}
        labels = k8s_secrets._get_secret_labels(secret_config)
        self.assertEqual(labels, {})

        # Test annotations
        secret_config = {"annotations": {"description": "test secret"}}
        annotations = k8s_secrets._get_secret_annotations(secret_config)
        self.assertEqual(annotations, {"description": "test secret"})

        # Test default annotations
        secret_config = {}
        annotations = k8s_secrets._get_secret_annotations(secret_config)
        self.assertEqual(annotations, {})

    # AWS Secrets Manager secretstore tests
    def test_aws_backing_store_validation(self, getpass):
        """Test that AWS Secrets Manager secretstore validates correctly"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation passes for aws-secrets-manager
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

    def test_aws_backing_store_rejects_generate(self, getpass):
        """Test that AWS secretstore rejects generate: instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"password": "generate:strong"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test validation fails for generate instruction
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("generate:", result[1])
        self.assertIn("not supported with aws-secrets-manager secretstore", result[1])

    def test_aws_backing_store_rejects_other_fields(self, getpass):
        """Test that AWS secretstore rejects vault/kubernetes-specific fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test rejects vault targets
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"targets": ["hub"], "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("not supported with aws-secrets-manager secretstore", result[1])

        # Test rejects kubernetes namespaces
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"namespaces": ["default"], "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("not supported with aws-secrets-manager secretstore", result[1])

    def test_aws_secret_name_validation(self, getpass):
        """Test AWS secret name validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test valid secretName
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "test_secret": {"secretName": "custom/secret", "field1": "value1"}
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test empty secretName
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"secretName": "", "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("secretName must be a non-empty string", result[1])

    def test_aws_tags_validation(self, getpass):
        """Test AWS tags validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test valid tags
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "test_secret": {
                    "tags": {"Environment": "production", "Team": "platform"},
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test invalid tags (non-dict)
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {"test_secret": {"tags": "invalid", "field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("tags must be a dictionary", result[1])

    def test_aws_automatic_rotation_validation(self, getpass):
        """Test AWS automatic rotation validation"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()

        # Test valid rotation config
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "test_secret": {
                    "automaticRotation": {
                        "enabled": True,
                        "rotationSchedule": "rate(30 days)",
                    },
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])

        # Test missing enabled field
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "test_secret": {
                    "automaticRotation": {"rotationSchedule": "rate(30 days)"},
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("must have 'enabled' field", result[1])

        # Test enabled but missing rotationSchedule
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {
                "test_secret": {
                    "automaticRotation": {"enabled": True},
                    "field1": "value1",
                }
            },
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn("requires 'rotationSchedule' when enabled", result[1])

    def test_get_secret_name_for_aws(self, getpass):
        """Test AWS secret name generation"""
        # Create a mock module and AWS secrets instance
        module = mock.MagicMock()

        # Test with prefix
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "awsConfig": {"prefix": "myapp/prod/"},
            "secrets": {},
        }
        aws_secrets = load_secrets_v3.LoadSecretsV3AWS(module, syaml)

        # Test custom secretName with prefix
        secret_config = {"secretName": "rds/credentials"}
        secret_name = aws_secrets._get_secret_name_for_aws("database", secret_config)
        self.assertEqual(secret_name, "myapp/prod/rds/credentials")

        # Test default name with prefix
        secret_config = {}
        secret_name = aws_secrets._get_secret_name_for_aws("api-config", secret_config)
        self.assertEqual(secret_name, "myapp/prod/api-config")

        # Test without prefix
        syaml_no_prefix = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {},
        }
        aws_secrets_no_prefix = load_secrets_v3.LoadSecretsV3AWS(
            module, syaml_no_prefix
        )

        secret_config = {"secretName": "custom-name"}
        secret_name = aws_secrets_no_prefix._get_secret_name_for_aws(
            "database", secret_config
        )
        self.assertEqual(secret_name, "custom-name")

    def test_get_secret_tags_merging(self, getpass):
        """Test AWS secret tags merging"""
        # Create a mock module and AWS secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "awsConfig": {
                "defaultTags": {
                    "Environment": "production",
                    "ManagedBy": "validated-patterns",
                }
            },
            "secrets": {},
        }
        aws_secrets = load_secrets_v3.LoadSecretsV3AWS(module, syaml)

        # Test merging default and secret-specific tags
        secret_config = {
            "tags": {
                "Application": "myapp",
                "Environment": "staging",  # Override default
            }
        }
        merged_tags = aws_secrets._get_secret_tags(secret_config)
        expected_tags = {
            "Environment": "staging",  # Secret-specific takes precedence
            "ManagedBy": "validated-patterns",  # From defaults
            "Application": "myapp",  # Secret-specific
        }
        self.assertEqual(merged_tags, expected_tags)

        # Test with no secret-specific tags
        secret_config = {}
        merged_tags = aws_secrets._get_secret_tags(secret_config)
        expected_tags = {"Environment": "production", "ManagedBy": "validated-patterns"}
        self.assertEqual(merged_tags, expected_tags)

    def test_get_secret_kms_key_id(self, getpass):
        """Test AWS KMS key ID resolution"""
        # Create a mock module and AWS secrets instance
        module = mock.MagicMock()
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "awsConfig": {"defaultKmsKeyId": "alias/default-key"},
            "secrets": {},
        }
        aws_secrets = load_secrets_v3.LoadSecretsV3AWS(module, syaml)

        # Test secret-specific KMS key
        secret_config = {"kmsKeyId": "alias/custom-key"}
        kms_key_id = aws_secrets._get_secret_kms_key_id(secret_config)
        self.assertEqual(kms_key_id, "alias/custom-key")

        # Test default KMS key
        secret_config = {}
        kms_key_id = aws_secrets._get_secret_kms_key_id(secret_config)
        self.assertEqual(kms_key_id, "alias/default-key")

        # Test no default KMS key
        syaml_no_default = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "secrets": {},
        }
        aws_secrets_no_default = load_secrets_v3.LoadSecretsV3AWS(
            module, syaml_no_default
        )
        secret_config = {}
        kms_key_id = aws_secrets_no_default._get_secret_kms_key_id(secret_config)
        self.assertIsNone(kms_key_id)

    # Optional field tests
    def test_parse_optional_field_instruction(self, getpass):
        """Test parsing of optional field instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test object form with optional=true
        instruction = {"value": "file://path/to/file", "optional": True}
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "file")
        self.assertEqual(param, "path/to/file")
        self.assertTrue(is_optional)

        # Test object form with optional=false
        instruction = {"value": "prompt:Enter password", "optional": False}
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "prompt")
        self.assertEqual(param, "Enter password")
        self.assertFalse(is_optional)

        # Test object form without optional (defaults to false)
        instruction = {"value": "static_value"}
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "static")
        self.assertEqual(param, "static_value")
        self.assertFalse(is_optional)

        # Test various instruction types in object form
        instruction = {"value": "file+base64://path/to/binary", "optional": True}
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "file_base64")
        self.assertEqual(param, "path/to/binary")
        self.assertTrue(is_optional)

        instruction = {"value": "ini://~/.config/app.ini:default:key", "optional": True}
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "ini")
        self.assertEqual(param, "~/.config/app.ini:default:key")
        self.assertTrue(is_optional)

        instruction = {
            "value": "ini+base64://~/.config/app.ini:default:token",
            "optional": True,
        }
        field_type, param, is_optional = secrets._parse_field_instruction(instruction)
        self.assertEqual(field_type, "ini_base64")
        self.assertEqual(param, "~/.config/app.ini:default:token")
        self.assertTrue(is_optional)

    def test_parse_field_instruction_ini_base64(self, getpass):
        """Test parsing of ini+base64:// instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test ini+base64:// parsing with full format
        field_type, param, is_optional = secrets._parse_field_instruction(
            "ini+base64://~/.docker/config.json:auths:registry.example.com:auth"
        )
        self.assertEqual(field_type, "ini_base64")
        self.assertEqual(param, "~/.docker/config.json:auths:registry.example.com:auth")
        self.assertFalse(is_optional)

        # Test ini+base64:// parsing with short format
        field_type, param, is_optional = secrets._parse_field_instruction(
            "ini+base64://~/.aws/credentials:secret_key"
        )
        self.assertEqual(field_type, "ini_base64")
        self.assertEqual(param, "~/.aws/credentials:secret_key")
        self.assertFalse(is_optional)

        # Test regular ini:// parsing still works
        field_type, param, is_optional = secrets._parse_field_instruction(
            "ini://~/.aws/credentials:access_key"
        )
        self.assertEqual(field_type, "ini")
        self.assertEqual(param, "~/.aws/credentials:access_key")
        self.assertFalse(is_optional)

    def test_validate_field_ini_base64(self, getpass):
        """Test validation of ini+base64:// field instructions"""
        # Create a test ini file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(
                "[default]\ntest_key=test_value\nauth_token=dGVzdF90b2tlbl92YWx1ZQ==\n"
            )
            f.write("[registry]\nauth=base64encodedauth\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test valid ini+base64:// instruction with full format
            instruction = f"ini+base64://{ini_file_path}:registry:auth"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertTrue(result[0])
            self.assertEqual(result[1], "")

            # Test valid ini+base64:// instruction with short format
            instruction = f"ini+base64://{ini_file_path}:auth_token"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertTrue(result[0])
            self.assertEqual(result[1], "")

            # Test invalid ini+base64:// instruction (non-existent file)
            instruction = "ini+base64:///nonexistent/file.ini:default:key"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertFalse(result[0])
            self.assertIn("ini file not found", result[1])

            # Test invalid ini+base64:// instruction (bad format)
            instruction = "ini+base64://invalid_format"
            result = secrets._validate_field(
                "test_secret", "test_field", instruction, "vault"
            )
            self.assertFalse(result[0])
            self.assertIn("invalid ini specification", result[1])

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_get_field_value_ini_base64(self, getpass):
        """Test getting field value for ini+base64:// instructions"""
        # Create a test ini file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[default]\n")
            f.write("api_key=my_secret_api_key\n")
            f.write("encoded_token=dGVzdF90b2tlbl92YWx1ZQ==\n")
            f.write("\n")
            f.write("[docker_config]\n")
            f.write("auth_token=plain_text_auth_token\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test full format instruction
            instruction = f"ini+base64://{ini_file_path}:default:api_key"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            # Should be base64 encoded version of "my_secret_api_key"
            expected_b64 = base64.b64encode("my_secret_api_key".encode("utf-8")).decode(
                "utf-8"
            )
            self.assertEqual(result, expected_b64)

            # Verify it decodes correctly
            decoded = base64.b64decode(result).decode("utf-8")
            self.assertEqual(decoded, "my_secret_api_key")

            # Test short format instruction
            instruction = f"ini+base64://{ini_file_path}:encoded_token"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            # Should be base64 encoded version of "dGVzdF90b2tlbl92YWx1ZQ=="
            expected_b64 = base64.b64encode(
                "dGVzdF90b2tlbl92YWx1ZQ==".encode("utf-8")
            ).decode("utf-8")
            self.assertEqual(result, expected_b64)

            # Test custom section
            instruction = f"ini+base64://{ini_file_path}:docker_config:auth_token"
            result = secrets._get_field_value("test_secret", "test_field", instruction)
            expected_b64 = base64.b64encode(
                "plain_text_auth_token".encode("utf-8")
            ).decode("utf-8")
            self.assertEqual(result, expected_b64)

            # Verify it decodes correctly
            decoded = base64.b64decode(result).decode("utf-8")
            self.assertEqual(decoded, "plain_text_auth_token")

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_ini_base64_vs_ini_behavior(self, getpass):
        """Test that ini+base64:// properly base64 encodes while ini:// doesn't"""
        # Create a test ini file
        import os
        import tempfile

        test_value = "test_secret_value_123"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(f"[default]\ntest_key={test_value}\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Get value from regular ini:// instruction
            ini_instruction = f"ini://{ini_file_path}:test_key"
            ini_value = secrets._get_field_value(
                "test_secret", "test_field", ini_instruction
            )

            # Get value from ini+base64:// instruction
            ini_base64_instruction = f"ini+base64://{ini_file_path}:test_key"
            ini_base64_value = secrets._get_field_value(
                "test_secret", "test_field", ini_base64_instruction
            )

            # Regular ini should return plain text
            self.assertEqual(ini_value, test_value)

            # ini+base64 should return base64 encoded version
            expected_b64 = base64.b64encode(test_value.encode("utf-8")).decode("utf-8")
            self.assertEqual(ini_base64_value, expected_b64)

            # Values should be different
            self.assertNotEqual(ini_value, ini_base64_value)

            # Decoding the base64 value should give original
            decoded = base64.b64decode(ini_base64_value).decode("utf-8")
            self.assertEqual(decoded, test_value)
            self.assertEqual(decoded, ini_value)

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_optional_field_ini_base64_handling(self, getpass):
        """Test optional ini+base64:// fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test optional ini+base64:// file that doesn't exist
        instruction = {
            "value": "ini+base64://nonexistent.ini:section:key",
            "optional": True,
        }
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNone(value)  # Should return None, not fail

        # Test optional ini+base64:// key that doesn't exist in existing file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[section1]\nkey1=value1\n")
            ini_file_path = f.name

        try:
            instruction = {
                "value": f"ini+base64://{ini_file_path}:section1:nonexistent_key",
                "optional": True,
            }
            value = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertIsNone(value)  # Should return None, not fail
        finally:
            os.unlink(ini_file_path)

    def test_optional_field_ini_base64_successful_read(self, getpass):
        """Test that optional ini+base64:// fields work normally when they succeed"""
        # Create a test ini file
        import os
        import tempfile

        test_value = "successful_test_value"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write(f"[default]\ntest_key={test_value}\n")
            ini_file_path = f.name

        try:
            # Create a mock module and secrets instance
            module = mock.MagicMock()
            syaml = {"version": "3.0", "secrets": {}}
            secrets = load_secrets_v3.SecretsV3Base(module, syaml)

            # Test optional ini+base64:// that exists and succeeds
            instruction = {
                "value": f"ini+base64://{ini_file_path}:test_key",
                "optional": True,
            }
            value = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertIsNotNone(value)  # Should return actual base64 encoded content

            # Verify it's properly base64 encoded
            expected_b64 = base64.b64encode(test_value.encode("utf-8")).decode("utf-8")
            self.assertEqual(value, expected_b64)

            # Verify it decodes back to original value
            decoded = base64.b64decode(value).decode("utf-8")
            self.assertEqual(decoded, test_value)

        finally:
            # Clean up
            os.unlink(ini_file_path)

    def test_parse_optional_field_validation_errors(self, getpass):
        """Test validation errors for optional field instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test object form without value key
        instruction = {"optional": True}
        with self.assertRaises(ValueError) as cm:
            secrets._parse_field_instruction(instruction)
        self.assertIn("must have 'value' key", str(cm.exception))

    def test_optional_field_value_handling(self, getpass):
        """Test that optional fields return None when they fail"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        module.fail_json.side_effect = AnsibleFailJson
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test optional file that doesn't exist
        instruction = {"value": "file://nonexistent/file.txt", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNone(value)  # Should return None, not fail

        # Test required file that doesn't exist (should fail)
        instruction = "file://nonexistent/file.txt"
        with self.assertRaises(
            AnsibleFailJson
        ):  # module.fail_json raises AnsibleFailJson
            secrets._get_field_value("test_secret", "test_field", instruction)

    def test_optional_field_ini_handling(self, getpass):
        """Test optional INI fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test optional INI file that doesn't exist
        instruction = {"value": "ini://nonexistent.ini:section:key", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNone(value)  # Should return None, not fail

        # Test optional INI key that doesn't exist in existing file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False) as f:
            f.write("[section1]\nkey1=value1\n")
            ini_file_path = f.name

        try:
            instruction = {
                "value": f"ini://{ini_file_path}:section1:nonexistent_key",
                "optional": True,
            }
            value = secrets._get_field_value("test_secret", "test_field", instruction)
            self.assertIsNone(value)  # Should return None, not fail
        finally:
            os.unlink(ini_file_path)

    def test_optional_field_prompt_handling(self, getpass):
        """Test optional prompt fields"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Mock getpass to raise KeyboardInterrupt (user cancels)
        getpass.side_effect = KeyboardInterrupt()

        # Test optional prompt that gets cancelled
        instruction = {"value": "prompt:Enter optional password", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNone(value)  # Should return None, not fail

        # Reset getpass mock
        getpass.side_effect = None
        getpass.return_value = "test_password"

    def test_optional_field_static_values_work(self, getpass):
        """Test that optional static values work normally"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test optional static string
        instruction = {"value": "static_string_value", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertEqual(value, "static_string_value")

        # Test optional static number
        instruction = {"value": 42, "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertEqual(value, "42")  # Static values are converted to strings

        # Test optional static boolean
        instruction = {"value": True, "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertEqual(value, "True")  # Static values are converted to strings

    def test_policies_only_valid_with_vault_secretstore(self, getpass):
        """Test that 'policies' field is only valid when secretstore is 'vault'"""
        # Create a mock module
        module = mock.MagicMock()

        # Test policies with vault secretstore - should pass
        syaml = {
            "version": "3.0",
            "secretstore": "vault",
            "policies": {"custom": {"length": 16, "charset": "alphanumeric"}},
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test policies with kubernetes secretstore - should fail
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "policies": {"custom": {"length": 16, "charset": "alphanumeric"}},
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn(
            "The 'policies' field is only valid when secretstore is 'vault'", result[1]
        )
        self.assertIn("but secretstore is 'kubernetes'", result[1])

        # Test policies with aws-secrets-manager secretstore - should fail
        syaml = {
            "version": "3.0",
            "secretstore": "aws-secrets-manager",
            "policies": {"custom": {"length": 16, "charset": "alphanumeric"}},
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn(
            "The 'policies' field is only valid when secretstore is 'vault'", result[1]
        )
        self.assertIn("but secretstore is 'aws-secrets-manager'", result[1])

        # Test no policies with non-vault secretstore - should pass
        syaml = {
            "version": "3.0",
            "secretstore": "kubernetes",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test no policies with vault secretstore - should pass
        syaml = {
            "version": "3.0",
            "secretstore": "vault",
            "secrets": {"test_secret": {"field1": "value1"}},
        }
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

    def test_policies_validation_with_sample_files(self, getpass):
        """Test policies validation using sample YAML files"""
        # Create a mock module
        module = mock.MagicMock()

        # Test that kubernetes with policies fails
        kubernetes_invalid_file = os.path.join(
            self.testdir_v3, "values-secret-v3-invalid-policies-kubernetes.yaml"
        )
        with open(kubernetes_invalid_file, "r", encoding="utf-8") as file:
            syaml = yaml.safe_load(file.read())

        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn(
            "The 'policies' field is only valid when secretstore is 'vault'", result[1]
        )
        self.assertIn("but secretstore is 'kubernetes'", result[1])

        # Test that aws with policies fails
        aws_invalid_file = os.path.join(
            self.testdir_v3, "values-secret-v3-invalid-policies-aws.yaml"
        )
        with open(aws_invalid_file, "r", encoding="utf-8") as file:
            syaml = yaml.safe_load(file.read())

        secrets = load_secrets_v3.SecretsV3Base(module, syaml)
        result = secrets._validate_secrets()
        self.assertFalse(result[0])
        self.assertIn(
            "The 'policies' field is only valid when secretstore is 'vault'", result[1]
        )
        self.assertIn("but secretstore is 'aws-secrets-manager'", result[1])

    def test_optional_field_successful_file_read(self, getpass):
        """Test that optional fields work normally when they succeed"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test optional file that exists
        instruction = {"value": f"file://{self.test_file}", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNotNone(value)  # Should return actual file content
        self.assertIn(
            "This space intentionally left blank", value
        )  # Should contain file content

        # Test optional file+base64 that exists
        instruction = {"value": f"file+base64://{self.test_file}", "optional": True}
        value = secrets._get_field_value("test_secret", "test_field", instruction)
        self.assertIsNotNone(value)  # Should return base64 encoded content


if __name__ == "__main__":
    unittest.main()
