#!/usr/bin/env python3
"""
Comprehensive unit tests for the v2 to v3 YAML converter.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

# Import the converter (adjust path as needed)
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from convert_v2_to_v3 import V2ToV3Converter  # noqa: E402


class TestV2ToV3Converter(unittest.TestCase):
    """Test cases for the V2ToV3Converter class"""

    def setUp(self):
        """Set up test fixtures"""
        self.converter = V2ToV3Converter()
        # Suppress log output during tests
        self.converter.log = lambda msg: self.converter.conversion_log.append(msg)

    def test_convert_vault_policies_basic(self):
        """Test basic vault policy conversion"""
        vault_policies = {
            "basic": """length=10
rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
rule "charset" { charset = "0123456789" min-chars = 1 }"""
        }

        result = self.converter.convert_vault_policies_to_policies(vault_policies)

        expected = {"basic": {"length": 10, "charset": "alphanumeric"}}

        self.assertEqual(result, expected)

    def test_convert_vault_policies_with_symbols(self):
        """Test vault policy conversion with symbols"""
        vault_policies = {
            "advanced": """length=20
rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
rule "charset" { charset = "0123456789" min-chars = 1 }
rule "charset" { charset = "!@#%^&*" min-chars = 1 }"""
        }

        result = self.converter.convert_vault_policies_to_policies(vault_policies)

        expected = {"advanced": {"length": 20, "charset": "alphanumeric_symbols"}}

        self.assertEqual(result, expected)

    def test_convert_vault_policies_no_length(self):
        """Test vault policy conversion when no length is specified"""
        vault_policies = {
            "no_length": """rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }"""
        }

        result = self.converter.convert_vault_policies_to_policies(vault_policies)

        expected = {
            "no_length": {
                "length": 16,  # default
                "charset": "alphanumeric",  # default when only lowercase found
            }
        }

        self.assertEqual(result, expected)

    def test_convert_backing_store(self):
        """Test backing store conversion"""
        test_cases = [
            ("vault", "vault"),
            ("k8s", "kubernetes"),
            ("kubernetes", "kubernetes"),
            ("none", "none"),
            ("VAULT", "vault"),  # case insensitive
            ("unknown", "vault"),  # default fallback
        ]

        for input_store, expected_output in test_cases:
            with self.subTest(input_store=input_store):
                result = self.converter.convert_backing_store(input_store)
                self.assertEqual(result, expected_output)

    def test_convert_field_simple_value(self):
        """Test converting a field with a simple value"""
        field = {"name": "username", "value": "admin"}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "username")
        self.assertEqual(field_value, "admin")

    def test_convert_field_file_path(self):
        """Test converting a field with a file path"""
        field = {"name": "certificate", "path": "/path/to/cert.pem"}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "certificate")
        self.assertEqual(field_value, "file:///path/to/cert.pem")

    def test_convert_field_file_path_base64(self):
        """Test converting a field with a base64 file path"""
        field = {"name": "certificate", "path": "/path/to/cert.pem", "base64": True}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "certificate")
        self.assertEqual(field_value, "file:///path/to/cert.pem.b64")

    def test_convert_field_generate(self):
        """Test converting a field with generation"""
        field = {
            "name": "password",
            "onMissingValue": "generate",
            "vaultPolicy": "basicPolicy",
        }

        field_name, field_value = self.converter.convert_field_to_v3(
            field, {"basicPolicy": "some_policy"}
        )

        self.assertEqual(field_name, "password")
        self.assertEqual(field_value, "generate:basicPolicy")

    def test_convert_field_generate_no_policy(self):
        """Test converting a field with generation but no policy"""
        field = {"name": "password", "onMissingValue": "generate"}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "password")
        self.assertEqual(field_value, "generate:basic")

    def test_convert_field_prompt(self):
        """Test converting a field that prompts for input"""
        field = {"name": "secret", "onMissingValue": "prompt"}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "secret")
        self.assertIsNone(field_value)

    def test_convert_field_optional_file(self):
        """Test converting a field with optional file"""
        field = {
            "name": "optional_cert",
            "path": "/path/to/cert.pem",
            "onMissingValue": "prompt",
        }

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "optional_cert")
        self.assertEqual(
            field_value, {"value": "file:///path/to/cert.pem", "optional": True}
        )

    def test_convert_field_null_path(self):
        """Test converting a field with null path"""
        field = {"name": "null_field", "path": None}

        field_name, field_value = self.converter.convert_field_to_v3(field, {})

        self.assertEqual(field_name, "null_field")
        self.assertIsNone(field_value)

    def test_convert_secrets(self):
        """Test converting a list of secrets to v3 format"""
        v2_secrets = [
            {
                "name": "app-config",
                "vaultPrefixes": ["hub", "spoke1"],
                "fields": [
                    {"name": "username", "value": "admin"},
                    {
                        "name": "password",
                        "onMissingValue": "generate",
                        "vaultPolicy": "basic",
                    },
                ],
            },
            {
                "name": "certificates",
                "fields": [{"name": "ca_cert", "path": "/certs/ca.pem"}],
            },
        ]

        vault_policies = {"basic": "some_policy"}
        result = self.converter.convert_secrets(v2_secrets, vault_policies)

        expected = {
            "app-config": {
                "username": "admin",
                "password": "generate:basic",
                "targets": ["hub", "spoke1"],
            },
            "certificates": {"ca_cert": "file:///certs/ca.pem"},
        }

        self.assertEqual(result, expected)

    def test_extract_global_settings(self):
        """Test extracting global settings from v2 secrets"""
        v2_secrets = [
            {"name": "secret1", "vaultPrefixes": ["hub", "spoke1"]},
            {"name": "secret2", "vaultPrefixes": ["hub", "spoke2"]},
        ]

        result = self.converter.extract_global_settings(v2_secrets)

        # Should extract unique prefixes as targets
        self.assertIsNotNone(result)
        self.assertIn("targets", result)
        self.assertCountEqual(result["targets"], ["hub", "spoke1", "spoke2"])

    def test_extract_global_settings_no_prefixes(self):
        """Test extracting global settings when no prefixes exist"""
        v2_secrets = [
            {"name": "secret1", "fields": [{"name": "test", "value": "value"}]}
        ]

        result = self.converter.extract_global_settings(v2_secrets)

        self.assertIsNone(result)

    def test_convert_file_complete_example(self):
        """Test converting a complete v2 file"""
        v2_data = {
            "version": "2.0",
            "backingStore": "vault",
            "vaultPolicies": {
                "basic": """length=12
rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
rule "charset" { charset = "0123456789" min-chars = 1 }"""
            },
            "secrets": [
                {
                    "name": "database",
                    "vaultPrefixes": ["hub"],
                    "fields": [
                        {"name": "username", "value": "dbuser"},
                        {
                            "name": "password",
                            "onMissingValue": "generate",
                            "vaultPolicy": "basic",
                        },
                        {"name": "ca_cert", "path": "/etc/ssl/ca.pem", "base64": True},
                    ],
                }
            ],
        }

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(v2_data, f)
            temp_path = f.name

        try:
            result = self.converter.convert_file(temp_path)

            expected_structure = {
                "version": "3.0",
                "secretstore": "vault",
                "policies": {"basic": {"length": 12, "charset": "alphanumeric"}},
                "settings": {"targets": ["hub"]},
                "secrets": {
                    "database": {
                        "username": "dbuser",
                        "password": "generate:basic",
                        "ca_cert": "file:///etc/ssl/ca.pem.b64",
                        "targets": ["hub"],
                    }
                },
            }

            self.assertEqual(result, expected_structure)

        finally:
            os.unlink(temp_path)

    def test_convert_file_invalid_version(self):
        """Test error handling for invalid version"""
        v2_data = {"version": "1.0", "secrets": []}  # Wrong version

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(v2_data, f)
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as context:
                self.converter.convert_file(temp_path)

            self.assertIn("expected '2.0'", str(context.exception))

        finally:
            os.unlink(temp_path)

    def test_convert_file_invalid_yaml(self):
        """Test error handling for invalid YAML"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [unclosed")
            temp_path = f.name

        try:
            with self.assertRaises(ValueError) as context:
                self.converter.convert_file(temp_path)

            self.assertIn("Error reading input file", str(context.exception))

        finally:
            os.unlink(temp_path)

    def test_write_output(self):
        """Test writing output to file"""
        v3_data = {"version": "3.0", "secrets": {"test": {"username": "testuser"}}}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            output_path = f.name

        try:
            self.converter.write_output(v3_data, output_path)

            # Verify file was written correctly
            with open(output_path, "r") as f:
                content = f.read()

            # Check for header comments
            self.assertIn("# Converted from version 2.0 to 3.0 format", content)

            # Check YAML content
            lines = content.split("\n")
            yaml_start = None
            for i, line in enumerate(lines):
                if line.strip().startswith("version:") and "3.0" in line:
                    yaml_start = i
                    break

            self.assertIsNotNone(yaml_start, "Could not find version line in output")

            # Parse the YAML part
            yaml_content = "\n".join(lines[yaml_start:])
            parsed_data = yaml.safe_load(yaml_content)
            self.assertEqual(parsed_data, v3_data)

        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_conversion_log(self):
        """Test that conversion logging works"""
        self.converter.log = lambda msg: self.converter.conversion_log.append(msg)

        vault_policies = {
            "test": """length=8
rule "charset" { charset = "abc" min-chars = 1 }"""
        }

        self.converter.convert_vault_policies_to_policies(vault_policies)

        # Should have logged conversion
        self.assertTrue(len(self.converter.conversion_log) > 0)
        self.assertTrue(
            any(
                "Converted policy 'test'" in msg
                for msg in self.converter.conversion_log
            )
        )

    def test_edge_case_empty_secrets(self):
        """Test handling of empty secrets list"""
        v2_data = {"version": "2.0", "backingStore": "vault", "secrets": []}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(v2_data, f)
            temp_path = f.name

        try:
            result = self.converter.convert_file(temp_path)

            expected = {"version": "3.0", "secretstore": "vault", "secrets": {}}

            self.assertEqual(result, expected)

        finally:
            os.unlink(temp_path)

    def test_edge_case_no_backing_store(self):
        """Test handling of missing backingStore"""
        v2_data = {"version": "2.0", "secrets": []}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(v2_data, f)
            temp_path = f.name

        try:
            result = self.converter.convert_file(temp_path)

            # Should not have secretstore if not specified
            self.assertNotIn("secretstore", result)
            self.assertEqual(result["version"], "3.0")

        finally:
            os.unlink(temp_path)

    def test_vault_mount_warning(self):
        """Test that vaultMount generates a warning"""
        v2_secrets = [
            {
                "name": "test-secret",
                "vaultMount": "custom-mount",
                "fields": [{"name": "test", "value": "value"}],
            }
        ]

        result = self.converter.convert_secrets(v2_secrets, {})

        # Check that warning was logged
        warning_logged = any(
            "vaultMount" in msg and "WARNING" in msg
            for msg in self.converter.conversion_log
        )
        self.assertTrue(
            warning_logged, "Expected warning about vaultMount not being logged"
        )

        # Check that secret was still converted
        self.assertIn("test-secret", result)
        self.assertEqual(result["test-secret"]["test"], "value")

    def test_real_v2_file_conversion(self):
        """Test conversion using actual v2 test files from the repository"""
        # This test uses the existing v2 test files to ensure compatibility
        test_dir = Path(__file__).parent / "v2"

        if not test_dir.exists():
            self.skipTest("v2 test directory not found")

        v2_base_file = test_dir / "values-secret-v2-base.yaml"

        if not v2_base_file.exists():
            self.skipTest("v2 base test file not found")

        try:
            result = self.converter.convert_file(str(v2_base_file))

            # Basic validation of the result
            self.assertEqual(result["version"], "3.0")
            self.assertIn("secrets", result)
            self.assertIsInstance(result["secrets"], dict)

            # If it had vaultPolicies, they should be converted to policies
            if "policies" in result:
                self.assertIsInstance(result["policies"], dict)
                for policy_name, policy in result["policies"].items():
                    self.assertIn("length", policy)
                    self.assertIn("charset", policy)

        except Exception as e:
            self.fail(f"Failed to convert real v2 file: {e}")


class TestConverterCLI(unittest.TestCase):
    """Test the command-line interface of the converter"""

    def test_main_function_exists(self):
        """Test that main function exists and is callable"""
        from convert_v2_to_v3 import main

        self.assertTrue(callable(main))

    @patch("sys.argv", ["convert_v2_to_v3.py", "--help"])
    def test_help_argument(self):
        """Test that help argument works"""
        from convert_v2_to_v3 import main

        # Should exit with 0 when showing help
        with self.assertRaises(SystemExit) as context:
            main()

        self.assertEqual(context.exception.code, 0)


if __name__ == "__main__":
    # Set up test environment
    print("Running V2 to V3 converter tests...")

    # Run tests with detailed output
    unittest.main(verbosity=2)
