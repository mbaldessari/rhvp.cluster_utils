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
from unittest import mock
from unittest.mock import call, patch

from ansible.module_utils import basic
from ansible.module_utils.common.text.converters import to_bytes
from ansible_collections.rhvp.cluster_utils.plugins.module_utils import load_secrets_v3
from ansible_collections.rhvp.cluster_utils.plugins.modules import vault_load_secrets


def set_module_args(args):
    """prepare arguments so that they will be picked up during module creation"""
    args = json.dumps({"ANSIBLE_MODULE_ARGS": args})
    basic._ANSIBLE_ARGS = to_bytes(args)


class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""

    pass


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""

    pass


def exit_json(*args, **kwargs):
    """function to patch over exit_json; package return data into an exception"""
    if "changed" not in kwargs:
        kwargs["changed"] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """function to patch over fail_json; package return data into an exception"""
    kwargs["failed"] = True
    kwargs["args"] = args
    raise AnsibleFailJson(kwargs)


@mock.patch("getpass.getpass")
class TestVaultLoadSecretsV3(unittest.TestCase):

    def setUp(self):
        self.mock_module_helper = patch.multiple(
            basic.AnsibleModule, exit_json=exit_json, fail_json=fail_json
        )
        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)
        self.orig_home = os.environ["HOME"]
        self.testdir_v3 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v3")
        os.environ["HOME"] = self.testdir_v3
        self.test_file = os.path.expanduser("~/test-file-contents")

    def tearDown(self):
        os.environ["HOME"] = self.orig_home

    def test_module_fail_when_required_args_missing(self, getpass):
        with self.assertRaises(AnsibleFailJson):
            set_module_args({})
            vault_load_secrets.main()

    def test_parse_field_instruction_file_base64(self, getpass):
        """Test parsing of file+base64:// instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test file+base64:// parsing
        field_type, param = secrets._parse_field_instruction("file+base64://path/to/file")
        self.assertEqual(field_type, "file_base64")
        self.assertEqual(param, "path/to/file")

        # Test regular file:// parsing still works
        field_type, param = secrets._parse_field_instruction("file://path/to/file")
        self.assertEqual(field_type, "file")
        self.assertEqual(param, "path/to/file")

        # Test static value
        field_type, param = secrets._parse_field_instruction("static_value")
        self.assertEqual(field_type, "static")
        self.assertEqual(param, "static_value")

    def test_get_field_value_file_base64(self, getpass):
        """Test getting field value for file+base64:// instructions"""
        # Create a mock module and secrets instance
        module = mock.MagicMock()
        syaml = {"version": "3.0", "secrets": {}}
        secrets = load_secrets_v3.SecretsV3Base(module, syaml)

        # Test file+base64:// value retrieval
        instruction = f"file+base64://{self.test_file}"

        # Get the expected base64 content
        with open(self.test_file, 'rb') as f:
            file_content = f.read()
        expected_b64 = base64.b64encode(file_content).decode('utf-8')

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
        result = secrets._validate_field("test_secret", "test_field", instruction)
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test invalid file+base64:// instruction (non-existent file)
        instruction = "file+base64://nonexistent/file"
        result = secrets._validate_field("test_secret", "test_field", instruction)
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
        result = secrets._validate_field("test_secret", "test_field", instruction)
        self.assertTrue(result[0])
        self.assertEqual(result[1], "")

        # Test invalid file+base64:// instruction (non-existent file)
        instruction = "file+base64://nonexistent/file"
        result = secrets._validate_field("test_secret", "test_field", instruction)
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
        file_base64_value = secrets._get_field_value("test_secret", "test_field", file_base64_instruction)

        # Read the file content directly for comparison
        with open(self.test_file, 'rb') as f:
            file_content = f.read()
        expected_b64 = base64.b64encode(file_content).decode('utf-8')

        # Verify the base64 value matches expected encoding
        self.assertEqual(file_base64_value, expected_b64)

        # Verify it's valid base64 by decoding it
        try:
            decoded_bytes = base64.b64decode(file_base64_value)
            # This should succeed without exception
            self.assertIsInstance(decoded_bytes, bytes)
        except Exception as e:
            self.fail(f"file+base64:// output is not valid base64: {e}")


if __name__ == "__main__":
    unittest.main()