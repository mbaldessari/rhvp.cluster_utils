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
Module that implements V3 of the values-secret.yaml spec
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import getpass
import os
import re
import time

from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    find_dupes,
    get_version,
)

# Default password policies for V3
DEFAULT_V3_POLICIES = {
    "basic": {
        "length": 16,
        "charset": "alphanumeric"
    },
    "medium": {
        "length": 20,
        "charset": "alphanumeric_symbols"
    },
    "strong": {
        "length": 32,
        "charset": "all"
    }
}

# Convert simplified charset names to vault policy format
CHARSET_MAPPINGS = {
    "alphanumeric": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789"
    },
    "alphanumeric_symbols": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "symbols": "!@#%^&*"
    },
    "all": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?"
    }
}


class SecretsV3Base:
    """
    Base class for V3 secrets handling with simplified syntax
    """

    def __init__(self, module, syaml):
        self.module = module
        self.syaml = syaml

    def _get_version(self):
        """Get version from YAML, ensuring it's 3.0"""
        version = get_version(self.syaml)
        if version != "3.0":
            self.module.fail_json(f"Version is not 3.0: {version}")
        return version

    def _get_settings(self):
        """Get global settings with defaults"""
        settings = self.syaml.get("settings", {})
        return {
            "targets": settings.get("targets", ["hub"]),
            "namespace": settings.get("namespace", "validated-patterns-secrets")
        }

    def _get_secrets(self):
        """Get secrets dictionary"""
        return self.syaml.get("secrets", {})

    def _get_policies(self):
        """Get vault policies, merging defaults with user-defined"""
        user_policies = self.syaml.get("policies", {})
        policies = DEFAULT_V3_POLICIES.copy()
        policies.update(user_policies)
        return policies

    def _convert_policy_to_vault_format(self, policy_config):
        """Convert simplified policy config to vault policy format"""
        length = policy_config.get("length", 16)
        charset = policy_config.get("charset", "alphanumeric")

        if charset not in CHARSET_MAPPINGS:
            self.module.fail_json(f"Unknown charset: {charset}")

        vault_policy = f"length={length}\n"

        charset_map = CHARSET_MAPPINGS[charset]
        for char_type, chars in charset_map.items():
            vault_policy += f'rule "charset" {{ charset = "{chars}" min-chars = 1 }}\n'

        return vault_policy

    def _get_vault_policies(self):
        """Get vault policies in vault format"""
        policies = self._get_policies()
        vault_policies = {}

        for name, config in policies.items():
            if isinstance(config, str):
                # Already in vault format
                vault_policies[name] = config
            else:
                # Convert from simplified format
                vault_policies[name] = self._convert_policy_to_vault_format(config)

        return vault_policies

    def _parse_field_instruction(self, instruction):
        """Parse a field instruction into type and parameters"""
        if not isinstance(instruction, str):
            return "static", instruction

        # Check for instruction patterns
        if instruction.startswith("file://"):
            return "file", instruction[7:]  # Remove file:// prefix
        elif instruction.startswith("generate:"):
            return "generate", instruction[9:]  # Remove generate: prefix
        elif instruction.startswith("prompt:"):
            return "prompt", instruction[7:]  # Remove prompt: prefix
        else:
            return "static", instruction

    def _validate_secrets(self):
        """Validate the V3 secrets structure"""
        secrets = self._get_secrets()
        if len(secrets) == 0:
            self.module.fail_json("No secrets found")

        # Check for duplicate secret names
        secret_names = list(secrets.keys())
        dupes = find_dupes(secret_names)
        if len(dupes) > 0:
            return (False, f"You cannot have duplicate secret names: {dupes}")

        # Validate each secret
        for secret_name, secret_config in secrets.items():
            result = self._validate_secret(secret_name, secret_config)
            if not result[0]:
                return result

        return (True, "")

    def _validate_secret(self, secret_name, secret_config):
        """Validate a single secret"""
        if not isinstance(secret_config, dict):
            return (False, f"Secret '{secret_name}' must be a dictionary")

        # Validate targets if specified
        if "targets" in secret_config:
            targets = secret_config["targets"]
            if not isinstance(targets, list) or len(targets) == 0:
                return (False, f"Secret '{secret_name}' targets must be a non-empty list")

        # Validate fields
        field_names = []
        for field_name, instruction in secret_config.items():
            if field_name == "targets":
                continue  # Skip targets field

            field_names.append(field_name)
            result = self._validate_field(secret_name, field_name, instruction)
            if not result[0]:
                return result

        # Check for duplicate field names
        field_dupes = find_dupes(field_names)
        if len(field_dupes) > 0:
            return (False, f"Secret '{secret_name}' has duplicate field names: {field_dupes}")

        return (True, "")

    def _validate_field(self, secret_name, field_name, instruction):
        """Validate a single field instruction"""
        field_type, param = self._parse_field_instruction(instruction)

        match field_type:
            case "static":
                # Static values are always valid
                return (True, "")
            case "file":
                if not param:
                    return (False, f"Secret '{secret_name}' field '{field_name}' has empty file path")
                # Check if file exists
                expanded_path = os.path.expanduser(param)
                if not os.path.isfile(expanded_path):
                    return (False, f"Secret '{secret_name}' field '{field_name}' file not found: {param}")
                return (True, "")
            case "generate":
                if not param:
                    return (False, f"Secret '{secret_name}' field '{field_name}' has empty policy name")
                # Check if policy exists
                policies = self._get_policies()
                if param not in policies:
                    return (False, f"Secret '{secret_name}' field '{field_name}' uses unknown policy: {param}")
                return (True, "")
            case "prompt":
                if not param:
                    return (False, f"Secret '{secret_name}' field '{field_name}' has empty prompt message")
                return (True, "")
            case _:
                return (False, f"Secret '{secret_name}' field '{field_name}' has unknown instruction type")

    def _get_field_value(self, secret_name, field_name, instruction):
        """Get the actual value for a field based on its instruction"""
        field_type, param = self._parse_field_instruction(instruction)

        match field_type:
            case "static":
                return param
            case "file":
                expanded_path = os.path.expanduser(param)
                try:
                    with open(expanded_path, 'r') as f:
                        content = f.read().strip()
                    # Auto-detect binary files and base64 encode them
                    if self._is_binary_file(expanded_path):
                        return base64.b64encode(content.encode()).decode('utf-8')
                    return content
                except Exception as e:
                    self.module.fail_json(f"Error reading file {param}: {str(e)}")
            case "prompt":
                prompt_text = f"{param}: "
                return getpass.getpass(prompt_text)
            case "generate":
                # This should be handled by the vault operations
                return None
            case _:
                self.module.fail_json(f"Unknown field type: {field_type}")

    def _is_binary_file(self, filepath):
        """Check if a file is binary (should be base64 encoded)"""
        binary_extensions = {'.crt', '.pem', '.key', '.p12', '.pfx', '.der', '.cer'}
        _, ext = os.path.splitext(filepath.lower())
        return ext in binary_extensions

    def sanitize_values(self):
        """Validate the V3 secrets structure"""
        self._get_version()  # Validates version is 3.0

        result = self._validate_secrets()
        if not result[0]:
            self.module.fail_json(result[1])


class LoadSecretsV3(SecretsV3Base):
    """
    V3 implementation for loading secrets into vault
    """

    def __init__(self, module, syaml, namespace, pod):
        super().__init__(module, syaml)
        self.namespace = namespace
        self.pod = pod

    def _run_command(self, command, attempts=1, sleep=3, checkrc=True):
        """
        Runs a command on the host ansible is running on. A failing command
        will raise an exception in this function directly (due to check=True)

        Parameters:
            command(str): The command to be run.
            attempts(int): Number of times to retry in case of Error (defaults to 1)
            sleep(int): Number of seconds to wait in between retry attempts (defaults to 3s)

        Returns:
            ret(subprocess.CompletedProcess): The return value from run()
        """
        for attempt in range(attempts):
            ret = self.module.run_command(
                command,
                check_rc=checkrc,
                use_unsafe_shell=True,
                environ_update=os.environ.copy(),
            )
            if ret[0] == 0:
                return ret
            if attempt >= attempts - 1:
                return ret
            time.sleep(sleep)

    def inject_vault_policies(self):
        """Inject vault policies for password generation"""
        for name, policy in self._get_vault_policies().items():
            cmd = (
                f"echo '{policy}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"'cat - > /tmp/{name}.hcl';"
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c 'vault write sys/policies/password/{name} "
                f" policy=@/tmp/{name}.hcl'"
            )
            self._run_command(cmd, attempts=3)

    def _inject_secret(self, secret_name, secret_config, mount="secret"):
        """Inject a single secret into vault"""
        settings = self._get_settings()
        targets = secret_config.get("targets", settings["targets"])

        field_count = 0
        for field_name, instruction in secret_config.items():
            if field_name == "targets":
                continue

            verb = "put" if field_count == 0 else "patch"
            self._inject_field(secret_name, field_name, instruction, mount, targets, verb)
            field_count += 1

    def _inject_field(self, secret_name, field_name, instruction, mount, targets, verb):
        """Inject a single field into vault"""
        field_type, param = self._parse_field_instruction(instruction)

        match field_type:
            case "generate":
                self._inject_generated_field(secret_name, field_name, param, mount, targets, verb)
            case _:
                value = self._get_field_value(secret_name, field_name, instruction)
                self._inject_static_field(secret_name, field_name, value, mount, targets, verb)

    def _inject_generated_field(self, secret_name, field_name, policy_name, mount, targets, verb):
        """Inject a generated field using vault policy"""
        gen_cmd = f"vault read -field=password sys/policies/password/{policy_name}/generate"

        for target in targets:
            cmd = (
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"\"{gen_cmd} | vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}=-\""
            )
            self._run_command(cmd, attempts=3)

    def _inject_static_field(self, secret_name, field_name, value, mount, targets, verb):
        """Inject a static field value"""
        for target in targets:
            cmd = (
                f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                f"\"vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}='{value}'\""
            )
            self._run_command(cmd, attempts=3)

    def inject_secrets(self):
        """Inject all secrets into vault"""
        # Inject vault policies first
        self.inject_vault_policies()

        secrets = self._get_secrets()
        total_secrets = 0

        for secret_name, secret_config in secrets.items():
            self._inject_secret(secret_name, secret_config)
            # Count fields, not secrets
            field_count = len([k for k in secret_config.keys() if k != "targets"])
            total_secrets += field_count

        return total_secrets