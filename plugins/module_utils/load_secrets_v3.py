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
import configparser
import getpass
import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    find_dupes,
    get_version,
)

# Default password policies for V3
DEFAULT_V3_POLICIES: Dict[str, Dict[str, Union[int, str]]] = {
    "basic": {"length": 16, "charset": "alphanumeric"},
    "medium": {"length": 20, "charset": "alphanumeric_symbols"},
    "strong": {"length": 32, "charset": "all"},
}

# Convert simplified charset names to vault policy format
CHARSET_MAPPINGS: Dict[str, Dict[str, str]] = {
    "alphanumeric": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
    },
    "alphanumeric_symbols": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "symbols": "!@#%^&*",
    },
    "all": {
        "lowercase": "abcdefghijklmnopqrstuvwxyz",
        "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    },
}


class SecretsV3Base:
    """
    Base class for V3 secrets handling with simplified syntax
    """

    def __init__(self, module: Any, syaml: Dict[str, Any]) -> None:
        self.module = module
        self.syaml = syaml
        # Initialize errors list for error collection
        self.errors: List[str] = []

    def _get_version(self) -> str:
        """Get version from YAML, ensuring it's 3.0"""
        version = get_version(self.syaml)
        if version != "3.0":
            self.module.fail_json(f"Version is not 3.0: {version}")
        return version

    def _get_settings(self) -> Dict[str, Any]:
        """Get global settings with defaults"""
        settings = self.syaml.get("settings", {})
        return {
            "targets": settings.get("targets", ["hub"]),
            "namespace": settings.get("namespace", "validated-patterns-secrets"),
        }

    def _get_backing_store(self) -> str:
        """Get backing store with default"""
        return self.syaml.get("secretstore", "vault")

    def _get_aws_config(self) -> Dict[str, Any]:
        """Get AWS configuration"""
        return self.syaml.get("awsConfig", {})

    def _get_secrets(self) -> Dict[str, Any]:
        """Get secrets dictionary"""
        return self.syaml.get("secrets", {})

    def _get_policies(self) -> Dict[str, Union[str, Dict[str, Union[int, str]]]]:
        """Get vault policies, merging defaults with user-defined"""
        user_policies = self.syaml.get("policies", {})
        # Create a new dict with explicit type to handle the variance issue
        policies: Dict[str, Union[str, Dict[str, Union[int, str]]]] = {}
        # Copy defaults first
        for k, v in DEFAULT_V3_POLICIES.items():
            policies[k] = v
        # Then update with user policies
        policies.update(user_policies)
        return policies

    def _convert_policy_to_vault_format(
        self, policy_config: Dict[str, Union[int, str]]
    ) -> str:
        """Convert simplified policy config to vault policy format"""
        length = policy_config.get("length", 16)
        charset = policy_config.get("charset", "alphanumeric")

        if charset not in CHARSET_MAPPINGS:
            self.module.fail_json(f"Unknown charset: {charset}")

        vault_policy = f"length={length}\n"

        charset_map = CHARSET_MAPPINGS[str(charset)]
        for char_type, chars in charset_map.items():
            vault_policy += f'rule "charset" {{ charset = "{chars}" min-chars = 1 }}\n'

        return vault_policy

    def _get_vault_policies(self) -> Dict[str, str]:
        """Get vault policies in vault format"""
        policies = self._get_policies()
        vault_policies: Dict[str, str] = {}

        for name, config in policies.items():
            if isinstance(config, str):
                # Already in vault format
                vault_policies[name] = config
            else:
                # Convert from simplified format
                vault_policies[name] = self._convert_policy_to_vault_format(config)

        return vault_policies

    def _parse_field_instruction(
        self, instruction: Union[str, Dict[str, Any], Any]
    ) -> Tuple[str, Any, bool]:
        """Parse a field instruction into type and parameters"""
        # Handle object form: {value: "instruction", optional: true}
        if isinstance(instruction, dict):
            if "value" not in instruction:
                raise ValueError("Object form field instruction must have 'value' key")
            actual_instruction = instruction["value"]
            is_optional = instruction.get("optional", False)
        else:
            # Handle simple form: "instruction"
            actual_instruction = instruction
            is_optional = False

        # Parse the actual instruction
        if not isinstance(actual_instruction, str):
            return "static", actual_instruction, is_optional

        # Check for instruction patterns
        if actual_instruction.startswith("file+base64://"):
            return (
                "file_base64",
                actual_instruction[14:],
                is_optional,
            )  # Remove file+base64:// prefix
        elif actual_instruction.startswith("ini+base64://"):
            return (
                "ini_base64",
                actual_instruction[13:],
                is_optional,
            )  # Remove ini+base64:// prefix
        elif actual_instruction.startswith("file://"):
            return "file", actual_instruction[7:], is_optional  # Remove file:// prefix
        elif actual_instruction.startswith("ini://"):
            return "ini", actual_instruction[6:], is_optional  # Remove ini:// prefix
        elif actual_instruction.startswith("generate:"):
            return (
                "generate",
                actual_instruction[9:],
                is_optional,
            )  # Remove generate: prefix
        elif actual_instruction.startswith("prompt:"):
            return (
                "prompt",
                actual_instruction[7:],
                is_optional,
            )  # Remove prompt: prefix
        else:
            return "static", actual_instruction, is_optional

    def _validate_secrets(self) -> Tuple[bool, str]:
        """Validate the V3 secrets structure"""
        # Validate backing store
        backing_store = self._get_backing_store()
        if backing_store not in ["vault", "kubernetes", "aws-secrets-manager"]:
            return (
                False,
                f"Unsupported secretstore: {backing_store}. Supported values: vault, kubernetes, aws-secrets-manager",
            )

        # Validate that policies are only used with vault secretstore
        if "policies" in self.syaml and backing_store != "vault":
            return (
                False,
                f"The 'policies' field is only valid when secretstore is 'vault', but secretstore is '{backing_store}'",
            )

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
            result = self._validate_secret(secret_name, secret_config, backing_store)
            if not result[0]:
                return result

        return (True, "")

    def _validate_secret(
        self, secret_name: str, secret_config: Any, backing_store: str
    ) -> Tuple[bool, str]:
        """Validate a single secret"""
        if not isinstance(secret_config, dict):
            return (False, f"Secret '{secret_name}' must be a dictionary")

        # Validate backing store specific fields
        if backing_store == "vault":
            # Validate targets if specified
            if "targets" in secret_config:
                targets = secret_config["targets"]
                if not isinstance(targets, list) or len(targets) == 0:
                    return (
                        False,
                        f"Secret '{secret_name}' targets must be a non-empty list",
                    )

            # Check for kubernetes-specific fields in vault mode
            kubernetes_fields = ["namespaces", "type", "labels", "annotations"]
            for k_field in kubernetes_fields:
                if k_field in secret_config:
                    return (
                        False,
                        f"Secret '{secret_name}' contains kubernetes-specific field '{k_field}' but secretstore is vault",
                    )

        elif backing_store == "kubernetes":
            # Validate namespaces if specified
            if "namespaces" in secret_config:
                namespaces = secret_config["namespaces"]
                if isinstance(namespaces, str):
                    if not namespaces.strip():
                        return (
                            False,
                            f"Secret '{secret_name}' namespaces cannot be empty",
                        )
                elif isinstance(namespaces, list):
                    if len(namespaces) == 0:
                        return (
                            False,
                            f"Secret '{secret_name}' namespaces list cannot be empty",
                        )
                    for ns in namespaces:
                        if not isinstance(ns, str) or not ns.strip():
                            return (
                                False,
                                f"Secret '{secret_name}' namespaces must be non-empty strings",
                            )
                else:
                    return (
                        False,
                        f"Secret '{secret_name}' namespaces must be a string or list of strings",
                    )

            # Validate kubernetes secret type if specified
            if "type" in secret_config:
                secret_type = secret_config["type"]
                if not isinstance(secret_type, str) or not secret_type.strip():
                    return (
                        False,
                        f"Secret '{secret_name}' type must be a non-empty string",
                    )

            # Validate labels if specified
            if "labels" in secret_config:
                labels = secret_config["labels"]
                if not isinstance(labels, dict):
                    return (
                        False,
                        f"Secret '{secret_name}' labels must be a dictionary",
                    )
                for key, value in labels.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        return (
                            False,
                            f"Secret '{secret_name}' labels keys and values must be strings",
                        )

            # Validate annotations if specified
            if "annotations" in secret_config:
                annotations = secret_config["annotations"]
                if not isinstance(annotations, dict):
                    return (
                        False,
                        f"Secret '{secret_name}' annotations must be a dictionary",
                    )
                for key, value in annotations.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        return (
                            False,
                            f"Secret '{secret_name}' annotations keys and values must be strings",
                        )

            # Check for vault-specific fields in kubernetes mode
            if "targets" in secret_config:
                return (
                    False,
                    f"Secret '{secret_name}' contains vault-specific field 'targets' but secretstore is kubernetes",
                )

        elif backing_store == "aws-secrets-manager":
            # Validate AWS-specific fields
            if "secretName" in secret_config:
                secret_name_value = secret_config["secretName"]
                if (
                    not isinstance(secret_name_value, str)
                    or not secret_name_value.strip()
                ):
                    return (
                        False,
                        f"Secret '{secret_name}' secretName must be a non-empty string",
                    )

            if "description" in secret_config:
                description = secret_config["description"]
                if not isinstance(description, str):
                    return (
                        False,
                        f"Secret '{secret_name}' description must be a string",
                    )

            if "kmsKeyId" in secret_config:
                kms_key_id = secret_config["kmsKeyId"]
                if not isinstance(kms_key_id, str) or not kms_key_id.strip():
                    return (
                        False,
                        f"Secret '{secret_name}' kmsKeyId must be a non-empty string",
                    )

            if "tags" in secret_config:
                tags = secret_config["tags"]
                if not isinstance(tags, dict):
                    return (False, f"Secret '{secret_name}' tags must be a dictionary")
                for key, value in tags.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        return (
                            False,
                            f"Secret '{secret_name}' tags keys and values must be strings",
                        )

            if "automaticRotation" in secret_config:
                rotation_config = secret_config["automaticRotation"]
                if not isinstance(rotation_config, dict):
                    return (
                        False,
                        f"Secret '{secret_name}' automaticRotation must be a dictionary",
                    )

                if "enabled" not in rotation_config:
                    return (
                        False,
                        f"Secret '{secret_name}' automaticRotation must have 'enabled' field",
                    )

                enabled = rotation_config["enabled"]
                if not isinstance(enabled, bool):
                    return (
                        False,
                        f"Secret '{secret_name}' automaticRotation enabled must be a boolean",
                    )

                if enabled:
                    if "rotationSchedule" not in rotation_config:
                        return (
                            False,
                            f"Secret '{secret_name}' automaticRotation requires 'rotationSchedule' when enabled",
                        )

            # Check for vault/kubernetes-specific fields in AWS mode
            invalid_fields = ["targets", "namespaces", "type", "labels", "annotations"]
            for field in invalid_fields:
                if field in secret_config:
                    return (
                        False,
                        f"Secret '{secret_name}' contains field '{field}' which is not supported with aws-secrets-manager secretstore",
                    )

        # Validate fields
        field_names = []
        reserved_fields = [
            "targets",
            "namespaces",
            "type",
            "labels",
            "annotations",
            "secretName",
            "description",
            "kmsKeyId",
            "tags",
            "automaticRotation",
        ]
        for field_name, instruction in secret_config.items():
            if field_name in reserved_fields:
                continue  # Skip reserved fields

            field_names.append(field_name)
            result = self._validate_field(
                secret_name, field_name, instruction, backing_store
            )
            if not result[0]:
                return result

        # Check for duplicate field names
        field_dupes = find_dupes(field_names)
        if len(field_dupes) > 0:
            return (
                False,
                f"Secret '{secret_name}' has duplicate field names: {field_dupes}",
            )

        return (True, "")

    def _validate_field(
        self,
        secret_name: str,
        field_name: str,
        instruction: Union[str, Dict[str, Any], Any],
        backing_store: str,
    ) -> Tuple[bool, str]:
        """Validate a single field instruction"""
        field_type, param, is_optional = self._parse_field_instruction(instruction)

        match field_type:
            case "static":
                # Static values are always valid
                return (True, "")
            case "file":
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty file path",
                    )
                # Check if file exists (skip for optional fields)
                if not is_optional:
                    expanded_path = os.path.expanduser(param)
                    if not os.path.isfile(expanded_path):
                        return (
                            False,
                            f"Secret '{secret_name}' field '{field_name}' file not found: {param}",
                        )
                return (True, "")
            case "file_base64":
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty file path",
                    )
                # Check if file exists (skip for optional fields)
                if not is_optional:
                    expanded_path = os.path.expanduser(param)
                    if not os.path.isfile(expanded_path):
                        return (
                            False,
                            f"Secret '{secret_name}' field '{field_name}' file not found: {param}",
                        )
                return (True, "")
            case "ini":
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty ini specification",
                    )
                # Parse and validate ini specification
                try:
                    file_path, section, key = self._parse_ini_spec(param)
                    # Check if file exists (skip for optional fields)
                    if not is_optional:
                        expanded_path = os.path.expanduser(file_path)
                        if not os.path.isfile(expanded_path):
                            return (
                                False,
                                f"Secret '{secret_name}' field '{field_name}' ini file not found: {file_path}",
                            )
                    return (True, "")
                except ValueError as e:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' invalid ini specification: {e}",
                    )
                return (True, "")
            case "ini_base64":
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty ini specification",
                    )
                # Parse and validate ini specification
                try:
                    file_path, section, key = self._parse_ini_spec(param)
                    # Check if file exists (skip for optional fields)
                    if not is_optional:
                        expanded_path = os.path.expanduser(file_path)
                        if not os.path.isfile(expanded_path):
                            return (
                                False,
                                f"Secret '{secret_name}' field '{field_name}' ini file not found: {file_path}",
                            )
                    return (True, "")
                except ValueError as e:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' invalid ini specification: {e}",
                    )
                return (True, "")
            case "generate":
                if backing_store in ["kubernetes", "aws-secrets-manager"]:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' uses 'generate:' instruction which is not supported with {backing_store} secretstore. Use 'prompt:' instead.",  # noqa: E501
                    )
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty policy name",
                    )
                # Check if policy exists
                policies = self._get_policies()
                if param not in policies:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' uses unknown policy: {param}",
                    )
                return (True, "")
            case "prompt":
                if not param:
                    return (
                        False,
                        f"Secret '{secret_name}' field '{field_name}' has empty prompt message",
                    )
                return (True, "")
            case _:
                return (
                    False,
                    f"Secret '{secret_name}' field '{field_name}' has unknown instruction type",
                )

    def _get_field_value(
        self,
        secret_name: str,
        field_name: str,
        instruction: Union[str, Dict[str, Any], Any],
    ) -> Optional[str]:
        """Get the actual value for a field based on its instruction"""
        field_type, param, is_optional = self._parse_field_instruction(instruction)

        try:
            return self._get_field_value_internal(
                field_type, param, secret_name, field_name
            )
        except Exception as e:
            error_msg = f"Secret '{secret_name}' field '{field_name}': {str(e)}"
            self.errors.append(error_msg)

            if is_optional:
                # For optional fields, return None and continue
                return None
            else:
                # For required fields, fail immediately
                self.module.fail_json(msg=error_msg)
                return None  # This line will never be reached, but satisfies mypy

    def _get_field_value_internal(
        self, field_type: str, param: Any, secret_name: str, field_name: str
    ) -> Optional[str]:
        """Internal method to get field value (can raise exceptions)"""
        match field_type:
            case "static":
                return str(param) if param is not None else None
            case "file":
                expanded_path = os.path.expanduser(param)
                try:
                    # Always read as text file - use file+base64:// for binary files
                    with open(expanded_path, "r") as f:
                        text_content = f.read().strip()
                    return text_content
                except Exception as e:
                    raise Exception(f"Error reading file {param}: {str(e)}")
            case "file_base64":
                expanded_path = os.path.expanduser(param)
                try:
                    with open(expanded_path, "rb") as f:
                        content = f.read()
                    # Always base64 encode the file content
                    return base64.b64encode(content).decode("utf-8")
                except Exception as e:
                    raise Exception(f"Error reading file {param}: {str(e)}")
            case "ini":
                try:
                    file_path, section, key = self._parse_ini_spec(param)
                    return self._read_ini_value(file_path, section, key)
                except Exception as e:
                    raise Exception(f"Error reading ini value {param}: {str(e)}")
            case "ini_base64":
                try:
                    file_path, section, key = self._parse_ini_spec(param)
                    value = self._read_ini_value(file_path, section, key)
                    # Base64 encode the INI value
                    return base64.b64encode(value.encode("utf-8")).decode("utf-8")
                except Exception as e:
                    raise Exception(f"Error reading ini value {param}: {str(e)}")
            case "prompt":
                prompt_text = f"{param}: "
                try:
                    return getpass.getpass(prompt_text)
                except (KeyboardInterrupt, EOFError):
                    raise Exception(f"Prompt cancelled for {param}")
            case "generate":
                # This should be handled by the vault operations
                return None
            case _:
                raise Exception(f"Unknown field type: {field_type}")

    def _parse_ini_spec(self, ini_spec: str) -> Tuple[str, str, str]:
        """
        Parse ini specification into file_path, section, and key

        Formats supported:
        - file_path:section:key
        - file_path:key (defaults to 'default' section)
        """
        parts = ini_spec.split(":")
        if len(parts) == 2:
            # file_path:key format (default section)
            file_path, key = parts
            section = "default"
        elif len(parts) == 3:
            # file_path:section:key format
            file_path, section, key = parts
        else:
            raise ValueError(
                f"Invalid ini specification format: {ini_spec}. Expected 'file:key' or 'file:section:key'"
            )

        if not file_path:
            raise ValueError("File path cannot be empty")
        if not key:
            raise ValueError("Key cannot be empty")
        if not section:
            raise ValueError("Section cannot be empty")

        return file_path, section, key

    def _read_ini_value(self, file_path: str, section: str, key: str) -> str:
        """Read a value from an INI file"""
        expanded_path = os.path.expanduser(file_path)

        config = configparser.ConfigParser()
        config.read(expanded_path)

        if section not in config:
            raise KeyError(f"Section '{section}' not found in {file_path}")

        if key not in config[section]:
            raise KeyError(
                f"Key '{key}' not found in section '{section}' of {file_path}"
            )

        return config[section][key]

    def sanitize_values(self) -> None:
        """Validate the V3 secrets structure"""
        self._get_version()  # Validates version is 3.0

        result = self._validate_secrets()
        if not result[0]:
            self.module.fail_json(result[1])


class LoadSecretsV3(SecretsV3Base):
    """
    V3 implementation for loading secrets into vault
    """

    def __init__(
        self, module: Any, syaml: Dict[str, Any], namespace: str, pod: str
    ) -> None:
        super().__init__(module, syaml)
        self.namespace = namespace
        self.pod = pod
        # Check for direct vault mode (for integration testing)
        self.direct_mode = os.environ.get("VAULT_DIRECT_MODE", "").lower() == "true"

    def _run_command(
        self, command: str, attempts: int = 1, sleep: int = 3, checkrc: bool = True
    ) -> Tuple[int, str, str]:
        """
        Runs a command on the host ansible is running on. A failing command
        will be logged as an error but processing will continue

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
                check_rc=False,  # Don't fail on error, let us handle it
                use_unsafe_shell=True,
                environ_update=os.environ.copy(),
            )
            if ret[0] == 0:
                return ret
            if attempt >= attempts - 1:
                # Log the error but don't fail
                error_msg = f"Command failed after {attempts} attempts: {command}\nError: {ret[2]}"
                self.errors.append(error_msg)
                return ret
            time.sleep(sleep)
        # This should never be reached, but satisfies mypy
        return (1, "", "Unexpected error")

    def inject_vault_policies(self) -> None:
        """Inject vault policies for password generation"""
        for name, policy in self._get_vault_policies().items():
            if self.direct_mode:
                # Direct mode: use podman exec to run commands in vault container
                vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
                vault_token = os.environ.get("VAULT_TOKEN", "myroot")
                cmd = (
                    f"echo '{policy}' | podman exec -i vault-test sh -c "
                    f"'cat - > /tmp/{name}.hcl';"
                    f"podman exec vault-test sh -c 'VAULT_ADDR={vault_addr} VAULT_TOKEN={vault_token} vault write sys/policies/password/{name} "
                    f" policy=@/tmp/{name}.hcl'"
                )
                self._run_command(cmd, attempts=3)
            else:
                # OpenShift mode: use oc exec
                cmd = (
                    f"echo '{policy}' | oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f"'cat - > /tmp/{name}.hcl';"
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c 'vault write sys/policies/password/{name} "
                    f" policy=@/tmp/{name}.hcl'"
                )
                self._run_command(cmd, attempts=3)

    def _inject_secret(
        self, secret_name: str, secret_config: Dict[str, Any], mount: str = "secret"
    ) -> None:
        """Inject a single secret into vault"""
        settings = self._get_settings()
        targets = secret_config.get("targets", settings["targets"])

        field_count = 0
        for field_name, instruction in secret_config.items():
            if field_name == "targets":
                continue

            verb = "put" if field_count == 0 else "patch"
            self._inject_field(
                secret_name, field_name, instruction, mount, targets, verb
            )
            field_count += 1

    def _inject_field(
        self,
        secret_name: str,
        field_name: str,
        instruction: Union[str, Dict[str, Any], Any],
        mount: str,
        targets: List[str],
        verb: str,
    ) -> None:
        """Inject a single field into vault"""
        field_type, param, is_optional = self._parse_field_instruction(instruction)

        match field_type:
            case "generate":
                self._inject_generated_field(
                    secret_name, field_name, param, mount, targets, verb
                )
            case _:
                value = self._get_field_value(secret_name, field_name, instruction)
                if value is not None:  # Only inject if value was successfully retrieved
                    self._inject_static_field(
                        secret_name, field_name, value, mount, targets, verb
                    )
                # If value is None (optional field failed), skip this field

    def _inject_generated_field(
        self,
        secret_name: str,
        field_name: str,
        policy_name: str,
        mount: str,
        targets: List[str],
        verb: str,
    ) -> None:
        """Inject a generated field using vault policy"""
        gen_cmd = (
            f"vault read -field=password sys/policies/password/{policy_name}/generate"
        )

        for target in targets:
            if self.direct_mode:
                # Direct mode: use podman exec to run commands in vault container
                vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
                vault_token = os.environ.get("VAULT_TOKEN", "myroot")
                cmd = f'podman exec vault-test sh -c "VAULT_ADDR={vault_addr} VAULT_TOKEN={vault_token} {gen_cmd} | VAULT_ADDR={vault_addr} VAULT_TOKEN={vault_token} vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}=-"'  # noqa: E501
            else:
                # OpenShift mode: use oc exec
                cmd = (
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f'"{gen_cmd} | vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}=-"'
                )
            ret = self._run_command(cmd, attempts=3)
            if ret[0] != 0:
                error_msg = f"Failed to inject generated field '{field_name}' for secret '{secret_name}' in target '{target}'"
                self.errors.append(error_msg)

    def _inject_static_field(
        self,
        secret_name: str,
        field_name: str,
        value: str,
        mount: str,
        targets: List[str],
        verb: str,
    ) -> None:
        """Inject a static field value"""
        for target in targets:
            if self.direct_mode:
                # Direct mode: use podman exec to run commands in vault container
                vault_addr = os.environ.get("VAULT_ADDR", "http://localhost:8200")
                vault_token = os.environ.get("VAULT_TOKEN", "myroot")
                cmd = f"podman exec vault-test sh -c \"VAULT_ADDR={vault_addr} VAULT_TOKEN={vault_token} vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}='{value}'\""  # noqa: E501
            else:
                # OpenShift mode: use oc exec
                cmd = (
                    f"oc exec -n {self.namespace} {self.pod} -i -- sh -c "
                    f"\"vault kv {verb} -mount={mount} {target}/{secret_name} {field_name}='{value}'\""
                )
            ret = self._run_command(cmd, attempts=3)
            if ret[0] != 0:
                error_msg = f"Failed to inject static field '{field_name}' for secret '{secret_name}' in target '{target}'"
                self.errors.append(error_msg)

    def inject_secrets(self) -> int:
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

        # Report any errors that occurred during processing
        if self.errors:
            error_summary = (
                f"Encountered {len(self.errors)} errors while processing secrets:\n"
            )
            for i, error in enumerate(self.errors, 1):
                error_summary += f"{i}. {error}\n"

            # Fail the module with all collected errors
            self.module.fail_json(msg=error_summary.strip())

        return total_secrets


class LoadSecretsV3Kubernetes(SecretsV3Base):
    """
    V3 implementation for loading secrets into Kubernetes
    """

    def __init__(self, module: Any, syaml: Dict[str, Any]) -> None:
        super().__init__(module, syaml)

    def _get_namespaces_for_secret(self, secret_config: Dict[str, Any]) -> List[str]:
        """Get the namespaces for a secret, either from config or default"""
        if "namespaces" in secret_config:
            namespaces = secret_config["namespaces"]
            if isinstance(namespaces, str):
                return [namespaces]
            elif isinstance(namespaces, list):
                return namespaces

        # Use default namespace from settings
        settings = self._get_settings()
        default_namespace = settings.get("namespace", "validated-patterns-secrets")
        return [default_namespace]

    def _get_secret_type(self, secret_config: Dict[str, Any]) -> str:
        """Get the Kubernetes secret type"""
        return secret_config.get("type", "Opaque")

    def _get_secret_labels(self, secret_config: Dict[str, Any]) -> Dict[str, str]:
        """Get the labels for the secret"""
        return secret_config.get("labels", {})

    def _get_secret_annotations(self, secret_config: Dict[str, Any]) -> Dict[str, str]:
        """Get the annotations for the secret"""
        return secret_config.get("annotations", {})

    def _create_kubernetes_secret(
        self, secret_name: str, secret_config: Dict[str, Any]
    ) -> int:
        """Create a Kubernetes secret"""
        namespaces = self._get_namespaces_for_secret(secret_config)
        secret_type = self._get_secret_type(secret_config)
        labels = self._get_secret_labels(secret_config)
        annotations = self._get_secret_annotations(secret_config)

        # Collect secret data
        secret_data: Dict[str, str] = {}
        reserved_fields = ["namespaces", "type", "labels", "annotations"]

        for field_name, instruction in secret_config.items():
            if field_name in reserved_fields:
                continue

            # Get the field value
            value = self._get_field_value(secret_name, field_name, instruction)
            if (
                value is not None
            ):  # Only include fields that were successfully processed
                secret_data[field_name] = value
            # If value is None (optional field failed), skip this field

        # Create secret in each namespace
        total_created = 0
        for namespace in namespaces:
            result = self._create_secret_in_namespace(
                secret_name, namespace, secret_type, labels, annotations, secret_data
            )
            if result:
                total_created += 1

        return total_created

    def _create_secret_in_namespace(
        self,
        secret_name: str,
        namespace: str,
        secret_type: str,
        labels: Dict[str, str],
        annotations: Dict[str, str],
        secret_data: Dict[str, str],
    ) -> bool:
        """Create a single Kubernetes secret in a specific namespace"""
        try:
            # Prepare secret manifest
            secret_manifest: Dict[str, Any] = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": secret_name,
                    "namespace": namespace,
                    "labels": labels,
                    "annotations": annotations,
                },
                "type": secret_type,
                "data": {},
            }

            # Handle special case for kubernetes.io/dockerconfigjson
            import base64
            import json

            if secret_type == "kubernetes.io/dockerconfigjson":
                # For dockerconfigjson secrets, create the required .dockerconfigjson field
                registry_url = secret_data.get("registry_url", "registry.example.com")
                username = secret_data.get("username", "")
                auth_data = secret_data.get("auth_data", "")

                # Create the docker config structure
                docker_config = {
                    "auths": {
                        registry_url: {
                            "username": username,
                            "auth": auth_data
                        }
                    }
                }

                # Only add password field if we have it
                if "password" in secret_data:
                    docker_config["auths"][registry_url]["password"] = secret_data["password"]

                docker_config_json = json.dumps(docker_config)
                secret_manifest["data"][".dockerconfigjson"] = base64.b64encode(
                    docker_config_json.encode("utf-8")
                ).decode("utf-8")
            else:
                # For other secret types, encode each field separately
                for key, value in secret_data.items():
                    if isinstance(value, str):
                        secret_manifest["data"][key] = base64.b64encode(
                            value.encode("utf-8")
                        ).decode("utf-8")
                    else:
                        # Convert non-string values to string first
                        secret_manifest["data"][key] = base64.b64encode(
                            str(value).encode("utf-8")
                        ).decode("utf-8")

            # Use kubectl to create the secret
            import tempfile

            # Write manifest to temporary file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as f:
                import yaml

                yaml.dump(secret_manifest, f)
                manifest_file = f.name

            try:
                # Apply the manifest using kubectl
                cmd = f"kubectl apply -f {manifest_file}"
                result = self.module.run_command(cmd, check_rc=False)

                if result[0] == 0:
                    return True
                else:
                    self.module.fail_json(
                        f"Failed to create secret {secret_name} in namespace {namespace}: {result[2]}"
                    )
                    return False
            finally:
                # Clean up temporary file
                import os

                os.unlink(manifest_file)

        except Exception as e:
            self.module.fail_json(
                f"Failed to create secret {secret_name} in namespace {namespace}: {str(e)}"
            )
            return False

    def inject_secrets(self) -> int:
        """Inject all secrets into Kubernetes"""
        secrets = self._get_secrets()
        total_secrets = 0

        for secret_name, secret_config in secrets.items():
            created_count = self._create_kubernetes_secret(secret_name, secret_config)
            total_secrets += created_count

        return total_secrets


class LoadSecretsV3AWS(SecretsV3Base):
    """
    V3 implementation for loading secrets into AWS Secrets Manager
    """

    def __init__(self, module: Any, syaml: Dict[str, Any]) -> None:
        super().__init__(module, syaml)

    def _get_secret_name_for_aws(
        self, secret_key: str, secret_config: Dict[str, Any]
    ) -> str:
        """Get the full secret name for AWS Secrets Manager"""
        aws_config = self._get_aws_config()
        prefix = aws_config.get("prefix", "")

        # Use custom secretName if provided, otherwise use the key
        if "secretName" in secret_config:
            secret_name = secret_config["secretName"]
        else:
            secret_name = secret_key

        # Apply prefix if configured
        if prefix:
            return f"{prefix}{secret_name}"
        else:
            return secret_name

    def _get_secret_description(self, secret_config: Dict[str, Any]) -> str:
        """Get description for the secret"""
        return secret_config.get("description", "")

    def _get_secret_kms_key_id(self, secret_config: Dict[str, Any]) -> Optional[str]:
        """Get KMS key ID for the secret"""
        aws_config = self._get_aws_config()
        return secret_config.get("kmsKeyId", aws_config.get("defaultKmsKeyId"))

    def _get_secret_tags(self, secret_config: Dict[str, Any]) -> Dict[str, str]:
        """Get tags for the secret, merging defaults with secret-specific tags"""
        aws_config = self._get_aws_config()
        default_tags = aws_config.get("defaultTags", {})
        secret_tags = secret_config.get("tags", {})

        # Merge default tags with secret-specific tags (secret-specific takes precedence)
        merged_tags = default_tags.copy()
        merged_tags.update(secret_tags)
        return merged_tags

    def _get_secret_automatic_rotation(
        self, secret_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Get automatic rotation configuration"""
        return secret_config.get("automaticRotation")

    def _create_aws_secret(self, secret_key: str, secret_config: Dict[str, Any]) -> int:
        """Create an AWS Secrets Manager secret"""
        secret_name = self._get_secret_name_for_aws(secret_key, secret_config)
        description = self._get_secret_description(secret_config)
        kms_key_id = self._get_secret_kms_key_id(secret_config)
        tags = self._get_secret_tags(secret_config)
        rotation_config = self._get_secret_automatic_rotation(secret_config)

        # Collect secret data
        secret_data: Dict[str, str] = {}
        reserved_fields = [
            "secretName",
            "description",
            "kmsKeyId",
            "tags",
            "automaticRotation",
        ]

        for field_name, instruction in secret_config.items():
            if field_name in reserved_fields:
                continue

            # Get the field value
            value = self._get_field_value(secret_key, field_name, instruction)
            if (
                value is not None
            ):  # Only include fields that were successfully processed
                secret_data[field_name] = value
            # If value is None (optional field failed), skip this field

        # Create the secret using AWS CLI
        try:
            result = self._create_secret_with_aws_cli(
                secret_name, secret_data, description, kms_key_id, tags, rotation_config
            )
            return 1 if result else 0
        except Exception as e:
            self.module.fail_json(
                f"Failed to create AWS secret {secret_name}: {str(e)}"
            )
            return 0

    def _create_secret_with_aws_cli(
        self,
        secret_name: str,
        secret_data: Dict[str, str],
        description: str,
        kms_key_id: Optional[str],
        tags: Dict[str, str],
        rotation_config: Optional[Dict[str, Any]],
    ) -> bool:
        """Create secret using AWS CLI"""
        import json

        # Prepare secret value as JSON
        secret_value = json.dumps(secret_data)

        # Build AWS CLI command
        aws_config = self._get_aws_config()
        region = aws_config.get("region")
        profile = aws_config.get("profile")

        cmd_parts = ["aws", "secretsmanager", "create-secret"]
        cmd_parts.extend(["--name", secret_name])
        cmd_parts.extend(["--secret-string", secret_value])

        if description:
            cmd_parts.extend(["--description", description])

        if kms_key_id:
            cmd_parts.extend(["--kms-key-id", kms_key_id])

        if region:
            cmd_parts.extend(["--region", region])

        if profile:
            cmd_parts.extend(["--profile", profile])

        # Add tags if provided
        if tags:
            for key, value in tags.items():
                cmd_parts.extend(["--tags", f"Key={key},Value={value}"])

        # Add replication regions if configured
        replication_regions = aws_config.get("replicationRegions", [])
        if replication_regions:
            replica_regions = []
            for replica in replication_regions:
                replica_spec = f"Region={replica['region']}"
                if "kmsKeyId" in replica:
                    replica_spec += f",KmsKeyId={replica['kmsKeyId']}"
                replica_regions.append(replica_spec)
            cmd_parts.extend(["--replica-regions", ",".join(replica_regions)])

        # Execute command
        cmd = " ".join([f'"{part}"' if " " in part else part for part in cmd_parts])
        result = self.module.run_command(cmd, check_rc=False)

        if result[0] != 0:
            # Check if secret already exists
            if "ResourceExistsException" in result[2]:
                # Secret exists, update it instead
                return self._update_existing_secret(
                    secret_name, secret_data, description, region, profile
                )
            else:
                self.module.fail_json(
                    f"Failed to create secret {secret_name}: {result[2]}"
                )
                return False

        # Configure automatic rotation if specified
        if rotation_config and rotation_config.get("enabled"):
            self._configure_automatic_rotation(
                secret_name, rotation_config, region, profile
            )

        return True

    def _update_existing_secret(
        self,
        secret_name: str,
        secret_data: Dict[str, str],
        description: str,
        region: Optional[str],
        profile: Optional[str],
    ) -> bool:
        """Update an existing secret"""
        import json

        secret_value = json.dumps(secret_data)
        cmd_parts = ["aws", "secretsmanager", "update-secret"]
        cmd_parts.extend(["--secret-id", secret_name])
        cmd_parts.extend(["--secret-string", secret_value])

        if description:
            cmd_parts.extend(["--description", description])

        if region:
            cmd_parts.extend(["--region", region])

        if profile:
            cmd_parts.extend(["--profile", profile])

        cmd = " ".join([f'"{part}"' if " " in part else part for part in cmd_parts])
        result = self.module.run_command(cmd, check_rc=False)

        return result[0] == 0

    def _configure_automatic_rotation(
        self,
        secret_name: str,
        rotation_config: Dict[str, Any],
        region: Optional[str],
        profile: Optional[str],
    ) -> None:
        """Configure automatic rotation for a secret"""
        cmd_parts = ["aws", "secretsmanager", "rotate-secret"]
        cmd_parts.extend(["--secret-id", secret_name])

        if "rotationLambdaArn" in rotation_config:
            cmd_parts.extend(
                ["--rotation-lambda-arn", rotation_config["rotationLambdaArn"]]
            )

        if "rotationSchedule" in rotation_config:
            cmd_parts.extend(
                [
                    "--rotation-rules",
                    f"AutomaticallyAfterDays={rotation_config['rotationSchedule']}",
                ]
            )

        if region:
            cmd_parts.extend(["--region", region])

        if profile:
            cmd_parts.extend(["--profile", profile])

        cmd = " ".join([f'"{part}"' if " " in part else part for part in cmd_parts])
        result = self.module.run_command(cmd, check_rc=False)

        if result[0] != 0:
            self.module.fail_json(
                f"Failed to configure rotation for secret {secret_name}: {result[2]}"
            )

    def inject_secrets(self) -> int:
        """Inject all secrets into AWS Secrets Manager"""
        secrets = self._get_secrets()
        total_secrets = 0

        for secret_key, secret_config in secrets.items():
            created_count = self._create_aws_secret(secret_key, secret_config)
            total_secrets += created_count

        return total_secrets
