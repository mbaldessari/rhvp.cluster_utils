# Copyright 2022, 2023 Red Hat, Inc.
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
Module that implements V3 parsing of the values-secret.yaml spec for the parse_secrets_info module
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import os
from typing import Any, Dict, List, Optional, Union

from ansible_collections.rhvp.cluster_utils.plugins.module_utils.load_secrets_common import (
    find_dupes,
    get_ini_value,
    get_version,
    stringify_dict,
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
        "symbols": "!@#%^&*()",
    },
}

secret_store_namespace = "validated-patterns-secrets"


class ParseSecretsV3:
    def __init__(self, module, syaml, secrets_backing_store):
        self.module = module
        self.syaml = syaml
        self.secrets_backing_store = str(secrets_backing_store)
        self.secret_store_namespace = None
        self.parsed_secrets = {}
        self.kubernetes_secret_objects = []
        self.vault_policies = {}

    def _get_backingstore(self):
        """
        Return the backing store from settings or default to 'vault'
        In V3, the backing store is defined in the secretstore field
        """
        file_backing_store = str(self.syaml.get("secretstore", "vault"))

        # Check if the file backing store matches what was passed in
        if file_backing_store != self.secrets_backing_store:
            self.module.fail_json(
                f"Secrets file specifies '{file_backing_store}' backend but pattern config "
                f"specifies '{self.secrets_backing_store}'."
            )

        return self.secrets_backing_store

    def _get_secret_store_namespace(self):
        settings = self.syaml.get("settings", {})
        return str(settings.get("namespace", secret_store_namespace))

    def _get_targets(self):
        """Get global targets from settings"""
        settings = self.syaml.get("settings", {})
        return settings.get("targets", ["hub"])

    def _get_secrets(self):
        return self.syaml.get("secrets", {})

    def _convert_policy_to_vault_format(self, policy):
        """Convert V3 policy format to vault policy format"""
        if isinstance(policy, str):
            # If it's already a string, assume it's a vault policy
            return policy

        if isinstance(policy, dict):
            length = policy.get("length", 16)
            charset = policy.get("charset", "alphanumeric")

            if charset in CHARSET_MAPPINGS:
                charset_rules = []
                for rule_type, chars in CHARSET_MAPPINGS[charset].items():
                    charset_rules.append(f'rule "charset" {{ charset = "{chars}" min-chars = 1 }}')

                return f"length={length}\n" + "\n".join(charset_rules)
            else:
                self.module.fail_json(f"Unknown charset '{charset}' in policy")

        self.module.fail_json(f"Invalid policy format: {policy}")

    def _get_vault_policies(self):
        """Get and convert vault policies"""
        policies = {}

        # Add default validated pattern policy
        policies["validatedPatternDefaultPolicy"] = (
            "length=20\n"
            'rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }\n'
            'rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }\n'
            'rule "charset" { charset = "0123456789" min-chars = 1 }\n'
            'rule "charset" { charset = "!@#%^&*" min-chars = 1 }\n'
        )

        # Add user-defined policies
        user_policies = self.syaml.get("policies", {})
        for name, policy in user_policies.items():
            policies[name] = self._convert_policy_to_vault_format(policy)

        return policies

    def _create_k8s_secret(self, sname, secret_type, namespace, labels, annotations):
        return {
            "type": secret_type,
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": sname,
                "namespace": namespace,
                "annotations": annotations,
                "labels": labels,
            },
            "stringData": {},
        }

    def _process_secret_field(self, secret_name, field_name, field_value, secret_targets):
        """Process a single secret field from V3 format"""
        field_info = {
            "name": field_name,
            "value": field_value,
            "targets": secret_targets,
        }

        # Handle generate: syntax
        if isinstance(field_value, str) and field_value.startswith("generate:"):
            policy = field_value.split(":", 1)[1] if ":" in field_value else "basic"
            field_info["onMissingValue"] = "generate"
            field_info["vaultPolicy"] = policy
            field_info["value"] = None

            if self._get_backingstore() != "vault":
                self.module.fail_json(
                    f"Cannot use 'generate:' with non-vault backing store for secret {secret_name} field {field_name}"
                )

        return field_info

    def _inject_field_v3(self, secret_name, field_name, field_value, secret_targets):
        """Inject a field using V3 logic"""
        field_info = self._process_secret_field(secret_name, field_name, field_value, secret_targets)

        if field_info.get("onMissingValue") == "generate":
            # Handle generated secrets
            self.parsed_secrets[secret_name]["generate"].append(field_name)
            self.parsed_secrets[secret_name]["fields"][field_name] = None
            vault_policy = field_info.get("vaultPolicy", "basic")
            self.parsed_secrets[secret_name]["vault_policies"][field_name] = vault_policy
        else:
            # Handle regular secrets
            self.parsed_secrets[secret_name]["fields"][field_name] = str(field_value)

    def parse(self):
        """Main parsing method for V3 secrets"""
        version = get_version(self.syaml)
        if version != "3.0":
            self.module.fail_json(f"Version is not 3.0: {version}")

        self.vault_policies = self._get_vault_policies()
        self.secret_store_namespace = self._get_secret_store_namespace()
        backing_store = self._get_backingstore()
        secrets = self._get_secrets()
        global_targets = self._get_targets()

        total_secrets = 0

        if len(secrets) == 0:
            self.module.warn("No secrets were parsed")
            return total_secrets

        # Validate backing store
        if backing_store not in ["kubernetes", "vault", "none", "aws-secrets-manager"]:
            self.module.fail_json(
                f"Unsupported backing store '{backing_store}' for version 3.0"
            )

        for secret_name, secret_data in secrets.items():
            total_secrets += 1

            # Get secret-specific targets or use global targets
            secret_targets = secret_data.get("targets", global_targets)

            # Initialize parsed secret structure
            self.parsed_secrets[secret_name] = {
                "name": secret_name,
                "fields": {},
                "vault_mount": "secret",  # V3 uses fixed mount
                "vault_policies": {},
                "vault_prefixes": secret_targets,  # In V3, targets become prefixes
                "override": [],
                "generate": [],
                "paths": {},
                "base64": [],
                "ini_file": {},
                "type": "Opaque",  # Default type for V3
                "target_namespaces": [],  # V3 doesn't use target namespaces in the same way
                "labels": {},
                "annotations": {},
            }

            # Process each field in the secret
            for field_name, field_value in secret_data.items():
                if field_name == "targets":
                    continue  # Skip the targets metadata

                self._inject_field_v3(secret_name, field_name, field_value, secret_targets)

            # Create Kubernetes secrets if needed
            if backing_store == "kubernetes":
                k8s_namespaces = [self._get_secret_store_namespace()]
            else:
                k8s_namespaces = []

            for tns in k8s_namespaces:
                k8s_secret = self._create_k8s_secret(
                    secret_name, "Opaque", tns, {}, {}
                )
                k8s_secret["stringData"] = self.parsed_secrets[secret_name]["fields"]
                self.kubernetes_secret_objects.append(k8s_secret)

        return total_secrets

    def sanitize_values(self):
        """Validate the V3 secrets file structure"""
        version = get_version(self.syaml)
        if version != "3.0":
            self.module.fail_json(f"Version is not 3.0: {version}")

        backing_store = self._get_backingstore()
        if backing_store not in ["kubernetes", "vault", "none", "aws-secrets-manager"]:
            self.module.fail_json(
                f"Unsupported backing store '{backing_store}' for version 3.0"
            )

        secrets = self._get_secrets()
        if len(secrets) == 0:
            return  # Empty secrets is allowed in V3

        # Validate no duplicate secret names
        secret_names = list(secrets.keys())
        dupes = find_dupes(secret_names)
        if len(dupes) > 0:
            self.module.fail_json(f"Duplicate secret names found: {dupes}")

        # Validate each secret
        for secret_name, secret_data in secrets.items():
            if not isinstance(secret_data, dict):
                self.module.fail_json(f"Secret '{secret_name}' must be a dictionary")

            # Validate targets if present
            if "targets" in secret_data:
                if not isinstance(secret_data["targets"], list):
                    self.module.fail_json(f"Secret '{secret_name}' targets must be a list")
                if len(secret_data["targets"]) == 0:
                    self.module.fail_json(f"Secret '{secret_name}' targets cannot be empty")