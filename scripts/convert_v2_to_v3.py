#!/usr/bin/env python3
"""
Converter utility to migrate values-secret files from version 2.0 to version 3.0 format.

Usage:
    python convert_v2_to_v3.py input.yaml output.yaml
    python convert_v2_to_v3.py input.yaml  # outputs to input_v3.yaml
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml


class V2ToV3Converter:
    """Converts values-secret files from v2.0 to v3.0 format"""

    def __init__(self, preserve_comments: bool = True):
        self.preserve_comments = preserve_comments
        self.conversion_log: List[str] = []

    def log(self, message: str) -> None:
        """Log a conversion message"""
        self.conversion_log.append(message)
        print(f"[CONVERT] {message}")

    def convert_vault_policies_to_policies(
        self, vault_policies: Dict[str, str]
    ) -> Dict[str, Dict[str, Union[str, int]]]:
        """Convert v2 vaultPolicies to v3 policies format"""
        policies: Dict[str, Dict[str, Union[str, int]]] = {}

        for policy_name, policy_content in vault_policies.items():
            policy: Dict[str, Union[str, int]] = {}

            # Extract length
            length_match = re.search(r"length\s*=\s*(\d+)", policy_content)
            if length_match:
                policy["length"] = int(length_match.group(1))
            else:
                policy["length"] = 16  # default
                self.log(f"No length found in policy '{policy_name}', using default 16")

            # Determine charset based on rules
            charset_rules = re.findall(
                r'rule\s+"charset"\s*{\s*charset\s*=\s*"([^"]+)"', policy_content
            )

            if not charset_rules:
                policy["charset"] = "alphanumeric"
                self.log(
                    f"No charset rules found in policy '{policy_name}', using default 'alphanumeric'"
                )
            else:
                # Analyze charset rules to determine v3 charset type
                has_lower = any(
                    "abcdefghijklmnopqrstuvwxyz" in rule for rule in charset_rules
                )
                has_upper = any(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" in rule for rule in charset_rules
                )
                has_digits = any("0123456789" in rule for rule in charset_rules)
                has_symbols = any(
                    re.search(r'[!@#$%^&*()_+\-=\[\]{}|;\':",./<>?]', rule)
                    for rule in charset_rules
                )

                if has_symbols:
                    policy["charset"] = "alphanumeric_symbols"
                elif has_lower and has_upper and has_digits:
                    policy["charset"] = "alphanumeric"
                elif has_lower and has_upper:
                    policy["charset"] = "alpha"
                elif has_digits:
                    policy["charset"] = "numeric"
                else:
                    policy["charset"] = "alphanumeric"
                    self.log(
                        f"Could not determine charset for policy '{policy_name}', using default 'alphanumeric'"
                    )

            policies[policy_name] = policy
            self.log(f"Converted policy '{policy_name}': {policy}")

        return policies

    def convert_backing_store(self, backing_store: str) -> str:
        """Convert v2 backingStore to v3 secretstore"""
        store_mapping = {
            "vault": "vault",
            "k8s": "kubernetes",
            "kubernetes": "kubernetes",
            "none": "none",
        }

        result = store_mapping.get(backing_store.lower(), "vault")
        if result != backing_store.lower():
            self.log(
                f"Converted backingStore '{backing_store}' to secretstore '{result}'"
            )

        return result

    def convert_field_to_v3(
        self, field: Dict[str, Any], vault_policies: Dict[str, str]
    ) -> Tuple[str, Any]:
        """Convert a v2 field to v3 format"""
        field_name = field["name"]

        # Handle file paths
        if "path" in field:
            path = field["path"]
            if path is None:
                self.log(f"Field '{field_name}' has null path, treating as prompt")
                return field_name, None

            # Handle base64 encoding
            if field.get("base64", False):
                file_ref = f"file://{path}.b64"
                self.log(
                    f"Field '{field_name}' converted to base64 file reference: {file_ref}"
                )
            else:
                file_ref = f"file://{path}"
                self.log(
                    f"Field '{field_name}' converted to file reference: {file_ref}"
                )

            # Handle optional files
            if field.get("onMissingValue") == "prompt":
                return field_name, {"value": file_ref, "optional": True}

            return field_name, file_ref

        # Handle generation
        if field.get("onMissingValue") == "generate":
            vault_policy = field.get("vaultPolicy")
            if vault_policy:
                generate_ref = f"generate:{vault_policy}"
                self.log(
                    f"Field '{field_name}' converted to generation reference: {generate_ref}"
                )
                return field_name, generate_ref
            else:
                self.log(
                    f"Field '{field_name}' has generate but no vaultPolicy, using 'generate:basic'"
                )
                return field_name, "generate:basic"

        # Handle prompts
        if field.get("onMissingValue") == "prompt":
            if "value" in field and field["value"] is not None:
                return field_name, field["value"]
            else:
                self.log(f"Field '{field_name}' will prompt for value")
                return field_name, None

        # Handle direct values
        if "value" in field:
            return field_name, field["value"]

        # Default case
        self.log(f"Field '{field_name}' has no clear conversion, treating as null")
        return field_name, None

    def convert_secrets(
        self, v2_secrets: List[Dict[str, Any]], vault_policies: Dict[str, str]
    ) -> Dict[str, Dict[str, Any]]:
        """Convert v2 secrets list to v3 secrets dict"""
        v3_secrets = {}

        for secret in v2_secrets:
            secret_name = secret["name"]
            v3_secret = {}

            # Convert fields
            if "fields" in secret:
                for field in secret["fields"]:
                    field_name, field_value = self.convert_field_to_v3(
                        field, vault_policies
                    )
                    v3_secret[field_name] = field_value

            # Handle vaultPrefixes as targets
            if "vaultPrefixes" in secret:
                v3_secret["targets"] = secret["vaultPrefixes"]
                self.log(
                    f"Secret '{secret_name}' vaultPrefixes converted to targets: {secret['vaultPrefixes']}"
                )

            # Handle vaultMount (note: v3 doesn't have direct equivalent, log warning)
            if "vaultMount" in secret:
                self.log(
                    f"WARNING: Secret '{secret_name}' has vaultMount '{secret['vaultMount']}' - this is not directly supported in v3.0"
                )

            v3_secrets[secret_name] = v3_secret
            self.log(f"Converted secret '{secret_name}' with {len(v3_secret)} fields")

        return v3_secrets

    def extract_global_settings(
        self, v2_secrets: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Extract common settings that can be moved to global settings"""
        # Look for common vaultPrefixes across secrets
        all_prefixes = []
        for secret in v2_secrets:
            if "vaultPrefixes" in secret:
                all_prefixes.extend(secret["vaultPrefixes"])

        # If there are common prefixes, suggest them as global targets
        if all_prefixes:
            unique_prefixes = list(set(all_prefixes))
            # Always include targets if there are any prefixes (even if just one)
            return {"targets": unique_prefixes}

        return None

    def convert_file(self, input_path: str) -> Dict[str, Any]:
        """Convert a v2 YAML file to v3 format"""
        self.conversion_log.clear()

        try:
            with open(input_path, "r") as f:
                v2_data = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Error reading input file: {e}")

        if not isinstance(v2_data, dict):
            raise ValueError("Input file must contain a YAML dictionary")

        # Verify it's a v2 file
        version = v2_data.get("version")
        if version != "2.0":
            raise ValueError(f"Input file version is '{version}', expected '2.0'")

        self.log("Converting values-secret file from version 2.0 to 3.0")

        # Start building v3 structure
        v3_data = {"version": "3.0"}

        # Convert backing store
        if "backingStore" in v2_data:
            v3_data["secretstore"] = self.convert_backing_store(v2_data["backingStore"])

        # Convert vault policies
        vault_policies = v2_data.get("vaultPolicies", {})
        if vault_policies:
            v3_data["policies"] = self.convert_vault_policies_to_policies(  # type: ignore
                vault_policies
            )

        # Extract global settings
        secrets_list = v2_data.get("secrets", [])
        global_settings = self.extract_global_settings(secrets_list)
        if global_settings:
            v3_data["settings"] = global_settings  # type: ignore
            self.log(f"Added global settings: {global_settings}")

        # Convert secrets (always include secrets section, even if empty)
        v3_data["secrets"] = self.convert_secrets(secrets_list, vault_policies)  # type: ignore

        self.log(
            f"Conversion completed successfully. Converted {len(secrets_list)} secrets."
        )

        return v3_data

    def write_output(self, v3_data: Dict[str, Any], output_path: str) -> None:
        """Write the converted v3 data to output file"""
        try:
            with open(output_path, "w") as f:
                # Write header comment
                f.write("# Converted from version 2.0 to 3.0 format\n")
                f.write("# Original conversion performed by convert_v2_to_v3.py\n")
                f.write("# Please review and test the converted configuration\n\n")

                # Write YAML with proper formatting
                yaml.dump(
                    v3_data, f, default_flow_style=False, sort_keys=False, indent=2
                )

            self.log(f"Output written to: {output_path}")

        except Exception as e:
            raise ValueError(f"Error writing output file: {e}")

    def print_conversion_summary(self) -> None:
        """Print a summary of the conversion"""
        print("\n" + "=" * 60)
        print("CONVERSION SUMMARY")
        print("=" * 60)
        for message in self.conversion_log:
            print(f"  {message}")
        print("\nPlease review the converted file and test it thoroughly.")
        print("Some manual adjustments may be required.")


def main():
    parser = argparse.ArgumentParser(
        description="Convert values-secret files from v2.0 to v3.0 format",
        epilog="Example: python convert_v2_to_v3.py values-secret.yaml values-secret-v3.yaml",
    )

    parser.add_argument("input", help="Input v2.0 YAML file path")
    parser.add_argument(
        "output", nargs="?", help="Output v3.0 YAML file path (default: input_v3.yaml)"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress conversion messages"
    )
    parser.add_argument(
        "--summary", "-s", action="store_true", help="Show conversion summary"
    )

    args = parser.parse_args()

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        input_path = Path(args.input)
        output_path = input_path.parent / f"{input_path.stem}_v3{input_path.suffix}"

    try:
        converter = V2ToV3Converter()

        # Suppress print statements if quiet mode
        if args.quiet:
            converter.log = lambda msg: converter.conversion_log.append(msg)

        # Convert the file
        v3_data = converter.convert_file(args.input)
        converter.write_output(v3_data, str(output_path))

        if args.summary or not args.quiet:
            converter.print_conversion_summary()

        print(f"\n✅ Successfully converted {args.input} -> {output_path}")

    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
