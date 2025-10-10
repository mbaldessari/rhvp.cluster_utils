# Utility Scripts

This directory contains utility scripts for the `rhvp.cluster_utils` Ansible Collection.

## convert_v2_to_v3.py

A comprehensive utility to convert values-secret files from version 2.0 to version 3.0 format.

### Overview

The v2 to v3 converter automates the migration process from the legacy v2.0 secrets format to the modern v3.0 format, handling all the structural and syntactic changes between versions.

### Key Conversions

| v2.0 Feature | v3.0 Equivalent | Notes |
|--------------|-----------------|-------|
| `backingStore: vault` | `secretstore: "vault"` | Also converts `k8s` → `kubernetes` |
| `vaultPolicies:` | `policies:` | Converts HCL policy syntax to simplified YAML |
| `secrets:` (list) | `secrets:` (dict) | Changes from array to object structure |
| `fields:` (list) | Direct key-value pairs | Flattens field structure |
| `vaultPrefixes:` | `targets:` | Can be global or per-secret |
| `onMissingValue: generate` + `vaultPolicy: policy` | `"generate:policy"` | Combines into single instruction |
| `path: "/file/path"` | `"file:///file/path"` | Uses file:// URI scheme |
| `base64: true` | `.b64` suffix | Indicates base64 encoding via filename |

### Usage

#### Basic Usage

```bash
# Convert a v2 file to v3 format and save to file
python convert_v2_to_v3.py input-v2.yaml output-v3.yaml

# Convert and output to stdout (for piping)
python convert_v2_to_v3.py input-v2.yaml

# Quiet mode (suppress conversion messages, useful for piping)
python convert_v2_to_v3.py input-v2.yaml --quiet > output-v3.yaml

# Pipe conversion to another tool
python convert_v2_to_v3.py input-v2.yaml | kubectl apply -f -

# Show conversion summary
python convert_v2_to_v3.py input-v2.yaml --summary > output-v3.yaml
```

#### Example Conversion

**Input (v2.0 format):**
```yaml
version: "2.0"
backingStore: vault

vaultPolicies:
  basicPolicy: |
    length=12
    rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
    rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
    rule "charset" { charset = "0123456789" min-chars = 1 }

secrets:
  - name: database-config
    vaultPrefixes:
      - hub
      - spoke1
    fields:
      - name: username
        value: "dbuser"
      - name: password
        onMissingValue: generate
        vaultPolicy: basicPolicy
      - name: ca_cert
        path: /etc/ssl/ca.pem
        base64: true
```

**Output (v3.0 format):**
```yaml
# Converted from version 2.0 to 3.0 format
# Original conversion performed by convert_v2_to_v3.py
# Please review and test the converted configuration

version: '3.0'
secretstore: vault
policies:
  basicPolicy:
    length: 12
    charset: alphanumeric
settings:
  targets:
  - hub
  - spoke1
secrets:
  database-config:
    username: dbuser
    password: generate:basicPolicy
    ca_cert: file:///etc/ssl/ca.pem.b64
    targets:
    - hub
    - spoke1
```

### Conversion Details

#### Policy Conversion

The converter automatically detects vault policy content and converts complex HCL syntax to simplified v3.0 policy format:

- **Length Extraction**: Parses `length=N` from HCL
- **Charset Detection**: Analyzes charset rules to determine appropriate v3 charset:
  - `alphanumeric_symbols` - includes special characters
  - `alphanumeric` - letters and numbers only
  - `alpha` - letters only
  - `numeric` - numbers only

#### Field Conversion Logic

1. **File References**:
   - `path: "/file"` → `"file:///file"`
   - `path: "/file"` + `base64: true` → `"file:///file.b64"`
   - `path: null` → `null` (prompts for input)

2. **Generation**:
   - `onMissingValue: generate` + `vaultPolicy: policy` → `"generate:policy"`
   - Missing policy defaults to `"generate:basic"`

3. **Optional Files**:
   - `path: "/file"` + `onMissingValue: prompt` → `{value: "file:///file", optional: true}`

4. **Prompts**:
   - `onMissingValue: prompt` → `null`

#### Global Settings Extraction

The converter intelligently extracts common `vaultPrefixes` from secrets and promotes them to global `settings.targets`, while preserving per-secret overrides.

### Error Handling and Warnings

The converter provides detailed logging and handles various edge cases:

- **Unsupported Features**: Warns about `vaultMount` which has no v3 equivalent
- **Missing Policies**: Defaults to `basic` policy for generation without explicit policy
- **Invalid Charset**: Falls back to `alphanumeric` when charset cannot be determined
- **File Validation**: Preserves original paths but logs conversion details

### Testing

The converter includes comprehensive unit tests covering:

- ✅ All conversion scenarios (26 test cases)
- ✅ Error handling for invalid input
- ✅ Edge cases (empty secrets, missing backing store)
- ✅ Real-world v2 file compatibility
- ✅ Command-line interface

Run tests:
```bash
python tests/unit/test_convert_v2_to_v3.py
```

### Limitations and Manual Review Required

While the converter handles most scenarios automatically, **manual review is always required**:

1. **vaultMount**: No direct v3 equivalent - may need custom configuration
2. **Complex Policies**: Advanced HCL policies may need manual adjustment
3. **File Paths**: Verify file references are still valid in your environment
4. **Targets**: Review global vs per-secret target assignments
5. **Optional Logic**: Verify optional field behavior matches expectations

### Integration with Project Workflow

The converter can be integrated into migration workflows:

```bash
# Batch convert all v2 files
find . -name "*values-secret-v2*" -exec python scripts/convert_v2_to_v3.py {} \;

# Convert and validate
python scripts/convert_v2_to_v3.py old-values.yaml new-values.yaml
ansible-playbook validate-secrets.yml -e values_secrets=new-values.yaml
```

### Dependencies

- Python 3.8+
- PyYAML library
- No additional dependencies for core functionality

The converter is designed to be self-contained and portable for easy integration into existing workflows.