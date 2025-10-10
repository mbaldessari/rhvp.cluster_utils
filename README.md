# Ansible Collection - rhvp.cluster_utils

This collection represents the collected Ansible code from the Validated Patterns framework common repository.

The main purpose of this collections are to:

1. Assist with the management of secrets in Validated Patterns clusters, including unsealing Vault, and parsing and
loading local secrets files into VP secrets stores.

2. Help manage imperative and other utility functions of the cluster

## Utility Scripts

The collection includes utility scripts in the `scripts/` directory:

### convert_v2_to_v3.py

A migration utility to convert values-secret files from version 2.0 to version 3.0 format.

```bash
# Convert a v2 secrets file to v3 format
python scripts/convert_v2_to_v3.py old-values-v2.yaml new-values-v3.yaml

# Auto-generate output filename
python scripts/convert_v2_to_v3.py old-values-v2.yaml
```

Key features:
- Automatically converts all v2.0 syntax to v3.0 equivalents
- Handles vault policies, file references, generation instructions
- Extracts global settings and optimizes secret structure
- Comprehensive error handling and validation
- Detailed conversion logging and warnings

See `scripts/README.md` for complete documentation and examples.

## Documentation

For detailed information about modules, roles, and testing, see:
- `tests/integration/README.md` - Integration testing guide
- `scripts/README.md` - Utility scripts documentation
