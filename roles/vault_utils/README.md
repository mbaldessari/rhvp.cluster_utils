# Role Name

Bunch of utilities to manage the vault inside k8s imperatively

## Requirements

ansible-galaxy collection install kubernetes.core (formerly known as community.kubernetes)

## Role Variables

Defaults as to where the values-secret.yaml file is and the two ways to connect to a kubernetes cluster
(KUBECONFIG and ~/.kube/config respectively):

```yaml
values_secret: "{{ lookup('env', 'HOME') }}/values-secret.yaml"
kubeconfig: "{{ lookup('env', 'KUBECONFIG') }}"
kubeconfig_backup: "{{ lookup('env', 'HOME') }}/.kube/config"
```

Default values for vault configuration:

```yaml
vault_ns: "vault"
vault_pod: "vault-0"
vault_hub: "hub"
vault_hub_kubernetes_host: https://$KUBERNETES_PORT_443_TCP_ADDR:443
# Needs extra escaping due to how it gets injected via shell in the vault
vault_hub_capabilities: '[\\\"read\\\"]'
vault_base_path: "secret"
vault_path: "{{ vault_base_path }}/{{ vault_hub }}"
vault_hub_ttl: "15m"
vault_pki_max_lease_ttl: "8760h"
# "external-secrets" is the namespace when using the downstream openshift-external-secrets chart
external_secrets_ns: golang-external-secrets
# "ocp-external-secrets" is the service account name when using the downstream openshift-external-secrets chart
external_secrets_sa: golang-external-secrets
unseal_secret: "vaultkeys"
unseal_namespace: "imperative"
vault_jwt_config: false
```

## Dependencies

This relies on [kubernetes.core](https://docs.ansible.com/ansible/latest/collections/kubernetes/core/k8s_module.html)

## Vault out of the box configuration

This role configures four secret paths in vault:

1. `secret/global` - Any secret under this path is accessible in read-only only to all clusters known to ACM (hub and spokes)
2. `secret/hub` - Any secret under this path is accessible in read-only only to the ACM hub cluster
3. `secret/<fqdn.of.spoke.cluster>` - Any secret under this path is accessible in read-only only to the spoke cluster
4. `secret/pushsecrets` - Any secret here can be accessed in read and write mode to all clusters known to ACM. This area can
   be used with ESO's `PushSecrets` so you can push an existing secret from one namespace, to the vault under this path and
   then it can be retrieved by an `ExternalSecret` either in a different namespace *or* from an entirely different cluster.

## Values secret file format

Currently this role supports three formats: version 1.0 (which is the assumed
default when not specified), version 2.0, and version 3.0. Version 2.0 is more
featureful and supports generating secrets directly into the vault and also prompting
the user for a secret. Version 3.0 provides a simplified syntax with instruction-based
field definitions and improved policy management.

By default, the first file that will looked up is
`~/.config/hybrid-cloud-patterns/values-secret-<patternname>.yaml`, then
`~/.config/validated-patterns/values-secret-<patternname>.yaml`,
`~/values-secret-<patternname>.yaml` and should that not exist it will look for
`~/values-secret.yaml`.
The paths can be overridden by setting the environment variable `VALUES_SECRET` to the path of the
secret file.

The values secret YAML files can be encrypted with `ansible-vault`. If the role detects they are encrypted, the password to
decrypt them will be prompted when needed.

### Version 3.0

Version 3.0 introduces a simplified syntax with instruction-based field definitions. Here's an example of a version 3.0 file:

```yaml
version: "3.0"

# Backing store type (optional, defaults to "vault")
backingStore: "vault"

# Global settings (optional)
settings:
  targets: ["hub", "spoke1"]  # Default targets for all secrets
  namespace: "validated-patterns-secrets"  # Kubernetes namespace

# Password generation policies (optional)
policies:
  basic:
    length: 16
    charset: "alphanumeric"  # Options: alphanumeric, alphanumeric_symbols, all
  medium:
    length: 20
    charset: "alphanumeric_symbols"
  strong:
    length: 32
    charset: "all"
  # You can also use raw vault policy format:
  custom: |
    length=10
    rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }

# Secrets configuration
secrets:
  database:
    username: "dbuser"  # Static value
    password: "generate:strong"  # Generate using 'strong' policy
    ca_cert: "file://path/to/ca.crt"  # Load file content as-is
    binary_cert: "file+base64://path/to/cert.p12"  # Load file and base64 encode
    admin_password: "prompt:Enter admin password"  # Prompt user for input

  api-config:
    targets: ["spoke1"]  # Override global targets for this secret
    endpoint: "https://api.example.com"
    token: "generate:medium"
    config_file: "file+base64://path/to/config.json"

  aws:
    access_key: "ini://~/.aws/credentials:default:aws_access_key_id"
    secret_key: "ini://~/.aws/credentials:default:aws_secret_access_key"
    region: "ini://~/.aws/config:region"  # Uses default section
```

#### Configuration Options

**backingStore** (optional): Specifies the type of secrets storage backend. Defaults to `"vault"` and currently only supports Vault. This field provides future flexibility for adding support for other secret storage providers.

#### Field Instructions

Version 3.0 uses instruction-based field definitions with the following formats:

- **Static values**: Direct string, number, or boolean values
- **`file://path`**: Load file content as plain text
- **`file+base64://path`**: Load file content and base64 encode it (ideal for binary files)
- **`ini://path:section:key`**: Load value from INI file (e.g., `ini://~/.aws/credentials:default:aws_access_key_id`)
- **`ini://path:key`**: Load value from INI file using default section (e.g., `ini://~/.aws/config:region`)
- **`generate:policy_name`**: Generate password using specified policy
- **`prompt:message`**: Prompt user for input during execution

#### Policy Definitions

Policies support simplified configuration with three charset options:
- `alphanumeric`: Letters and numbers only
- `alphanumeric_symbols`: Letters, numbers, and basic symbols (!@#%^&*)
- `all`: Letters, numbers, and extended symbols

#### Kubernetes Backing Store

Version 3.0 also supports a `kubernetes` backing store that creates standard Kubernetes secrets instead of storing in Vault:

```yaml
version: "3.0"
backingStore: "kubernetes"

# Simple global settings (optional)
settings:
  namespace: "validated-patterns-secrets"  # Default namespace if not specified per secret

secrets:
  database:
    namespaces: "app-namespace"  # Single namespace
    type: "Opaque"              # Optional, defaults to "Opaque"
    labels:
      environment: "production"
      component: "database"
    annotations:
      database.io/connection-pool: "enabled"
    username: "dbuser"                                    # Static value
    password: "prompt:Enter database password"           # User prompt (no generate: support)
    ca_cert: "file://path/to/ca.crt"                    # File content
    binary_cert: "file+base64://path/to/cert.p12"       # Base64-encoded file

  docker-registry:
    namespaces: ["default", "app1", "app2", "ci-cd"]    # Multiple namespaces
    type: "kubernetes.io/dockerconfigjson"
    labels:
      registry: "production"
    .dockerconfigjson: "file+base64://~/.docker/config.json"

  tls-wildcard:
    namespaces: ["ingress-nginx", "istio-system"]
    type: "kubernetes.io/tls"
    labels:
      cert-type: "wildcard"
    tls.crt: "file://path/to/wildcard.crt"
    tls.key: "file://path/to/wildcard.key"

  # Uses default namespace from settings.namespace
  shared-config:
    # No namespaces specified = uses settings.namespace
    labels:
      shared: "true"
    api_key: "ini://~/.config/app.ini:default:api_key"
```

**Key differences for Kubernetes backing store:**

- **`namespaces`**: Accepts string or array of namespace(s) where secrets will be created
- **`type`**: Kubernetes secret type (defaults to "Opaque")
- **`labels`** and **`annotations`**: Standard Kubernetes metadata
- **No `generate:` instructions**: Use `prompt:` instead for sensitive values
- **No `targets`**: Use `namespaces` to specify where secrets are created
- **No `policies`**: Password generation not supported

#### AWS Secrets Manager Backing Store

Version 3.0 also supports an `aws-secrets-manager` backing store that creates secrets in AWS Secrets Manager:

```yaml
version: "3.0"
backingStore: "aws-secrets-manager"

# AWS-specific configuration
awsConfig:
  region: "us-east-1"
  profile: "default"
  prefix: "myapp/prod/"

  defaultKmsKeyId: "alias/aws/secretsmanager"
  defaultTags:
    Environment: "production"
    ManagedBy: "validated-patterns"

  # Cross-region replication (optional)
  replicationRegions:
    - region: "us-west-2"
      kmsKeyId: "alias/aws/secretsmanager"

secrets:
  database:
    secretName: "rds/credentials"          # Custom secret name
    description: "Database credentials"
    tags:
      Application: "myapp"
      Component: "database"
    username: "dbuser"
    password: "prompt:Enter database password"
    host: "ini://~/.config/db.ini:default:host"

  api-config:
    # Uses prefix: myapp/prod/api-config
    description: "API configuration"
    kmsKeyId: "alias/custom-encryption-key"  # Override default KMS key
    endpoint: "https://api.example.com"
    token: "prompt:Enter API token"
    config: "file+base64://path/to/config.json"

  auto-rotate-secret:
    secretName: "rds/auto-rotate"
    description: "Auto-rotating database secret"
    automaticRotation:
      enabled: true
      rotationSchedule: "rate(30 days)"
      rotationLambdaArn: "arn:aws:lambda:us-east-1:123456789012:function:SecretsManagerRotation"
    username: "autouser"
    password: "prompt:Enter initial password"
```

**Key features for AWS Secrets Manager backing store:**

- **`secretName`**: Custom secret name (defaults to YAML key)
- **`description`**: Human-readable description for the secret
- **`kmsKeyId`**: Custom KMS key for encryption (overrides default)
- **`tags`**: AWS tags merged with default tags from `awsConfig`
- **`automaticRotation`**: AWS automatic rotation configuration
- **Cross-region replication**: Configured in `awsConfig.replicationRegions`
- **No `generate:` instructions**: Use `prompt:` instead for sensitive values

**AWS Configuration Options:**

- **`region`**: AWS region for secrets
- **`profile`**: AWS CLI profile to use
- **`prefix`**: Prefix for all secret names
- **`defaultKmsKeyId`**: Default KMS key for encryption
- **`defaultTags`**: Tags applied to all secrets
- **`replicationRegions`**: Cross-region replication setup

### Version 2.0

Here is a version 2.0 example file (specifying `version: 2.0` is mandatory in this case):

```yaml
# NEVER COMMIT THESE VALUES TO GIT (unless your file only uses generated
# passwords or only points to files)

# Needed to specify the new format (missing version means old version: 1.0 by default)
version: 2.0

backingStore: vault # 'vault' is the default when omitted

# These are the vault policies to be created in the vault
# these are used when we let the vault generate the passwords
# by setting the 'onMissingValue' attribute to 'generate'
# See https://developer.hashicorp.com/vault/docs/concepts/password-policies
vaultPolicies:
  basicPolicy: |
    length=10
    rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
    rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
    rule "charset" { charset = "0123456789" min-chars = 1 }

  advancedPolicy: |
    length=20
    rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
    rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
    rule "charset" { charset = "0123456789" min-chars = 1 }
    rule "charset" { charset = "!@#$%^&*" min-chars = 1 }

# This is the mandatory top-level secrets entry
secrets:
  # This will create the following keys + attributes:
  # - secret/region-one/config-demo:
  #     secret: ...<generated basicPolicy secret>...
  #     secretprompt: ...<as input by the user>...
  #     secretprompt2: ...<as input by the user. If just enter is pressed it will be 'defaultvalue'>...
  #     secretfile: ...<content of the file as input by user. If just enter is pressed the file will be /tmp/ca.crt...0
  #     ca_crt: ...<content of /tmp/ca.crt>...
  #     ca_crt_b64: ...<content of /tmp/ca.crt base64-encoded before uploading to vault>...
  # - secret/snowflake.blueprints.rhecoeng.com:
  #     secret: ...<generated basicPolicy secret>...
  #     secretprompt: ...<as input by the user>...
  #     secretprompt2: ...<as input by the user. If just enter is pressed it will be 'defaultvalue'>...
  #     secretfile: ...<content of the file as input by user. If just enter is pressed the file will be /tmp/ca.crt...0
  #     ca_crt: ...<content of /tmp/ca.crt>...
  #     ca_crt_b64: ...<content of /tmp/ca.crt base64-encoded before uploading to vault>...
  - name: config-demo
    # This is the default and passes the -mount=secret option to the vault commands
    vaultMount: secret
    # These represent the paths inside the vault maint
    vaultPrefixes:
    - region-one
    - snowflake.blueprints.rhecoeng.com
    fields:
    - name: secret
      onMissingValue: generate # One of: error,generate,prompt (generate is only valid for normal secrets)
      # This override attribute is false by default. The attribute is only valid with 'generate'. If the secret already exists in the
      # vault it won't be changed unless override is set to true
      override: true
      vaultPolicy: basicPolicy
    - name: secretprompt
      value: null
      onMissingValue: prompt # when prompting for something you need to set either value: null or path: null as
                             # we need to know if it is a secret plaintext or a file path
      description: "Please specify the password for application ABC"
    - name: secretprompt2
      value: defaultvalue
      # Prompt will always ask for the password even if value is set, in which case a simple enter press will confirm the default values
      onMissingValue: prompt
      description: "Please specify the API key for XYZ"
    - name: secretprompt3
      onMissingValue: generate
      vaultPolicy: validatedPatternDefaultPolicy  # This is an always-existing hard-coded policy
    - name: secretfile
      path: /tmp/ca.crt
      onMissingValue: prompt
      description: "Insert path to Certificate Authority"
    - name: ca_crt
      path: /tmp/ca.crt
      onMissingValue: error # One of error, prompt (for path). generate makes no sense for file
    - name: ca_crt_b64
      path: /tmp/ca.crt
      base64: true # defaults to false
      onMissingValue: prompt # One of error, prompt (for path). generate makes no sense for file

  - name: config-demo2
    vaultPrefixes:
    - region-one
    - snowflake.blueprints.rhecoeng.com
    fields:
    - name: ca_crt2
      path: /tmp/ca.crt # this will be the default shown when prompted
      description: "Specify the path for ca_crt2"
      onMissingValue: prompt # One of error, prompt (for path). generate makes no sense for file
    - name: ca_crt
      path: /tmp/ca.crt
      onMissingValue: error # One of error, prompt (for path). generate makes no sense for file

  # The following will read the ini-file at ~/.aws/credentials and place the ini_key "[default]/aws_access_key_id"
  # in the aws_access_key_id_test vault attribute in the secret/hub/awsexample path
  - name: awsexample
    fields:
    - name: aws_access_key_id_test
      ini_file: ~/.aws/credentials
      ini_section: default
      ini_key: aws_access_key_id
    - name: aws_secret_access_key_test
      ini_file: ~/.aws/credentials
      ini_key: aws_secret_access_key
```

### Version 1.0

Here is a well-commented example of a version 1.0 file:

```yaml
---
# By default when a top-level 'version: 1.0' is missing it is assumed to be '1.0'
# NEVER COMMIT THESE VALUES TO GIT

secrets:
  # These secrets will be pushed in the vault at secret/hub/test The vault will
  # have secret/hub/test with secret1 and secret2 as keys with their associated
  # values (secrets)
  test:
    secret1: foo
    secret2: bar

  # This ends up as the s3Secret attribute to the path secret/hub/aws
  aws:
    s3Secret: test-secret

# This will create the vault key secret/hub/testfoo which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files:
  testfoo: ~/ca.crt
# These secrets will be pushed in the vault at secret/region1/test The vault will
# have secret/region1/test with secret1 and secret2 as keys with their associated
# values (secrets)
secrets.region1:
  test:
    secret1: foo1
    secret2: bar1
# This will create the vault key secret/region2/testbar which will have two
# properties 'b64content' and 'content' which will be the base64-encoded
# content and the normal content respectively
files.region2:
  testbar: ~/ca.crt
```

### Internals

Here is the rough high-level algorithm used to unseal the vault:

1. Check vault status. If vault is not initialized go to 2. If initialized go to 3.
2. Initialize vault and store unseal keys + login token inside a secret in k8s
3. Check vault status. If vault is unsealed go to 5. else to to 4.
4. Unseal the vault using the secrets read from the k8s secret
5. Configure the vault (should be idempotent)

## License

Apache

## Author Information

Michele Baldessari <michele@redhat.com>
