# nitor-vault

Command line tools and libraries for encrypting keys and values using client-side encryption with [AWS KMS](https://aws.amazon.com/kms/) keys.

## Installation

We recommend the Rust or Python version for CLI usage.

JavaScript and Java versions are available from npm and maven central respectively,
and installation will depend on your needs.

### Rust

Install the Rust vault CLI binary from [crates.io](https://crates.io/crates/nitor-vault) with:

```terminal
cargo install nitor-vault
```

See [rustup.rs](https://rustup.rs) if you need to install Rust first.

### Python

Use [pipx](https://github.com/pypa/pipx) or [uv](https://github.com/astral-sh/uv)
to install the Python vault from [PyPI](https://pypi.org/project/nitor-vault/) globally in an isolated environment.

```shell
pipx install nitor-vault
# or
uv tool install nitor-vault
```

Directly installing with pip is no longer supported by most Python distributions.

The previous Python Vault implementation (versions below 2.0) can be found in the branch:
[legacy-python-vault](https://github.com/NitorCreations/vault/tree/legacy-python-vault).
Wheels are still available for install in PyPI, for example `nitor-vault==0.56`.

## Example usage

Initialize a vault bucket and other infrastructure: `vault --init`.
This will create a CloudFormation stack.

Encrypt a file and store in vault bucket: `vault -s my-key -f <file>`

Decrypt a file: `vault -l <file>`

Encrypt a single value and store in vault bucket `vault -s my-key -v my-value`

Decrypt a single value `vault -l my-key`

### Using encrypted CloudFormation stack parameters

Encrypt a value like this: `vault -e 'My secret value'`

The command above will print the base64 encoded value encrypted with your vault KMS key.
Use that value in a CF parameter.
The value is then also safe to commit into version control and you can use it in scripts for example like this:

```shell
#!/bin/bash

MY_ENCRYPTED_SECRET="AQICAHhu3HREZVp0YXWZLoAceH1Nr2ZTXoNZZKTriJY71pQOjAHKtG5uYCdJOKYy9dhMEX03AAAAbTBrBgkqhkiG9w0BBwagXjBcAgEAMFcGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMYy/tKGJFDQP6f9m1AgEQgCq1E1q8I+btMUdwRK8wYFNyE/5ntICNM96VPDnYbeTgcHzLoCx+HM1cGvc"

UNENCRYPTED_SECRET="$(vault -y $MY_ENCRYPTED_SECRET)"
```

Obviously you need to make sure that in the context of running the vault,
there is some sort of way for providing KMS permissions by for example adding the decryptPolicy managed policy
from the vault Cloudformation stack to the EC2 instance or whatever runs the code.

To decrypt the parameter value at stack creation or update time, use a custom resource:

```yaml
Parameters:
  MySecret:
    Type: String
    Description: Param value encrypted with KMS
Resources:
  DecryptSecret:
    Type: "Custom::VaultDecrypt"
    Properties:
      ServiceToken: "arn:aws:lambda:<region>:<account-id>:function:vault-decrypter"
      Ciphertext: { "Ref": "MySecret" }
  DatabaseWithSecretAsPassword:
    Type: "AWS::RDS::DBInstance"
    Properties:
      ...
      MasterUserPassword:
        Fn::Sub: ${DecryptSecret.Plaintext}
```

## Licence

[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
