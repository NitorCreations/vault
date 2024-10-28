# nitor-vault

Python vault implementation using the Rust vault library.

See the [root readme](../README.md) for more general information.

## Usage

Uses `pvault` command name to avoid conflict with the previous Python version and the Rust version.

```console
 Usage: pvault [OPTIONS] COMMAND [ARGS]...

 Nitor Vault CLI, see https://github.com/nitorcreations/vault for usage examples

╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bucket              -b      TEXT  Override the bucket name [env var: VAULT_BUCKET]                                 │
│ --key-arn             -k      TEXT  Override the KMS key ARN [env var: VAULT_KEY]                                    │
│ --prefix              -p      TEXT  Optional prefix for key name [env var: VAULT_PREFIX]                             │
│ --region              -r      TEXT  Specify AWS region for the bucket [env var: AWS_REGION]                          │
│ --vault-stack                 TEXT  Specify CloudFormation stack name to use [env var: VAULT_STACK]                  │
│ --quiet               -q            Suppress additional output and error messages                                    │
│ --version             -v            Print version and exit                                                           │
│ --install-completion                Install completion for the current shell.                                        │
│ --show-completion                   Show completion for the current shell, to copy it or customize the installation. │
│ --help                -h            Show this message and exit.                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ all | a | list | ls   List available secrets                                                                         │
│ decrypt | y           Directly decrypt given value                                                                   │
│ delete | d            Delete an existing key from the store                                                          │
│ describe              Print CloudFormation stack parameters for current configuration                                │
│ encrypt | e           Directly encrypt given value                                                                   │
│ exists                Check if a key exists                                                                          │
│ id                    Print AWS user account information                                                             │
│ info                  Print vault information                                                                        │
│ init | i              Initialize a new KMS key and S3 bucket                                                         │
│ lookup | l            Output secret value for given key                                                              │
│ status                Print vault stack information                                                                  │
│ store | s             Store a new key-value pair                                                                     │
│ update | u            Update the vault CloudFormation stack                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Install

Install command globally using pip. From repo root:

```shell
cd python-pyo3
pip install .
```

Check the command is found in path.
If you ran the install command inside a virtual env,
it will only be installed to the venv.

```shell
which -a pvault
```

## Development

Uses:

- [PyO3](https://pyo3.rs/) for creating a native Python module from Rust code.
- [Maturin](https://www.maturin.rs) for building and packaging the Python module from Rust.

### Workflow

You can use [uv](https://github.com/astral-sh/uv) or the traditional Python and pip combo.

First, create a virtual env:

```shell
# uv
uv sync --all-extras
# pip
python3 -m venv .venv
source .venv/bin/activate
pip install '.[dev]'
```

After making changes to Rust code, build and install module:

```shell
# uv
uv run maturin develop
# venv
maturin develop
```

Run Python CLI:

```shell
# uv
uv run python/p_vault/vault.py -h
# venv
python3 python/p_vault/vault.py -h
```

Install and run vault inside virtual env:

```shell
# uv
uv pip install .
uv run vault -h
# venv
pip install .
vault -h
```
