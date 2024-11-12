# nitor-vault

Python vault implementation using the Rust vault library.

See the [repo](https://github.com/NitorCreations/vault) root readme for more general information.

## Usage

```console
Encrypted AWS key-value storage utility

Usage: vault [OPTIONS] [COMMAND]

Commands:
  all, -a, --all            List available secrets [aliases: a, list, ls]
  completion, --completion  Generate shell completion
  delete, -d, --delete      Delete an existing key from the store [aliases: d]
  describe, --describe      Print CloudFormation stack parameters for current configuration
  decrypt, -y, --decrypt    Directly decrypt given value [aliases: y]
  encrypt, -e, --encrypt    Directly encrypt given value [aliases: e]
  exists, --exists          Check if a key exists
  info, --info              Print vault information
  id                        Print AWS user account information
  status, --status          Print vault stack information
  init, -i, --init          Initialize a new KMS key and S3 bucket [aliases: i]
  update, -u, --update      Update the vault CloudFormation stack [aliases: u]
  lookup, -l, --lookup      Output secret value for given key [aliases: l]
  store, -s, --store        Store a new key-value pair [aliases: s]
  help                      Print this message or the help of the given subcommand(s)

Options:
  -b, --bucket <BUCKET>    Override the bucket name [env: VAULT_BUCKET=]
  -k, --key-arn <ARN>      Override the KMS key ARN [env: VAULT_KEY=]
  -p, --prefix <PREFIX>    Optional prefix for key name [env: VAULT_PREFIX=]
  -r, --region <REGION>    Specify AWS region for the bucket [env: AWS_REGION=]
      --vaultstack <NAME>  Specify CloudFormation stack name to use [env: VAULT_STACK=]
      --profile <PROFILE>  Specify AWS profile to use [env: AWS_PROFILE=]
  -q, --quiet              Suppress additional output and error messages
  -h, --help               Print help (see more with '--help')
  -V, --version            Print version
```

## Install

### From PyPI

Use [pipx](https://github.com/pypa/pipx) or [uv](https://github.com/astral-sh/uv)
to install the Python vault package from [PyPI](https://pypi.org/project/nitor-vault/) globally in an isolated environment.

```shell
pipx install nitor-vault
# or
uv tool install nitor-vault
```

The command `vault` should now be available in path.

### From source

Build and install locally from source code using pip.
This requires a [Rust toolchain](https://rustup.rs/) to be able to build the Rust library.
From the repo root:

```shell
cd python-pyo3
pip install .
# or with uv
uv pip install .
```

Check the command is found in path.
If you ran the install command inside a virtual env,
it will only be installed inside the venv,
and will not be available in path globally.

```shell
which -a vault
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
uv run python/n_vault/cli.py -h
# venv
python3 python/n_vault/cli.py -h
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
