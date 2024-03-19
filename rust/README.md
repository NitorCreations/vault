# nitor-vault

Rust CLI and library for encrypting keys and values using client-side encryption
with [AWS KMS](https://aws.amazon.com/kms/) keys.

```console
Usage: vault [OPTIONS] [COMMAND]

Commands:
  delete, -d, --delete  Delete an existing key from the store
  describe, --describe  Describe CloudFormation stack parameters for current configuration
  exists, -e, --exists  Check if a key exists
  all, -a, --all        List available secrets
  lookup, -l, --lookup  Print secret value for given key
  store, -s, --store    Store a new key-value pair
  info, -i, --info      Print region and stack information
  help                  Print this message or the help of the given subcommand(s)

Options:
  -b, --bucket <BUCKET>            Override the bucket name [env: VAULT_BUCKET=]
  -k, --key-arn <KEY_ARN>          Override the KMS key arn for storing or looking up [env: VAULT_KEY=]
  -r, --region <REGION>            Specify AWS region for the bucket [env: AWS_REGION=]
      --vault-stack <VAULT_STACK>  Optional CloudFormation stack to lookup key and bucket [env: VAULT_STACK=]
  -h, --help                       Print help (see more with '--help')
  -V, --version                    Print version
```

## Build

Using the shell script:

```shell
./build.sh
```

Note: works on Windows too, use Git for Windows Bash to run it.

Manually from terminal:

```shell
# debug
cargo build
cargo run
# release
cargo build --release
cargo run --release
# pass arguments
cargo run --release -- --help
```

Depending on which build profile is used, Cargo will output the executable to either:

```shell
rust/target/debug/vault
rust/target/release/vault
```

## Install

You can install a release binary locally
using [cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html).

Use the shell script:

```shell
./install.sh
```

The script calls `cargo install` and checks for the binary in path.
If you run the command directly,
note that you need to specify the path to the directory containing [Cargo.toml](./Cargo.toml).
From the repo root you would do:

```shell
cargo install --path rust/
```

Cargo will put the binary under `$HOME/.cargo/bin` by default,
which you should add to PATH if you don't have it there,
so the binaries installed through Cargo will be found.

If you still get another version when using vault,
you will need to put the cargo binary path `$HOME/.cargo/bin` first in path.

## Format code

Using [rustfmt](https://github.com/rust-lang/rustfmt)

```shell
cargo fmt
```

## Lint code

Using [Clippy](https://github.com/rust-lang/rust-clippy)

```shell
cargo clippy
cargo clippy --fix
```

## Update dependencies

```shell
cargo update
```
