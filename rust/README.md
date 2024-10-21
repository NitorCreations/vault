# nitor-vault

![Crates.io Version](https://img.shields.io/crates/v/nitor-vault)

Rust CLI and library for encrypting keys and values using client-side encryption
with [AWS KMS](https://aws.amazon.com/kms/) keys.

Install the Rust vault CLI from [crates.io](https://crates.io/crates/nitor-vault) with:

```terminal
cargo install nitor-vault
```

You will need to have Rust installed for this to work.
See [rustup.rs](https://rustup.rs) if you need to install Rust first.
By default, cargo puts the vault binary under `~/.cargo/bin/vault`.
Check with `which -a vault` to see what vault version you have first in path.

```console
Encrypted AWS key-value storage utility.

Usage: vault [OPTIONS] [COMMAND]

Commands:
  all, -a, --all        List available secrets
  delete, -d, --delete  Delete an existing key from the store
  describe, --describe  Describe CloudFormation stack parameters for current configuration
  exists, -e, --exists  Check if a key exists
  info, --info          Print vault information
  id, --id              Print AWS user account information
  status, --status      Print vault stack information
  init, -i, --init      Initialize a new KMS key and S3 bucket
  update, -u, --update  Update the vault CloudFormation stack
  lookup, -l, --lookup  Output secret value for given key
  store, -s, --store    Store a new key-value pair
  help                  Print this message or the help of the given subcommand(s)

Options:
  -b, --bucket <BUCKET>     Override the bucket name [env: VAULT_BUCKET=]
  -k, --key-arn <ARN>       Override the KMS key ARN [env: VAULT_KEY=]
  -p, --prefix <PREFIX>     Optional prefix for key name [env: VAULT_PREFIX=]
  -r, --region <REGION>     Specify AWS region for the bucket [env: AWS_REGION=]
      --vault-stack <NAME>  Specify CloudFormation stack name to use [env: VAULT_STACK=]
  -h, --help                Print help (see more with '--help')
  -V, --version             Print version
```

ANSI color output can be disabled by setting the env variable `NO_COLOR=1`.

## Library

The Nitor vault library can be used in other Rust projects directly.
Add the crate to your project with:

```shell
cargo add nitor-vault
```

```rust
use nitor_vault::Vault;

fn main() -> anyhow::Result<()> {
    let vault = Vault::default().await?;
    let value = Box::pin(vault.lookup("secret-key")).await?;
    println!("{value}");
    Ok(())
}
```

## Development

### Build

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

### Install

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

### Format code

Using [rustfmt](https://github.com/rust-lang/rustfmt)

```shell
cargo fmt
```

### Lint code

Using [Clippy](https://github.com/rust-lang/rust-clippy)

```shell
cargo clippy
cargo clippy --fix
```

### Update dependencies

```shell
cargo update
```

## Publish a new crate version

Go to [crates.io/settings/tokens](https://crates.io/settings/tokens) and create a new API token,
unless you already have one that has not expired.
Do _not_ create a token with no expiration date,
and prefer short expiration times.

Copy token and run `cargo login <token>`.

If you need to publish an older version (that is not the current git HEAD commit),
first checkout the version you want to publish.

Try publishing with `cargo publish --dry-run` and then run with `cargo publish`.
