# nitor-vault

![Crates.io Version](https://img.shields.io/crates/v/nitor-vault)

Rust CLI and library for encrypting keys and values using client-side encryption
with [AWS KMS](https://aws.amazon.com/kms/) keys.

Install the Rust vault CLI from [crates.io](https://crates.io/crates/nitor-vault) with:

```shell
cargo install nitor-vault
```

You will need to have Rust installed for this to work.
See [rustup.rs](https://rustup.rs) if you need to install Rust first.
By default, cargo puts the vault binary under `~/.cargo/bin/vault`.
Check with `which -a vault` to see what vault version you have first in path.

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
      --id <ID>            Specify AWS IAM access key ID
      --secret <SECRET>    Specify AWS IAM secret access key
      --profile <PROFILE>  Specify AWS profile name to use [env: AWS_PROFILE=]
  -q, --quiet              Suppress additional output and error messages
  -h, --help               Print help (see more with '--help')
  -V, --version            Print version
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

## Shell completion

Use the `completion` command to generate auto-completion scripts.

```console
Generate shell completion

Usage: vault {completion|--completion} [OPTIONS] <SHELL>

Arguments:
  <SHELL>  [possible values: bash, elvish, fish, powershell, zsh]

Options:
  -i, --install  Output completion directly to the correct directory instead of stdout
  -h, --help     Print help
```

### Oh My Zsh

If the `~/.oh-my-zsh/custom/plugins` dir is found when outputting for `zsh`,
the completions will be outputted as a custom plugin called `vault`.
Enable the completions by adding `vault` to the plugin list in `~/.zshrc` config.

### Powershell

A `completions` subdirectory will be created under the default profile directory path for the current user.
This will need to be loaded in the user profile, for example:

```powershell
# Load all completions scripts in the completions directory
$completionScriptsPath = "$HOME/.config/powershell/completions/"
if (Test-Path $completionScriptsPath)
{
    Get-ChildItem -Path $completionScriptsPath -Filter *.ps1 | ForEach-Object {
        . $_.FullName
    }
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

## TODO

- Add test cases with mocking: https://docs.aws.amazon.com/sdk-for-rust/latest/dg/testing.html
