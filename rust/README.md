# nitor-vault

Rust CLI and library for encrypting keys and values using client-side encryption with [AWS KMS](https://aws.amazon.com/kms/) keys.

## Build

Using the shell script:

```shell
./build.sh
```

Note: works on Windows too, just use Git for Windows Bash to run it.

Manually from terminal:

```shell
# debug
cargo build
cargo run
# release
cargo build --release
cargo run --release
```

Depending on which build profile is used, Cargo will output the executable to either:

```shell
rust/target/debug/vault
rust/target/release/vault
```

## Install

You can install a release binary locally using [cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html).
Note that you need to specify the path to the directory containing [Cargo.toml](./Cargo.toml),
so from the repo root you would do:

```shell
cargo install --path rust/
```

Using the shell script:

```shell
./install.sh
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
