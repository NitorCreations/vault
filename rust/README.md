# nitor-vault

CLI and library for encrypting keys and values using client-side encryption with AWS KMS keys.

## Build

```shell
# debug
cargo build
cargo run
# release
cargo build --release
cargo run --release
```

Cargo will output the executable to either

```shell
rust/target/debug/vault
rust/target/release/vault
```

depending on which build profile is used.

## Install

You can install a release binary locally using [cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html).
Note that you need to specify the path to the directory containing [Cargo.toml](./Cargo.toml),
so from the repo root you would do:

```shell
cargo install --path rust/
```

Cargo will put the binary under `$HOME/.cargo/bin` by default, which you should add to PATH if you don't have it there,
so the binaries installed through Cargo will be found.

## Format code

Using [rustfmt](https://github.com/rust-lang/rustfmt)

```shell
cargo fmt
```

## Lint

Using [Clippy](https://github.com/rust-lang/rust-clippy)

```shell
cargo clippy
cargo clippy --fix
```

## Update dependencies

```shell
cargo update
```
