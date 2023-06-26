#!/bin/bash
set -eo pipefail

# Build the Rust vault binary.

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

print_magenta "Building vault binary (Rust)..."

if [ -z "$(command -v cargo)" ]; then
    print_error_and_exit "Cargo not found in path. Maybe install rustup?"
fi

pushd "$DIR" > /dev/null
cargo build --release

if [ "$PLATFORM" = windows ]; then
    executable="vault.exe"
else
    executable="vault"
fi

rm -f "$executable"
mv ./target/release/"$executable" "$executable"
file "$executable"
./"$executable" --version
./"$executable" -h
popd > /dev/null
