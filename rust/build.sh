#!/bin/bash
set -eo pipefail

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

if [ -z "$(command -v cargo)" ]; then
    print_error "Cargo not found in path. Maybe install rustup?"
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
./"$executable" --version
./"$executable" -h
popd > /dev/null
