#!/bin/bash
set -eo pipefail

# Install the Rust vault binary.

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

print_magenta "Installing vault binary (Rust)..."

if [ -z "$(command -v cargo)" ]; then
    print_error_and_exit "Cargo not found in path. Maybe install rustup?"
fi

cargo install --path "$REPO_ROOT/rust"

if [ -z "$(command -v vault)" ]; then
    print_error_and_exit "Binary not found. Is the Cargo install directory in path?"
fi

print_magenta "Checking version..."

echo "$(vault --version) from $(which vault)"
