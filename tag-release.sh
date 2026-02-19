#!/bin/bash
# Copyright 2016-2025 Nitor Creations Oy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Create annotated git tags for Rust and Python releases based on Cargo.toml version."
    echo ""
    echo "Options:"
    echo "  -p | --push    Push tags to origin after creating them"
    echo "  -f | --force   Overwrite existing tags"
    echo "  -h | --help    Show this help message"
    echo ""
    exit 0
}

PUSH=false
FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p | --push)
            PUSH=true
            shift
            ;;
        -f | --force)
            FORCE=true
            shift
            ;;
        -h | --help)
            usage
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            ;;
    esac
done

cd "$SCRIPT_DIR"

# Get version from workspace Cargo.toml
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')

if [ -z "$VERSION" ]; then
    print_error_and_exit "Could not extract version from Cargo.toml"
fi

RUST_TAG="rust-${VERSION}"
PYTHON_TAG="python-${VERSION}"

print_magenta "Version from Cargo.toml: $VERSION"
echo ""

# Check if tags already exist
TAGS_TO_CREATE=()

if git rev-parse "$RUST_TAG" >/dev/null 2>&1; then
    if [ "$FORCE" = true ]; then
        print_yellow "Tag $RUST_TAG exists, will overwrite"
        TAGS_TO_CREATE+=("$RUST_TAG")
    else
        print_yellow "Tag $RUST_TAG already exists, skipping..."
    fi
else
    TAGS_TO_CREATE+=("$RUST_TAG")
fi

if git rev-parse "$PYTHON_TAG" >/dev/null 2>&1; then
    if [ "$FORCE" = true ]; then
        print_yellow "Tag $PYTHON_TAG exists, will overwrite"
        TAGS_TO_CREATE+=("$PYTHON_TAG")
    else
        print_yellow "Tag $PYTHON_TAG already exists, skipping..."
    fi
else
    TAGS_TO_CREATE+=("$PYTHON_TAG")
fi

if [ ${#TAGS_TO_CREATE[@]} -eq 0 ]; then
    echo ""
    print_yellow "No new tags to create"
    exit 0
fi

# Create tags
for TAG in "${TAGS_TO_CREATE[@]}"; do
    if [ "$FORCE" = true ]; then
        print_green "Creating annotated tag: $TAG (force)"
        git tag -a -f "$TAG" -m "$TAG"
    else
        print_green "Creating annotated tag: $TAG"
        git tag -a "$TAG" -m "$TAG"
    fi
done

echo ""

if [ "$PUSH" = true ]; then
    print_magenta "Pushing tags to origin..."
    for TAG in "${TAGS_TO_CREATE[@]}"; do
        if [ "$FORCE" = true ]; then
            git push --force origin "$TAG"
        else
            git push origin "$TAG"
        fi
    done
    print_green "Done!"
else
    echo "Tags created. Push them with:"
    echo ""
    for TAG in "${TAGS_TO_CREATE[@]}"; do
        print_yellow "  git push origin $TAG"
    done
    echo ""
    echo "Or run this script with -p | --push to push automatically."
    echo "Use -f | --force to overwrite existing tags."
fi
