#!/bin/bash
set -eo pipefail

# Copyright 2016-2024 Nitor Creations Oy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

USAGE="Usage: $(basename "$0") [OPTIONS] [MESSAGE]

Create new release for Nitor vault.

Arguments:
  [MESSAGE]    Optional commit message for git commit (default is the new version).

OPTIONS: All options are optional
  -h | --help                 Display these instructions.
  -d | --dryrun               Only print commands instead of executing them.
  -m | --major                Increment major version and reset minor version to 0.
  -v | --version [VERSION]    Set the new version explicitly.
  -x | --verbose              Display commands being executed.

Example Usage:
  $(basename "$0") -v 2.5              # Set version to 2.5.
  $(basename "$0") 'Updated features'  # Increment minor version number with commit message 'Updated features'."

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

init_options() {
  DRYRUN=false
  VERSION=$(grep '^VERSION' n_vault/__init__.py | cut -d\" -f 2)
  echo "Current version: $VERSION"
  MAJOR=${VERSION//.*/}
  MINOR=${VERSION##*.}
  while [ $# -gt 0 ]; do
    case "$1" in
      -h | --help)
        echo "$USAGE"
        exit 1
        ;;
      -d | --dryrun)
        DRYRUN=true
        print_yellow "Doing a dryrun"
        ;;
      -m | --major)
        MAJOR=$(($MAJOR + 1))
        MINOR="0"
        NEW_VERSION=$MAJOR.$MINOR
        echo "Incrementing major version: $NEW_VERSION"
        ;;
      -v | --version)
        NEW_VERSION="$2"
        shift
        ;;
      -x | --verbose)
        set -x
        ;;
      *)
        MESSAGE="$1"
        ;;
    esac
    shift
  done

  if [ -z "$NEW_VERSION" ]; then
    MINOR=$(($MINOR + 1))
    NEW_VERSION=$MAJOR.$MINOR
    echo "Incrementing minor version: $NEW_VERSION"
  fi

  if [ -z "$MESSAGE" ]; then
    MESSAGE="$NEW_VERSION"
  fi
}

init_options "$@"

print_magenta "Updating version number..."
"${SED_COMMAND[@]}" "s/^VERSION = .*/VERSION = \"$NEW_VERSION\"/g" n_vault/__init__.py
"${SED_COMMAND[@]}" "s/^version = .*/version = \"$NEW_VERSION\"/g" pyproject.toml
"${SED_COMMAND[@]}" "s|https://github.com/NitorCreations/vault/tarball/[^\"]*|https://github.com/NitorCreations/vault/tarball/$NEW_VERSION|g" pyproject.toml

run_command git commit -m "$MESSAGE" n_vault/__init__.py pyproject.toml
# TODO: should use annotated tags for releases: convert old tags and add `-a` here
run_command git tag "$NEW_VERSION" -m "$MESSAGE"
run_command git push origin "$NEW_VERSION"

print_magenta "Building package..."
rm -rf dist
check_and_set_python
$PYTHON -m build --sdist --wheel

print_magenta "Uploading package..."
twine check dist/*
run_command twine upload dist/*
