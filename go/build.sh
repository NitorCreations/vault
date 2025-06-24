#!/bin/bash
set -eo pipefail

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

USAGE="Usage: $(basename "$0") [OPTIONS]

OPTIONS: All options are optional
  -h | --help
    Display these instructions.

  -v | --verbose
    Display commands being executed.
"

init_options() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -h | --help)
        echo "$USAGE"
        exit 1
        ;;
      -v | --verbose)
        set -x
        ;;
    esac
    shift
  done

  # Get absolute path to repo root
  REPO_ROOT=$(git rev-parse --show-toplevel || (cd "$(dirname "../${BASH_SOURCE[0]}")" && pwd))
  PROJECT_PATH="$REPO_ROOT/go"

  if [ "$BASH_PLATFORM" = windows ]; then
    EXECUTABLE="vault.exe"
  else
    EXECUTABLE="vault"
  fi
}

build_project() {
  print_magenta "Building Nitor Vault (Go)..."
  if [ -z "$(command -v go)" ]; then
    print_error_and_exit "go not found in path"
  else
    go version
  fi

  pushd "$PROJECT_PATH" > /dev/null
  rm -f "$EXECUTABLE"
  time go build -v -o vault \
    -ldflags "-X github.com/nitorcreations/vault/go/cli.GitBranch=$GIT_BRANCH \
              -X github.com/nitorcreations/vault/go/cli.GitHash=$GIT_HASH \
              -X github.com/nitorcreations/vault/go/cli.Timestamp=$BUILD_TIME"

  file "$EXECUTABLE"
  popd > /dev/null
}

update_version_file() {
  VERSION_FILE="$PROJECT_PATH/cli/version.go"
  CURRENT_VERSION="$(grep "const VersionNumber =" "$VERSION_FILE" | cut -d\" -f 2)"
  {
    echo "package cli"
    echo ""
    echo "// Generated automatically; DO NOT EDIT MANUALLY."
    echo ""
    echo "const VersionNumber = \"$CURRENT_VERSION\""
  } > "$VERSION_FILE"
}

init_options "$@"
set_version_info
update_version_file
build_project
