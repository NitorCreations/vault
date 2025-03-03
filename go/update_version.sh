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

  -m | --major
    Increment major version.

  -v | --version <VERSION>
    Use given version as the new version number.

   --verbose
    Display commands being executed.
"

init_options() {
  INCREMENT_MAJOR=false
  while [ $# -gt 0 ]; do
    case "$1" in
      -h | --help)
        echo "$USAGE"
        exit 1
        ;;
      -m | --major)
        INCREMENT_MAJOR=true
        ;;
      -v | --version)
        VERSION="$2"
        shift
        ;;
      --verbose)
        set -x
        ;;
    esac
    shift
  done
}

init_options "$@"

VERSION_FILE="$DIR/cli/version.go"

CURRENT_VERSION="$(grep "const VersionNumber =" "$VERSION_FILE" | cut -d\" -f 2)"
MAJOR=$(echo "$CURRENT_VERSION" | cut -d '.' -f 1)
MINOR=$(echo "$CURRENT_VERSION" | cut -d '.' -f 2)

if [ -n "$VERSION" ] && [ "$INCREMENT_MAJOR" = true ]; then
  print_warn "Conflicting version arguments, using $VERSION"
fi

if [ -n "$VERSION" ]; then
  NEW_VERSION="$VERSION"
elif [ "$INCREMENT_MAJOR" = true ]; then
  MAJOR=$((MAJOR + 1))
  NEW_VERSION="$MAJOR.0.0"
else
  echo "Incrementing minor version"
  MINOR=$((MINOR + 1))
  NEW_VERSION="$MAJOR.$MINOR.0"
fi

echo "Current version:    $CURRENT_VERSION"
if [[ "$NEW_VERSION" =~ ^[0-9]+(\.[0-9]+){2}$ ]]; then
  print_green "New version number: $NEW_VERSION"
else
  print_error_and_exit "Version number needs to be in format 'X.X.X', got: $NEW_VERSION"
fi

set_version_info
{
  echo "package cli"
  echo ""
  echo "// Generated automatically; DO NOT EDIT MANUALLY."
  echo ""
  echo "const VersionNumber = \"$NEW_VERSION\""
} > "$VERSION_FILE"
