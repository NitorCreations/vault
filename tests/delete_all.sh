#!/bin/bash
set -eo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

CMD="$1"

for key in $($CMD --all | xargs); do
  "$DIR"/delete.sh "$CMD" "$key"
done
