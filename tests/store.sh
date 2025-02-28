#!/bin/bash
set -eo pipefail

CMD="$1"
KEY="$2"
VALUE="${3:-sha-$(git rev-parse HEAD)}"

echo "Storing secret '$KEY' using '$CMD'..."
$CMD -s "$KEY" -v "$VALUE" -w 2>&1 | tee output.log

test -f output.log || (echo "Error: output.log does not exist" && exit 1)
test -s output.log && (echo "Unexpected output in vault command:" && cat output.log && exit 1)

rm -f output.log
