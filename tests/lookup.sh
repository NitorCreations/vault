#!/bin/bash
set -eo pipefail

CMD="$1"
KEY="$2"
EXPECTED_VALUE="${3:-sha-$(git rev-parse HEAD)}"

echo "Looking up secret '$KEY' using '$CMD'..."
$CMD -l "$KEY" 2>&1 | tee output.log

test -f output.log || (echo "Error: output.log does not exist" && exit 1)

ACTUAL_VALUE=$(cat output.log)
[ "$ACTUAL_VALUE" = "$EXPECTED_VALUE" ] || (echo "Unexpected output in vault retrieval:" && cat output.log && exit 1)

rm -f output.log
