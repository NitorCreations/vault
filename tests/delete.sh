#!/bin/bash
set -eo pipefail

CMD="$1"
KEY="$2"

echo "Deleting secret '$KEY' using '$CMD'..."
$CMD -d "$KEY" 2>&1 | tee output.log

test -f output.log || (echo "Error: output.log does not exist" && exit 1)
test -s output.log && (echo "Unexpected output in vault delete command:" && cat output.log && exit 1)

rm -f output.log
