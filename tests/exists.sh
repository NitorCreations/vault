#!/bin/bash

CMD="$1"
KEY="$2"

echo "Verifying '$KEY' does not exist using '$CMD'..."
$CMD exists "$KEY" 2>&1 | tee output.log

test -f output.log || (echo "Error: output.log does not exist" && exit 1)

grep -q "key '$KEY' does not exist" < output.log

rm -f output.log
