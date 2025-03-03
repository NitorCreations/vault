#!/bin/bash
set -eo pipefail

COMMANDS=(
  "vault"
  "bin/go/vault"
  "bin/rust/vault"
  "nodejs/dist/cli/vault.js"
)

KEYS=(
  "secret-python"
  "secret-go"
  "secret-rust"
  "secret-nodejs"
)

for ((i = 0; i < ${#COMMANDS[@]}; i++)); do
  for ((j = i + 1; j < ${#COMMANDS[@]}; j++)); do
    for key in "${KEYS[@]}"; do
      cmd1="${COMMANDS[i]}"
      cmd2="${COMMANDS[j]}"
      echo "Comparing '$cmd1' and '$cmd2' with '$key'"
      diff <($cmd1 -l "$key") <($cmd2 -l "$key")
    done
  done
done
