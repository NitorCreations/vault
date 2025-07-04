#!/bin/bash
set -eo pipefail

# Common shell functions and definitions

REPO_ROOT=$(git rev-parse --show-toplevel || (cd "$(dirname "${BASH_SOURCE[0]}")" && pwd))
export REPO_ROOT

# Check BASH_PLATFORM
case "$(uname -s)" in
  "Darwin")
    BASH_PLATFORM="mac"
    ;;
  "MINGW"*)
    BASH_PLATFORM="windows"
    ;;
  *)
    BASH_PLATFORM="linux"
    ;;
esac
export BASH_PLATFORM

# BSD sed on MacOS works differently
if [ "$BASH_PLATFORM" = mac ]; then
  SED_COMMAND=(sed -i '')
else
  SED_COMMAND=(sed -i)
fi
export SED_COMMAND

# Print a message with red color
print_red() {
  printf "\e[1;49;31m%s\e[0m\n" "$1"
}

# Print a message with green color
print_green() {
  printf "\e[1;49;32m%s\e[0m\n" "$1"
}

# Print a message with yellow color
print_yellow() {
  printf "\e[1;49;33m%s\e[0m\n" "$1"
}

# Print a message with magenta color
print_magenta() {
  printf "\e[1;49;35m%s\e[0m\n" "$1"
}

print_error() {
  print_red "ERROR: $1"
}

print_warn() {
  print_yellow "WARNING: $1"
}

# Print an error and exit the program
print_error_and_exit() {
  print_error "$1"
  # use exit code if given as argument, otherwise default to 1
  exit "${2:-1}"
}

# Check Python is found on path and set PYTHON variable to it
check_and_set_python() {
  if [ -n "$(command -v python3)" ]; then
    PYTHON=$(which python3)
  elif [ -n "$(command -v python)" ]; then
    PYTHON=$(which python)
  else
    print_error_and_exit "Python not found in path"
  fi
  echo "$($PYTHON --version) from $PYTHON"
}

# if DRYRUN or DRY_RUN has been set, only print commands instead of running them
run_command() {
  if [ "$DRY_RUN" = true ] || [ "$DRYRUN" = true ]; then
    print_yellow "DRYRUN: $*"
  else
    echo "Running: $*"
    "$@"
  fi
}

# Set variables GIT_HASH and GIT_BRANCH
set_version_info() {
  BUILD_TIME=$(date -u +"%Y-%m-%dT%H%MZ")
  GIT_HASH=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
  GIT_BRANCH=$(git -C "$REPO_ROOT" branch --show-current)
  export BUILD_TIME
  export GIT_HASH
  export GIT_BRANCH
}
