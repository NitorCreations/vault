#!/bin/bash
set -exo pipefail

# Copyright 2016-2023 Nitor Creations Oy
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

# Import common functions
DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../common.sh
source "$DIR/../common.sh"

VERSION=$(grep '^VERSION' n_vault/__init__.py | cut -d\" -f 2)
MAJOR=${VERSION//.*/}
MINOR=${VERSION##*.}

if [ "$1" = "-m" ]; then
  MAJOR=$(($MAJOR + 1))
  MINOR="0"
  NEW_VERSION=$MAJOR.$MINOR
  shift
elif [ "$1" = "-v" ]; then
  shift
  NEW_VERSION="$1"
  shift
else
  MINOR=$(($MINOR + 1))
  NEW_VERSION=$MAJOR.$MINOR
  MESSAGE="$1"
fi

if [ -z "$MESSAGE" ]; then
  MESSAGE="$NEW_VERSION"
fi

"${SED_COMMAND[@]}" "s/^VERSION = .*/VERSION = \"$NEW_VERSION\"/g" n_vault/__init__.py
"${SED_COMMAND[@]}" "s/^version = .*/version = $NEW_VERSION/g" setup.cfg
# update tarball url versio
"${SED_COMMAND[@]}" "s/$VERSION/$NEW_VERSION/g" setup.cfg
git commit -m "$1" n_vault/__init__.py setup.cfg
git tag "$NEW_VERSION" -m "$MESSAGE"
git push origin "$NEW_VERSION"
rm -rf dist

check_and_set_python
$PYTHON setup.py sdist bdist_wheel
twine upload dist/*
