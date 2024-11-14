# Copyright 2016-2024 Nitor Creations Oy
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

import sys

from n_vault import nitor_vault_rs


def main():
    try:
        # Override the script name in the arguments list so the Rust CLI works correctly
        args = ["vault"] + sys.argv[1:]
        nitor_vault_rs.run(args)
    except KeyboardInterrupt:
        print("\naborted")
        exit(1)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
