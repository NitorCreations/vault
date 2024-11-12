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


from n_vault import nitor_vault_rs


class Vault:
    """Nitor Vault wrapper around the Rust vault library."""

    @staticmethod
    def lookup(name: str) -> str:
        return nitor_vault_rs.lookup(name)

    @staticmethod
    def list_all() -> list[str]:
        return nitor_vault_rs.list_all()
