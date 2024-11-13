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


from collections.abc import Collection

from n_vault import nitor_vault_rs


class Vault:
    """Nitor Vault wrapper around the Rust vault library."""

    def __init__(
        self,
        vault_stack: str = None,
        region: str = None,
        bucket: str = None,
        key: str = None,
        prefix: str = None,
        profile: str = None,
    ):
        self.vault_stack = vault_stack
        self.region = region
        self.bucket = bucket
        self.key = key
        self.prefix = prefix
        self.profile = profile

    def delete(self, name: str) -> None:
        return nitor_vault_rs.delete(
            name,
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def delete_many(self, names: Collection[str]) -> None:
        return nitor_vault_rs.delete_many(
            sorted(names),
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def exists(self, name: str) -> bool:
        return nitor_vault_rs.exists(
            name,
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def init(self) -> dict[str]:
        return nitor_vault_rs.init(
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            profile=self.profile,
        )

    def list_all(self) -> list[str]:
        return nitor_vault_rs.list_all(
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def lookup(self, name: str) -> str:
        return nitor_vault_rs.lookup(
            name,
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def stack_status(self) -> dict[str]:
        return nitor_vault_rs.stack_status(
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def store(self, key: str, value: bytes | str) -> None:
        if isinstance(value, str):
            value = value.encode("utf-8")

        return nitor_vault_rs.store(
            key,
            value,
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )

    def update(self) -> dict[str]:
        return nitor_vault_rs.update(
            vault_stack=self.vault_stack,
            region=self.region,
            bucket=self.bucket,
            key=self.key,
            prefix=self.prefix,
            profile=self.profile,
        )
