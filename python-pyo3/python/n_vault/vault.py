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

import os

from collections.abc import Collection
from dataclasses import dataclass
from typing import Optional, Union

from n_vault import nitor_vault_rs


@dataclass
class CloudFormationStackData:
    """Vault stack data from AWS CloudFormation describe stack."""

    result: str
    bucket: Optional[str]
    key: Optional[str]
    status: Optional[str]
    status_reason: Optional[str]
    version: Optional[int]


@dataclass
class StackCreated:
    """Result data for vault init."""

    result: str
    stack_name: Optional[str]
    stack_id: Optional[str]
    region: Optional[str]


@dataclass
class StackUpdated:
    """Result data for vault update."""

    result: str
    stack_id: Optional[str]
    previous_version: Optional[int]
    new_version: Optional[int]


class Vault:
    """
    Nitor Vault Python wrapper class around the Rust vault library.

    Note that initializing this class only saves the optional parameters,
    but does *not* construct an actual vault instance.
    Each method in this class creates its own Vault instance internally in the Rust library.
    """

    def __init__(
        self,
        vault_stack: str = None,
        vault_key: str = None,
        vault_bucket: str = None,
        vault_prefix: str = None,
        vault_region: str = None,
        profile: str = None,
    ):
        self.vault_stack = vault_stack
        self.vault_key = vault_key
        self.vault_bucket = vault_bucket
        self.vault_prefix = vault_prefix
        self.vault_region = vault_region
        self.profile = profile

    def all(self) -> str:
        """
        Return a string with all keys separated by os.linesep.
        """
        return os.linesep.join(item for item in self.list_all())

    def delete(self, name: str) -> None:
        """
        Delete data in S3 for given key name.
        """
        return nitor_vault_rs.delete(
            name,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def delete_many(self, names: Collection[str]) -> None:
        """
        Delete data for multiple keys.

        Takes in a collection of key name strings, such as a `list`, `tuple`, or `set`.
        """
        return nitor_vault_rs.delete_many(
            sorted(names),
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def direct_decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data with KMS.
        """
        return nitor_vault_rs.direct_decrypt(
            encrypted_data,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def direct_encrypt(self, data: Union[bytes, str]) -> bytes:
        """
        Encrypt data with KMS.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        return nitor_vault_rs.direct_encrypt(
            data,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def exists(self, name: str) -> bool:
        """
        Check if the given key name already exists in the S3 bucket.

        Returns True if the key exists, False otherwise.
        """
        return nitor_vault_rs.exists(
            name,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def init(self) -> Union[StackCreated, CloudFormationStackData]:
        """
        Initialize new Vault stack.

        This will create all required resources in AWS,
        after which the Vault can be used to store and lookup values.

        Returns a `StackCreated` if a new vault stack was initialized,
        or `CloudFormationStackData` if it already exists.
        """
        result = nitor_vault_rs.init(
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            profile=self.profile,
        )
        result_status = result.get("result")
        if result_status == "CREATED":
            return StackCreated(**result)
        elif result_status == "EXISTS" or result_status == "EXISTS_WITH_FAILED_STATE":
            return CloudFormationStackData(**result)

        raise RuntimeError(f"Unexpected result data: {result}")

    def list_all(self) -> list[str]:
        """
        Get all available secrets.

        Returns a list of key names.
        """
        return nitor_vault_rs.list_all(
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def lookup(self, name: str) -> str:
        """
        Lookup value for given key name.

        Always returns a string, with binary data encoded in base64.
        """
        return nitor_vault_rs.lookup(
            name,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def stack_status(self) -> CloudFormationStackData:
        """
        Get vault Cloudformation stack status.
        """
        data = nitor_vault_rs.stack_status(
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )
        return CloudFormationStackData(**data)

    def store(self, name: str, data: Union[bytes, str]) -> None:
        """
        Store encrypted value with given key name in S3.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        return nitor_vault_rs.store(
            name,
            data,
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )

    def update(self) -> Union[StackUpdated, CloudFormationStackData]:
        """
        Update the vault Cloudformation stack with the current template.

        Returns `StackUpdated` if the vault stack was updated to a new version,
        or `CloudFormationStackData` if it is already up to date.
        """
        result = nitor_vault_rs.update(
            vault_stack=self.vault_stack,
            region=self.vault_region,
            bucket=self.vault_bucket,
            key=self.vault_key,
            prefix=self.vault_prefix,
            profile=self.profile,
        )
        result_status = result.get("result")
        if result_status == "UPDATED":
            return StackUpdated(**result)
        elif result_status == "UP_TO_DATE":
            return CloudFormationStackData(**result)

        raise RuntimeError(f"Unexpected result data: {result}")
