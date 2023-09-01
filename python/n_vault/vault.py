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

import json
import os
from base64 import b64decode, b64encode

from botocore.exceptions import ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from threadlocal_aws import region, session
from threadlocal_aws.clients import cloudformation, kms, s3, sts
from threadlocal_aws.resources import s3_Bucket as bucket

from n_vault.template import TEMPLATE_STRING, VAULT_STACK_VERSION


def _template():
    return json.dumps(json.loads(TEMPLATE_STRING))


def _to_bytes(data):
    encode_method = getattr(data, "encode", None)
    if callable(encode_method):
        return data.encode("utf-8")
    return data


def _to_str(data):
    decode_method = getattr(data, "decode", None)
    if callable(decode_method):
        return data.decode("utf-8")
    return data


class Vault:
    _session = session()
    _kms = ""
    _prefix = ""
    _vault_key = ""
    _vault_bucket = ""
    _stack = ""

    def __init__(
        self,
        vault_stack="",
        vault_key="",
        vault_bucket="",
        vault_iam_id="",
        vault_iam_secret="",
        vault_prefix="",
        vault_region=None,
        vault_init=False,
    ):
        self._prefix = vault_prefix
        if self._prefix and not self._prefix.endswith("/"):
            self._prefix = self._prefix + "/"
        if not vault_region:
            vault_region = region()
        self._region = vault_region
        if not vault_stack:
            if "VAULT_STACK" in os.environ:
                self._stack = os.environ["VAULT_STACK"]
            else:
                self._stack = "vault"
        else:
            self._stack = vault_stack

        # Either use given vault iam credentials or assume that the environment has
        # some usable credentials (either through env vars or instance profile)
        if vault_iam_id and vault_iam_secret:
            self._session = session(aws_access_key_id=vault_iam_id, aws_secret_access_key=vault_iam_secret)
        self._c_args = {"session": self._session, "region": self._region}

        # Either use given vault kms key and/or vault bucket or look them up from a CloudFormation stack
        if vault_key:
            self._vault_key = vault_key
        elif "VAULT_KEY" in os.environ:
            self._vault_key = os.environ["VAULT_KEY"]
        if vault_bucket:
            self._vault_bucket = vault_bucket
        elif "VAULT_BUCKET" in os.environ:
            self._vault_bucket = os.environ["VAULT_BUCKET"]

        # If not given in constructor or environment, resolve from CloudFormation
        if not (self._vault_key and self._vault_bucket):
            if not vault_init:
                stack_info = self._get_cf_params()
                if not self._vault_key and "key_arn" in stack_info:
                    self._vault_key = stack_info["key_arn"]
                if not self._vault_bucket and "bucket_name" in stack_info:
                    self._vault_bucket = stack_info["bucket_name"]
        if not self._vault_bucket:
            account_id = sts(**self._c_args).get_caller_identity()["Account"]
            self._vault_bucket = self._stack + "-" + self._region + "-" + account_id

    def _encrypt(self, data):
        ret = {}
        key_dict = kms(**self._c_args).generate_data_key(KeyId=self._vault_key, KeySpec="AES_256")
        data_key = key_dict["Plaintext"]
        ret["datakey"] = key_dict["CiphertextBlob"]
        aesgcm_cipher = AESGCM(data_key)
        nonce = os.urandom(12)
        meta = json.dumps(
            {"alg": "AESGCM", "nonce": b64encode(nonce).decode()},
            separators=(",", ":"),
            sort_keys=True,
        )
        ret["aes-gcm-ciphertext"] = aesgcm_cipher.encrypt(nonce, data, _to_bytes(meta))
        cipher = _get_cipher(data_key)
        encryptor = cipher.encryptor()
        ret["ciphertext"] = encryptor.update(data) + encryptor.finalize()
        ret["meta"] = meta
        return ret

    def _decrypt(self, data_key, encrypted):
        decrypted_key = self.direct_decrypt(data_key)
        cipher = _get_cipher(decrypted_key)
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()

    def _aes_gcm_decrypt(self, nonce, data_key, encrypted):
        decrypted_key = self.direct_decrypt(data_key)
        cipher = AESGCM(decrypted_key)
        return cipher.decrypt(nonce, encrypted, None)

    def _get_cf_params(self):
        stack = cloudformation(**self._c_args).describe_stacks(StackName=self._stack)
        ret = {}
        if "Stacks" in stack and stack["Stacks"]:
            for output in stack["Stacks"][0]["Outputs"]:
                if output["OutputKey"] == "vaultBucketName":
                    ret["bucket_name"] = output["OutputValue"]
                if output["OutputKey"] == "kmsKeyArn":
                    ret["key_arn"] = output["OutputValue"]
                if output["OutputKey"] == "vaultStackVersion":
                    ret["deployed_version"] = int(output["OutputValue"])
        return ret

    def store(self, name, data):
        encrypted = self._encrypt(data)
        s3(**self._c_args).put_object(
            Bucket=self._vault_bucket,
            Body=encrypted["datakey"],
            ACL="private",
            Key=self._prefix + name + ".key",
        )
        s3(**self._c_args).put_object(
            Bucket=self._vault_bucket,
            Body=encrypted["ciphertext"],
            ACL="private",
            Key=self._prefix + name + ".encrypted",
        )
        s3(**self._c_args).put_object(
            Bucket=self._vault_bucket,
            Body=encrypted["aes-gcm-ciphertext"],
            ACL="private",
            Key=self._prefix + name + ".aesgcm.encrypted",
        )
        s3(**self._c_args).put_object(
            Bucket=self._vault_bucket,
            Body=encrypted["meta"],
            ACL="private",
            Key=self._prefix + name + ".meta",
        )
        return True

    def lookup(self, name):
        datakey = bytes(
            s3(**self._c_args).get_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".key")["Body"].read()
        )
        try:
            meta_add = bytes(
                s3(**self._c_args)
                .get_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".meta")["Body"]
                .read()
            )
            ciphertext = bytes(
                s3(**self._c_args)
                .get_object(
                    Bucket=self._vault_bucket,
                    Key=self._prefix + name + ".aesgcm.encrypted",
                )["Body"]
                .read()
            )
            meta = json.loads(_to_str(meta_add))
            return AESGCM(self.direct_decrypt(datakey)).decrypt(b64decode(meta["nonce"]), ciphertext, meta_add)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404" or e.response["Error"]["Code"] == "NoSuchKey":
                ciphertext = bytes(
                    s3(**self._c_args)
                    .get_object(
                        Bucket=self._vault_bucket,
                        Key=self._prefix + name + ".encrypted",
                    )["Body"]
                    .read()
                )
                return self._decrypt(datakey, ciphertext)
            else:
                raise

    def recrypt(self, name):
        data = self.lookup(name)
        self.store(name, data)

    def exists(self, name):
        try:
            s3(**self._c_args).head_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".key")
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            else:
                raise

    def delete(self, name):
        s3(**self._c_args).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".key")
        s3(**self._c_args).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".encrypted")
        try:
            s3(**self._c_args).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".aesgcm.encrypted")
            s3(**self._c_args).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + ".meta")
        except ClientError as e:
            if e.response["Error"]["Code"] == "404" or e.response["Error"]["Code"] == "NoSuchKey":
                pass
            else:
                raise

    def all(self):
        ret = ""
        for item in self.list_all():
            ret = ret + item + os.linesep
        return ret

    def list_all(self):
        ret = []
        for next_object in bucket(self._vault_bucket, **self._c_args).objects.filter(Prefix=self._prefix):
            if next_object.key.endswith(".aesgcm.encrypted") and next_object.key[:-17] not in ret:
                ret.append(next_object.key[:-17])
            elif next_object.key.endswith(".encrypted") and next_object.key[:-10] not in ret:
                ret.append(next_object.key[:-10])
        return ret

    def get_key(self):
        return self._vault_key

    def get_bucket(self):
        return self._vault_bucket

    def direct_encrypt(self, data):
        return kms(**self._c_args).encrypt(KeyId=self._vault_key, Plaintext=data)["CiphertextBlob"]

    def direct_decrypt(self, encrypted_data):
        return kms(**self._c_args).decrypt(CiphertextBlob=encrypted_data)["Plaintext"]

    def init(self):
        try:
            cloudformation(**self._c_args).describe_stacks(StackName=self._stack)
            print("Vault stack '" + self._stack + "' already initialized")
        except Exception:
            params = {"ParameterKey": "paramBucketName", "ParameterValue": self._vault_bucket}
            cloudformation(**self._c_args).create_stack(
                StackName=self._stack,
                TemplateBody=_template(),
                Parameters=[params],
                Capabilities=["CAPABILITY_IAM"],
            )

    def update(self):
        try:
            cloudformation(**self._c_args).describe_stacks(StackName=self._stack)
            deployed_version = None
            ok_to_update = False
            params = self._get_cf_params()
            if "deployed_version" in params:
                deployed_version = params["deployed_version"]
            if deployed_version < VAULT_STACK_VERSION:
                ok_to_update = True
            if ok_to_update or deployed_version is None:
                params = {"ParameterKey": "paramBucketName", "UsePreviousValue": True}
                cloudformation(**self._c_args).update_stack(
                    StackName=self._stack,
                    TemplateBody=_template(),
                    Parameters=[params],
                    Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
                )
            else:
                print(f"Current stack version {deployed_version} does not need update to version {VAULT_STACK_VERSION}")
        except Exception as e:
            print(f"Error while updating stack '{self._stack}': {repr(e)}")


STATIC_IV = bytearray(
    [
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0 & 0xFF,
        int(1337 / 256) & 0xFF,
        int(1337 % 256) & 0xFF,
    ]
)


def _get_cipher(key):
    backend = default_backend()
    return Cipher(AES(key), CTR(bytes(STATIC_IV)), backend=backend)
