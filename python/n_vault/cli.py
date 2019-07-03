
# Copyright 2016 Nitor Creations Oy
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
from __future__ import print_function
import argparse
import locale
import os
import sys
import json
import argcomplete
import requests
from base64 import b64decode, b64encode
from requests.exceptions import ConnectionError
from n_vault.vault import Vault

SYS_ENCODING = locale.getpreferredencoding()

def main():
    parser = argparse.ArgumentParser(description="Store and lookup locally " +\
                                     "encrypted data stored in S3")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('-s', '--store', help="Name of element to store. Opt" +\
                                              "ionally read from file name",
                        nargs='?', default="")
    action.add_argument('-l', '--lookup', help="Name of element to lookup")
    action.add_argument('-c', '--recrypt', help="Recrypt entry with AESGCM for added security")
    action.add_argument('-i', '--init', action='store_true',
                        help="Initializes a kms key and a s3 bucket with som" +\
                              "e roles for reading and writing on a fresh ac" +\
                              "count via CloudFormation. Means that the acco" +\
                              "unt used has to have rights to create the res" +\
                              "ources")
    action.add_argument('-u', '--update', action='store_true',
                        help="Updates the CloudFormation stack which declare" +\
                              "s all resources needed by the vault.")
    action.add_argument('-d', '--delete', help="Name of element to delete")
    action.add_argument('-a', '--all', action='store_true', help="List avail" +\
                                                                 "able secrets")
    action.add_argument('-e', '--encrypt', help="Directly encrypt given value")
    action.add_argument('-y', '--decrypt', help="Directly decrypt given value")
    parser.add_argument('-w', '--overwrite', action='store_true',
                        help="Add this argument if you want to overwrite an " +\
                             "existing element")
    store_data = parser.add_mutually_exclusive_group(required=False)
    store_data.add_argument('-v', '--value', help="Value to store")
    store_data.add_argument('-f', '--file', help="File to store. If no -s argument" +\
                                           " given, the name of the file is " +\
                                           "used as the default name. Give -" +\
                                           " for stdin")
    parser.add_argument('-o', "--outfile", help="The file to write the data to")
    parser.add_argument('-p', '--prefix', help="Optional prefix to store val" +\
                                               "ue under. empty by default")
    parser.add_argument('--vaultstack', help="Optional CloudFormation stack " +\
                                             "to lookup key and bucket. 'vau" +\
                                             "lt' by default")
    parser.add_argument('-b', '--bucket', help="Override the bucket name eit" +\
                                               "her for initialization or st" +\
                                               "oring and looking up values")
    parser.add_argument('-k', '--key-arn', help="Override the KMS key arn fo" +\
                                                "r storinig or looking up")
    parser.add_argument('--id', help="Give an IAM access key id to override " +\
                                     "those defined by environent")
    parser.add_argument('--secret', help="Give an IAM secret access key to o" +\
                                         "verride those defined by environent")
    parser.add_argument('-r', '--region', help="Give a region for the stack" +\
                                               "and bucket")
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    if args.store and not (args.value or args.file):
        parser.error("--store requires --value or --file")
    store_with_no_name = not args.store and not args.lookup and not args.init \
                         and not args.delete and not args.all and not args.update \
                         and not args.recrypt and not args.encrypt and not args.decrypt
    if store_with_no_name and not args.file:
        parser.error("--store requires a name or a --file argument to get the name to store")
    elif store_with_no_name:
        if args.file == "-":
            parser.error("--store requires a name for stdin")
        else:
            args.store = os.path.basename(args.file)
            data = open(args.file, 'rb').read()
    elif args.store:
        if args.value:
            data = args.value.encode("utf-8")
        elif args.file == "-":
            if getattr(sys.stdin, "buffer", None):
                data = sys.stdin.buffer.read()
            else:
                data = sys.stdin.read()
        else:
            with open(args.file, 'rb') as f:
                data = bytes(f.read())
    if not args.vaultstack:
        if "VAULT_STACK" in os.environ:
            args.vaultstack = os.environ["VAULT_STACK"]
        else:
            args.vaultstack = "vault"

    if not args.bucket and "VAULT_BUCKET" in os.environ:
        args.bucket = os.environ["VAULT_BUCKET"]

    if not args.prefix and "VAULT_PREFIX" in os.environ:
        args.prefix = os.environ["VAULT_PREFIX"]
    elif not args.prefix:
        args.prefix = ""

    instance_data = None

    if not args.init and not args.update:
        vlt = Vault(vault_stack=args.vaultstack, vault_key=args.key_arn,
                    vault_bucket=args.bucket, vault_iam_id=args.id,
                    vault_iam_secret=args.secret, vault_prefix=args.prefix,
                    vault_region=args.region)
        if args.store:
            if args.overwrite or not vlt.exists(args.store):
                vlt.store(args.store, data)
            elif not args.overwrite:
                parser.error("Will not overwrite '" + args.store +
                             "' without the --overwrite (-w) flag")
        elif args.delete:
            vlt.delete(args.delete)
        elif args.all:
            data = vlt.all()
            if args.outfile and not args.outfile == "-":
                with open(args.outfile, 'w') as outf:
                    outf.write(data)
            else:
                sys.stdout.write(data)
        elif args.recrypt:
            vlt.recrypt(args.recrypt)
            print(args.recrypt + " successfully recrypted")
        elif args.encrypt:
            print(b64encode(vlt.direct_encrypt(args.encrypt)))
        elif args.decrypt:
            print(vlt.direct_decrypt(b64decode(args.decrypt)))
        else:
            data = vlt.lookup(args.lookup)
            if args.outfile and not args.outfile == "-":
                out_dir = os.path.dirname(args.outfile)
                if not out_dir:
                    out_dir = "."
                if not os.path.exists(out_dir):
                    os.makedirs(out_dir)
                with open(args.outfile, 'wb') as outf:
                    outf.write(data)
            else:
                if getattr(sys.stdout, "buffer", None):
                    sys.stdout.buffer.write(data)
                else:
                    sys.stdout.write(data)
    else:
        vlt = Vault(vault_stack=args.vaultstack, vault_key=args.key_arn,
                    vault_bucket=args.bucket, vault_iam_id=args.id,
                    vault_iam_secret=args.secret, vault_prefix=args.prefix,
                    vault_region=args.region)
        if args.init:
            vlt.init()
        elif args.update:
            vlt.update()
