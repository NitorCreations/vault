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

from builtins import object
import os
from base64 import b64decode, b64encode
import json
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.backends import default_backend
from threadlocal_aws import session, region
from threadlocal_aws.clients import s3, kms, cloudformation, sts
from threadlocal_aws.resources import s3 as s3_resource

VAULT_STACK_VERSION = 22
TEMPLATE_STRING = """{
  "Parameters": {
    "paramBucketName": {
      "Default": "nitor-core-vault",
      "Type": "String",
      "Description": "Name of the vault bucket"
    }
  },
  "Resources": {
    "resourceDecryptRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Path": "/",
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": ["ec2.amazonaws.com"]
              }
            }
          ]
        }
      }
    },
    "resourceEncryptRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Path": "/",
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": ["ec2.amazonaws.com"]
              }
            }
          ]
        }
      }
    },
    "resourceLambdaRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "Path": "/",
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
              }
            }
          ]
        },
        "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
      }
    },    
    "kmsKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Id": "key-default-2",
          "Statement": [
            {
              "Action": [
                "kms:*"
              ],
              "Principal": {
                "AWS": {
                  "Fn::Join": [
                    "",
                    [
                      "arn:aws:iam::",
                      {
                        "Ref": "AWS::AccountId"
                      },
                      ":root"
                    ]
                  ]
                }
              },
              "Resource": "*",
              "Effect": "Allow",
              "Sid": "allowAdministration"
            }
          ]
        },
        "Description": "Key for encrypting / decrypting secrets"
      }
    },
    "vaultBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": {
          "Ref": "paramBucketName"
        }
      }
    },
    "iamPolicyEncrypt": {
      "Type": "AWS::IAM::ManagedPolicy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject"
              ],
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "paramBucketName"
                    },
                    "/*"
                  ]
                ]
              },
              "Effect": "Allow",
              "Sid": "putVaultItems"
            },
            {
              "Action": [
                "s3:ListBucket"
              ],
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "paramBucketName"
                    }
                  ]
                ]
              },
              "Effect": "Allow",
              "Sid": "listVault"
            },
            {
              "Action": [
                "cloudformation:DescribeStacks"
              ],
              "Resource": {
                "Fn::Sub": "arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*"
              },
              "Effect": "Allow",
              "Sid": "describeVault"
            },
            {
              "Action": [
                "kms:Decrypt",
                "kms:Encrypt",
                "kms:GenerateDataKey"
              ],
              "Resource": {
                "Fn::GetAtt": [
                  "kmsKey",
                  "Arn"
                ]
              },
              "Effect": "Allow",
              "Sid": "allowEncrypt"
            },
            {
              "Sid": "InvokeLambdaPermission",
              "Effect": "Allow",
              "Action": [
                  "lambda:InvokeFunction"
              ],
              "Resource": {"Fn::GetAtt": ["lambdaDecrypter", "Arn"]}
            }
          ]
        },
        "Description": "Policy to allow encrypting and decrypting vault secrets",
        "Roles": [
          {
            "Ref": "resourceEncryptRole"
          }
        ]
      }
    },
    "iamPolicyDecrypt": {
      "Type": "AWS::IAM::ManagedPolicy",
      "Properties": {
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Action": [
                "s3:GetObject"
              ],
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "paramBucketName"
                    },
                    "/*"
                  ]
                ]
              },
              "Effect": "Allow",
              "Sid": "getVaultItems"
            },
            {
              "Action": [
                "s3:ListBucket"
              ],
              "Resource": {
                "Fn::Join": [
                  "",
                  [
                    "arn:aws:s3:::",
                    {
                      "Ref": "paramBucketName"
                    }
                  ]
                ]
              },
              "Effect": "Allow",
              "Sid": "listVault"
            },
            {
              "Action": [
                "cloudformation:DescribeStacks"
              ],
              "Resource": {
                "Fn::Sub": "arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${AWS::StackName}/*"
              },
              "Effect": "Allow",
              "Sid": "describeVault"
            },
            {
              "Action": [
                "kms:Decrypt"
              ],
              "Resource": {
                "Fn::GetAtt": [
                  "kmsKey",
                  "Arn"
                ]
              },
              "Effect": "Allow",
              "Sid": "allowDecrypt"
            },
            {
              "Sid": "InvokeLambdaPermission",
              "Effect": "Allow",
              "Action": [
                  "lambda:InvokeFunction"
              ],
              "Resource": {"Fn::GetAtt": ["lambdaDecrypter", "Arn"]}
            }
          ]
        },
        "Description": "Policy to allow decrypting vault secrets",
        "Roles": [
          {
            "Ref": "resourceDecryptRole"
          },
          {
            "Ref": "resourceLambdaRole"
          }
        ]
      }
    },
    "lambdaDecrypter": {
      "Type": "AWS::Lambda::Function",
      "Properties": {
        "Description": { "Fn::Sub": "Nitor Vault ${AWS::StackName} Decrypter"},
        "Handler": "index.handler",
        "MemorySize": 128,
        "Runtime": "python2.7",
        "Timeout": 300,
        "Role": {"Fn::GetAtt": ["resourceLambdaRole", "Arn"]},
        "FunctionName": {"Fn::Sub": "${AWS::StackName}-decrypter"},
        "Code": {
          "ZipFile" : { "Fn::Join" : ["\\n", [
            "import json",
            "import logging",
            "import boto3",
            "import base64",
            "from botocore.vendored import requests",
            "log = logging.getLogger()",
            "log.setLevel(logging.INFO)",
            "kms = boto3.client('kms')",
            "SUCCESS = 'SUCCESS'",
            "FAILED = 'FAILED'",
            "def handler(event, context):",
            "  ciphertext = event['ResourceProperties']['Ciphertext']",
            "  responseData = {}",
            "  try:",
            "    responseData['Plaintext'] = kms.decrypt(CiphertextBlob=base64.b64decode(ciphertext)).get('Plaintext')",
            "    log.info('Decrypt successful!')",
            "    send(event, context, SUCCESS, responseData, event['LogicalResourceId'])",
            "  except Exception as e:",
            "    error_msg = 'Failed to decrypt: ' + repr(e)",
            "    log.error(error_msg)",
            "    send(event, context, FAILED, responseData, event['LogicalResourceId'])",
            "    raise Exception(error_msg)",
            "",
            "def send(event, context, responseStatus, responseData, physicalResourceId):",
            "  responseUrl = event['ResponseURL']",
            "  responseBody = {}",
            "  responseBody['Status'] = responseStatus",
            "  responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name",
            "  responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name",
            "  responseBody['StackId'] = event['StackId']",
            "  responseBody['RequestId'] = event['RequestId']",
            "  responseBody['LogicalResourceId'] = event['LogicalResourceId']",
            "  responseBody['Data'] = responseData",
            "  json_responseBody = json.dumps(responseBody)",
            "  headers = {",
            "    'content-type' : '',",
            "    'content-length' : str(len(json_responseBody))",
            "  }",
            "  try:",
            "    response = requests.put(responseUrl,",
            "                            data=json_responseBody,",
            "                            headers=headers)",
            "  except Exception as e:",
            "    log.warning('send(..) failed executing requests.put(..): ' + repr(e))"
          ]]}
        }
      }
    }
  },
  "Outputs": {
    "vaultBucketName": {
      "Description": "Vault Bucket",
      "Value": {
        "Ref": "vaultBucket"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "vaultBucketName"]]
        }
      }
    },
    "kmsKeyArn": {
      "Description": "KMS key Arn",
      "Value": {
        "Fn::GetAtt": [
          "kmsKey",
          "Arn"
        ]
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "kmsKeyArn"]]
        }
      }
    },
    "decryptRole": {
      "Description": "The role for decrypting",
      "Value": {
        "Ref": "resourceDecryptRole"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "decryptRole"]]
        }
      }
    },
    "encryptRole": {
      "Description": "The role for encrypting",
      "Value": {
        "Ref": "resourceEncryptRole"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "encryptRole"]]
        }
      }
    },
    "decryptPolicy": {
      "Description": "The policy for decrypting",
      "Value": {
        "Ref": "iamPolicyDecrypt"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "decryptPolicy"]]
        }
      }
    },
    "encryptPolicy": {
      "Description": "The policy for decrypting",
      "Value": {
        "Ref": "iamPolicyEncrypt"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "encryptPolicy"]]
        }
      }
    },
    "vaultStackVersion": {
      "Description": "The version of the currently deployed vault stack template",
      "Value": "%(version)s",
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "vaultStackVersion"]]
        }
      }
    },
    "lambdaDecrypterArn": {
      "Description": "Decrypter Lambda function ARN",
      "Value": {
        "Fn::Sub": "${lambdaDecrypter.Arn}"
      },
      "Export": {
        "Name": {
          "Fn::Join": [":", [{"Ref": "AWS::StackName"}, "lambdaDecrypterArn"]]
        }
      }
    }        
  }
}""" % {"version": VAULT_STACK_VERSION}

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

class Vault(object):
    _session = session()
    _kms = ""
    _prefix = ""
    _vault_key = ""
    _vault_bucket = ""
    _stack = ""
    def __init__(self, vault_stack="", vault_key="", vault_bucket="",
                 vault_iam_id="", vault_iam_secret="", vault_prefix="",
                 vault_region=None):
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
        # Either use given vault iam credentials or assume that the environent has
        # some usable credentials (either through env vars or instance profile)
        if vault_iam_id and vault_iam_secret:
            self._session = session(aws_access_key_id=vault_iam_id,
                                    aws_secret_access_key=vault_iam_secret)
        # Either use given vault kms key and/or vault bucket or look them up from a
        # cloudformation stack
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
            stack_info = self._get_cf_params()
            if not self._vault_key and 'key_arn' in stack_info:
                self._vault_key = stack_info['key_arn']
            if not self._vault_bucket and 'bucket_name' in stack_info:
                self._vault_bucket = stack_info['bucket_name']
        if not self._vault_bucket:
            account_id = sts(session=self._session, region=self._region).get_caller_identity()['Account']
            self._vault_bucket = self._stack + "-" + self._region + "-" + account_id

    def _encrypt(self, data):
        ret = {}
        key_dict = kms(session=self._session, region=self._region).generate_data_key(KeyId=self._vault_key,
                                               KeySpec="AES_256")
        data_key = key_dict['Plaintext']
        ret['datakey'] = key_dict['CiphertextBlob']
        aesgcm_cipher = AESGCM(data_key)
        nonce = os.urandom(12)
        meta = json.dumps({"alg": "AESGCM", "nonce": b64encode(nonce).decode()}, separators=(',',':'), sort_keys=True)
        ret['aes-gcm-ciphertext'] = aesgcm_cipher.encrypt(nonce, data, _to_bytes(meta))
        cipher = _get_cipher(data_key)
        encryptor = cipher.encryptor()
        ret['ciphertext'] = encryptor.update(data) + encryptor.finalize()
        ret['meta'] = meta
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
        stack = cloudformation(session=self._session, region=self._region).describe_stacks(StackName=self._stack)
        ret = {}
        if 'Stacks' in stack and stack['Stacks']:
            for output in  stack['Stacks'][0]['Outputs']:
                if output['OutputKey'] == 'vaultBucketName':
                    ret['bucket_name'] = output['OutputValue']
                if output['OutputKey'] == 'kmsKeyArn':
                    ret['key_arn'] = output['OutputValue']
                if output['OutputKey'] == 'vaultStackVersion':
                    ret['deployed_version'] = int(output['OutputValue'])
        return ret

    def store(self, name, data):
        encrypted = self._encrypt(data)
        s3(session=self._session, region=self._region).put_object(Bucket=self._vault_bucket, Body=encrypted['datakey'],
                            ACL='private', Key=self._prefix + name + '.key')
        s3(session=self._session, region=self._region).put_object(Bucket=self._vault_bucket, Body=encrypted['ciphertext'],
                            ACL='private', Key=self._prefix + name + '.encrypted')
        s3(session=self._session, region=self._region).put_object(Bucket=self._vault_bucket, Body=encrypted['aes-gcm-ciphertext'],
                            ACL='private', Key=self._prefix + name + '.aesgcm.encrypted')
        s3(session=self._session, region=self._region).put_object(Bucket=self._vault_bucket, Body=encrypted['meta'],
                            ACL='private', Key=self._prefix + name + '.meta')
        return True

    def lookup(self, name):
        datakey = bytes(s3(session=self._session, region=self._region).get_object(Bucket=self._vault_bucket,
                                            Key=self._prefix + name + '.key')['Body'].read())
        try:
            meta_add = bytes(s3(session=self._session, region=self._region).get_object(Bucket=self._vault_bucket,
                                                 Key=self._prefix + name + '.meta')['Body'].read())
            ciphertext = bytes(s3(session=self._session, region=self._region).get_object(Bucket=self._vault_bucket,
                                                   Key=self._prefix + name + '.aesgcm.encrypted')['Body'].read())
            meta = json.loads(_to_str(meta_add))
            return AESGCM(self.direct_decrypt(datakey)).decrypt(b64decode(meta['nonce']), ciphertext, meta_add)
        except ClientError as e:
            if e.response['Error']['Code'] == "404" or e.response['Error']['Code'] == 'NoSuchKey':
                ciphertext = bytes(s3(session=self._session, region=self._region).get_object(Bucket=self._vault_bucket,
                                                       Key=self._prefix + name + '.encrypted')['Body'].read())
                return self._decrypt(datakey, ciphertext)
            else:
                raise

    def recrypt(self, name):
        data = self.lookup(name)
        self.store(name, data)

    def exists(self, name):
        try:
            s3(session=self._session, region=self._region).head_object(Bucket=self._vault_bucket,
                                 Key=self._prefix + name + '.key')
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == "404":
                return False
            else:
                raise

    def delete(self, name):
        s3(session=self._session, region=self._region).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + '.key')
        s3(session=self._session, region=self._region).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + '.encrypted')
        try:
            s3(session=self._session, region=self._region).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + '.aesgcm.encrypted')
            s3(session=self._session, region=self._region).delete_object(Bucket=self._vault_bucket, Key=self._prefix + name + '.meta')
        except ClientError as e:
            if e.response['Error']['Code'] == "404" or e.response['Error']['Code'] == 'NoSuchKey':
                pass
            else:
                raise

    def all(self):
        ret = ""
        for item in self.list_all():
            ret = ret + item + os.linesep
        return ret

    def list_all(self):
        s3bucket = s3_resource(session=self._session, region=self._region).Bucket(self._vault_bucket)
        ret = []
        for next_object in s3bucket.objects.filter(Prefix=self._prefix):
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
        return kms(session=self._session, region=self._region).encrypt(KeyId=self._vault_key, Plaintext=data)['CiphertextBlob']

    def direct_decrypt(self, encrypted_data):
        return kms(session=self._session, region=self._region).decrypt(CiphertextBlob=encrypted_data)['Plaintext']

    def init(self):
        try:
            cloudformation(session=self._session, region=self._region).describe_stacks(StackName=self._stack)
            print("Vault stack '" + self._stack + "' already initialized")
        except:
            params = {}
            params['ParameterKey'] = "paramBucketName"
            params['ParameterValue'] = self._bucket
            cloudformation(session=self._session, region=self._region).create_stack(StackName=self._stack, TemplateBody=_template(),
                             Parameters=[params], Capabilities=['CAPABILITY_IAM'])

    def update(self):
        try:
            stack = cloudformation(session=self._session, region=self._region).describe_stacks(StackName=self._stack)
            deployed_version = None
            ok_to_update = False
            params = self._get_cf_params()
            if 'deployed_version' in params:
                deployed_version = params['deployed_version']
            if deployed_version < VAULT_STACK_VERSION:
                ok_to_update = True
            if ok_to_update or deployed_version is None:
                params = {}
                params['ParameterKey'] = "paramBucketName"
                params['UsePreviousValue'] = True
                cloudformation(session=self._session, region=self._region).update_stack(StackName=self._stack, TemplateBody=_template(),
                                 Parameters=[params],
                                 Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])
            else:
                print("Current stack version %(cur_ver)s does not need update to " \
                        "version %(code_version)s" % {"cur_ver": deployed_version,
                                                    "code_version": VAULT_STACK_VERSION})
        except Exception as e:
            print("Error while updating stack '" + self._stack + "': " + repr(e))

STATIC_IV = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 & 0xFF, int(1337 / 256) & 0xFF, int(1337 % 256) & 0xFF])
def _get_cipher(key):
    backend = default_backend()
    return Cipher(AES(key), CTR(bytes(STATIC_IV)), backend=backend)
