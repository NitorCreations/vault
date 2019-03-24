
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
import boto3
import requests
from base64 import b64decode, b64encode
from requests.exceptions import ConnectionError
from n_vault.vault import Vault

SYS_ENCODING = locale.getpreferredencoding()
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

def is_ec2():
    if sys.platform.startswith("win"):
        import wmi
        systeminfo = wmi.WMI().Win32_ComputerSystem()[0]
        return "EC2" == systeminfo.PrimaryOwnerName
    elif sys.platform.startswith("linux"):
        if os.path.isfile("/sys/hypervisor/uuid"):
            with open("/sys/hypervisor/uuid") as uuid:
                uuid_str = uuid.read()
                return uuid_str.startswith("ec2")
        else:
            return False

def region():
    """ Get default region - the region of the instance if run in an EC2 instance
    """
    # If it is set in the environment variable, use that
    if 'AWS_DEFAULT_REGION' in os.environ:
        return os.environ['AWS_DEFAULT_REGION']
    else:
        # Otherwise it might be configured in AWS credentials
        session = boto3.session.Session()
        if session.region_name:
            return session.region_name
        # If not configured and being called from an ec2 instance, use the
        # region of the instance
        elif is_ec2():
          try:
              response = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document')
              instance_data = json.loads(response.text)
              return instance_data['region']
          except ConnectionError:
              # no-op
              return ""
    return ""

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
    # Try to get region from instance metadata if not otherwise specified
    if not args.region:
        args.region = region()
    if args.region:
        os.environ['AWS_DEFAULT_REGION'] = args.region

    if not args.init and not args.update:
        vlt = Vault(vault_stack=args.vaultstack, vault_key=args.key_arn,
                    vault_bucket=args.bucket, vault_iam_id=args.id,
                    vault_iam_secret=args.secret, vault_prefix=args.prefix)
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
                with open(args.outfile, 'wb') as outf:
                    outf.write(data)
            else:
                if getattr(sys.stdout, "buffer", None):
                    sys.stdout.buffer.write(data)
                else:
                    sys.stdout.write(data)
    else:
        if not args.bucket:
            sts = boto3.client("sts")
            account_id = sts.get_caller_identity()['Account']
            args.bucket = args.vaultstack + "-" + args.region + "-" + account_id
        clf = boto3.client("cloudformation")
        if args.init:
            try:
                clf.describe_stacks(StackName=args.vaultstack)
                print("Vault stack '" + args.vaultstack + "' already initialized")
            except:
                params = {}
                params['ParameterKey'] = "paramBucketName"
                params['ParameterValue'] = args.bucket
                clf.create_stack(StackName=args.vaultstack, TemplateBody=_template(),
                                 Parameters=[params], Capabilities=['CAPABILITY_IAM'])
        elif args.update:
            try:
                stack = clf.describe_stacks(StackName=args.vaultstack)
                deployed_version = None
                ok_to_update = False
                for output in stack['Stacks'][0]['Outputs']:
                    if output['OutputKey'] == 'vaultStackVersion':
                        deployed_version = int(output['OutputValue'])
                        if int(output['OutputValue']) < VAULT_STACK_VERSION:
                            ok_to_update = True
                        break
                if ok_to_update or deployed_version is None:
                    params = {}
                    params['ParameterKey'] = "paramBucketName"
                    params['UsePreviousValue'] = True
                    clf.update_stack(StackName=args.vaultstack, TemplateBody=_template(),
                                     Parameters=[params], Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'])
                else:
                    print("Current stack version %(cur_ver)s does not need update to " \
                          "version %(code_version)s" % {"cur_ver": deployed_version,
                                                        "code_version": VAULT_STACK_VERSION})
            except Exception as e:
                print("Error while updating stack '" + args.vaultstack + "': " + repr(e))
