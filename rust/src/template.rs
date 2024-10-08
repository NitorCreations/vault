use std::sync::LazyLock;

pub const VAULT_STACK_VERSION: u32 = 25;

static TEMPLATE_STRING: LazyLock<String> = LazyLock::new(|| {
    let raw_template = r#"
{
  "AWSTemplateFormatVersion" : "2010-09-09",
  "Description": "Nitor Vault stack",
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
                "Service": [
                  "ec2.amazonaws.com"
                ]
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
                "Service": [
                  "ec2.amazonaws.com"
                ]
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
                "Service": [
                  "lambda.amazonaws.com",
                  "edgelambda.amazonaws.com"
                ]
              }
            }
          ]
        },
        "ManagedPolicyArns": [
          "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        ]
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
              "Resource": {
                "Fn::GetAtt": [
                  "lambdaDecrypter",
                  "Arn"
                ]
              }
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
              "Resource": {
                "Fn::GetAtt": [
                  "lambdaDecrypter",
                  "Arn"
                ]
              }
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
        "Description": {
          "Fn::Sub": "Nitor Vault ${AWS::StackName} Decrypter"
        },
        "Handler": "index.handler",
        "MemorySize": 128,
        "Runtime": "python3.8",
        "Timeout": 300,
        "Role": {
          "Fn::GetAtt": [
            "resourceLambdaRole",
            "Arn"
          ]
        },
        "FunctionName": {
          "Fn::Sub": "${AWS::StackName}-decrypter"
        },
        "Code": {
          "ZipFile": {
            "Fn::Join": [
              "\n",
              [
                "import json",
                "import logging",
                "import boto3",
                "import base64",
                "import cfnresponse",
                "log = logging.getLogger()",
                "log.setLevel(logging.INFO)",
                "kms = boto3.client('kms')",
                "SUCCESS = 'SUCCESS'",
                "FAILED = 'FAILED'",
                "def handler(event, context):",
                "  ciphertext = event['ResourceProperties']['Ciphertext']",
                "  responseData = {}",
                "  try:",
                "    responseData['Plaintext'] = kms.decrypt(CiphertextBlob=base64.b64decode(ciphertext)).get('Plaintext').decode()",
                "    log.info('Decrypt successful!')",
                "    cfnresponse.send(event, context, SUCCESS, responseData, event['LogicalResourceId'])",
                "  except Exception as e:",
                "    error_msg = 'Failed to decrypt: ' + repr(e)",
                "    log.error(error_msg)",
                "    cfnresponse.send(event, context, FAILED, responseData, event['LogicalResourceId'])",
                "    raise Exception(error_msg)"
              ]
            ]
          }
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "vaultBucketName"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "kmsKeyArn"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "decryptRole"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "encryptRole"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "decryptPolicy"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "encryptPolicy"
            ]
          ]
        }
      }
    },
    "vaultStackVersion": {
      "Description": "The version of the currently deployed vault stack template",
      "Value": "{VAULT_STACK_VERSION}",
      "Export": {
        "Name": {
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "vaultStackVersion"
            ]
          ]
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
          "Fn::Join": [
            ":",
            [
              {
                "Ref": "AWS::StackName"
              },
              "lambdaDecrypterArn"
            ]
          ]
        }
      }
    }
  }
}"#;
    raw_template.replace(
        "{VAULT_STACK_VERSION}",
        VAULT_STACK_VERSION.to_string().as_str(),
    )
});

/// Workaround for accessing string inside `LazyLock`.
pub fn template() -> &'static str {
    &TEMPLATE_STRING
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{BufWriter, Write};

    #[test]
    fn test_write_template_to_file() {
        // Write Cloudformation template JSON to file.
        // This way it can be easily compared with the JSON from the Python vault.
        // ```
        // uv run python -c "from n_vault.template import TEMPLATE_STRING; print(TEMPLATE_STRING)" > template.json
        // diff -y template.json ../python/template.json
        // ```
        let file = std::fs::File::create("template.json").expect("Unable to create template file");
        let mut writer = BufWriter::new(file);
        writer
            .write_all(template().as_bytes())
            .expect("Unable to write data");
        writer
            .write_all("\n".as_ref())
            .expect("Unable to write data");

        writer.flush().expect("Unable to flush data");
    }
}
