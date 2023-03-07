use std::string::FromUtf8Error;

use aws_sdk_cloudformation::types::SdkError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Describe CloudFormation Stack failed")]
    DescribeStackError(#[from] SdkError<aws_sdk_cloudformation::error::DescribeStacksError>),
    #[error("CloudFormation Stack outputs missing")]
    StackOutputsMissingError,
    #[error("Error getting bucket name from stack")]
    BucketNameMissingError,
    #[error("No KEY_ARN provided, can't encrypt")]
    KeyARNMissingError,
    #[error("Error Generating KMS Data key")]
    KMSGenerateDataKeyError(#[from] SdkError<aws_sdk_kms::error::GenerateDataKeyError>),
    #[error("Error decrypting Ciphertext with KMS")]
    KMSDecryptError(#[from] SdkError<aws_sdk_kms::error::DecryptError>),
    #[error("No Plaintext for generated datakey")]
    KMSDataKeyPlainTextMissingError,
    #[error("No ciphertextBlob for generated datakey")]
    KMSDataKeyCiphertextBlobMissingError,
    #[error("Invalid length for encryption cipher")]
    InvalidNonceLengthError(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("Invalid length for encryption cipher")]
    NonceDecryptError,
    #[error("Error, string not valid UTF8")]
    NonUtf8BodyError(#[from] FromUtf8Error),
    #[error("Error encrypting ciphertext")]
    CiphertextEncryptionError,
    #[error("Error parsing meta with serde")]
    EncryptObjectMetaToJsonError(#[from] serde_json::Error),
    #[error("Failed getting object from S3")]
    S3GetObjectError(#[from] SdkError<aws_sdk_s3::error::GetObjectError>),
    #[error("Error decrypting S3-object body")]
    S3GetObjectBodyError,
    #[error("Error putting object to S3")]
    S3PutObjectError(#[from] SdkError<aws_sdk_s3::error::PutObjectError>),
    #[error("Error listing S3 objects")]
    S3ListObjectsError(#[from] SdkError<aws_sdk_s3::error::ListObjectsV2Error>),
    #[error("No contents found from S3")]
    S3NoContentsError,
    #[error("Error getting region")]
    NoRegionError,
    #[error("Error parsing Nonce from base64")]
    NonceParseError(#[from] base64::DecodeError),
}
