use aws_sdk_cloudformation::error::SdkError;
use aws_sdk_cloudformation::operation::describe_stacks::DescribeStacksError;
use aws_sdk_kms::operation::decrypt::DecryptError;
use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyError;
use aws_sdk_s3::operation::delete_object::DeleteObjectError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::put_object::PutObjectError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Describe CloudFormation Stack failed")]
    DescribeStackError(#[from] SdkError<DescribeStacksError>),
    #[error("CloudFormation Stack outputs missing")]
    StackOutputsMissingError,
    #[error("Error getting bucket name from stack")]
    BucketNameMissingError,
    #[error("No KEY_ARN provided, can't encrypt")]
    KeyARNMissingError,
    #[error("Error Generating KMS Data key")]
    KMSGenerateDataKeyError(#[from] SdkError<GenerateDataKeyError>),
    #[error("Error decrypting Ciphertext with KMS")]
    KMSDecryptError(#[from] SdkError<DecryptError>),
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
    S3GetObjectError(#[from] SdkError<GetObjectError>),
    #[error("Failed deleting object from S3")]
    S3DeleteObjectError(#[from] SdkError<DeleteObjectError>),
    #[error("Key not existing in S3")]
    S3DeleteObjectKeyMissingError,
    #[error("Failed getting head-object from S3")]
    S3HeadObjectError(#[from] HeadObjectError),
    #[error("Error decrypting S3-object body")]
    S3GetObjectBodyError,
    #[error("Error putting object to S3")]
    S3PutObjectError(#[from] SdkError<PutObjectError>),
    #[error("Error listing S3 objects")]
    S3ListObjectsError(#[from] SdkError<ListObjectsV2Error>),
    #[error("No contents found from S3")]
    S3NoContentsError,
    #[error("Error getting region")]
    NoRegionError,
    #[error("Error parsing Nonce from base64")]
    NonceParseError(#[from] base64::DecodeError),
}
