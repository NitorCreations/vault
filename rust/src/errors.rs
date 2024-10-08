use std::io;
use std::string::FromUtf8Error;

use aws_sdk_cloudformation::error::SdkError;
use aws_sdk_cloudformation::operation::create_stack::CreateStackError;
use aws_sdk_cloudformation::operation::describe_stacks::DescribeStacksError;
use aws_sdk_cloudformation::operation::update_stack::UpdateStackError;
use aws_sdk_cloudformation::Error as cloudformationError;
use aws_sdk_kms::operation::decrypt::DecryptError;
use aws_sdk_kms::operation::generate_data_key::GenerateDataKeyError;
use aws_sdk_s3::error::BuildError;
use aws_sdk_s3::operation::delete_object::DeleteObjectError;
use aws_sdk_s3::operation::delete_objects::DeleteObjectsError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::put_object::PutObjectError;
use aws_sdk_sts::operation::get_caller_identity::GetCallerIdentityError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Describe CloudFormation Stack failed")]
    DescribeStackError(#[from] SdkError<DescribeStacksError>),
    #[error("CloudFormation Stack outputs missing")]
    StackOutputsMissingError,
    #[error("Failed to get bucket name from stack")]
    BucketNameMissingError,
    #[error("No KEY_ARN provided, can't encrypt")]
    KeyARNMissingError,
    #[error("Failed to generate KMS Data key")]
    KMSGenerateDataKeyError(#[from] SdkError<GenerateDataKeyError>),
    #[error("Failed to decrypt Ciphertext with KMS")]
    KMSDecryptError(#[from] SdkError<DecryptError>),
    #[error("No Plaintext for generated data key")]
    KMSDataKeyPlainTextMissingError,
    #[error("No ciphertextBlob for generated data key")]
    KMSDataKeyCiphertextBlobMissingError,
    #[error("Invalid length for encryption cipher")]
    InvalidNonceLengthError(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("Invalid length for encryption cipher")]
    NonceDecryptError,
    #[error("String is not valid UTF8")]
    NonUtf8BodyError(#[from] FromUtf8Error),
    #[error("Failed to encrypt ciphertext")]
    CiphertextEncryptionError,
    #[error("Failed to parse meta with serde")]
    EncryptObjectMetaToJsonError(#[from] serde_json::Error),
    #[error("Failed getting object from S3")]
    S3GetObjectError(#[from] SdkError<GetObjectError>),
    #[error("Failed deleting object from S3")]
    S3DeleteObjectError(#[from] SdkError<DeleteObjectError>),
    #[error("Key does not exist in S3")]
    S3DeleteObjectKeyMissingError,
    #[error("Failed getting head-object from S3")]
    S3HeadObjectError(#[from] HeadObjectError),
    #[error("Failed to decrypt S3-object body")]
    S3GetObjectBodyError,
    #[error("Failed putting object to S3")]
    S3PutObjectError(#[from] SdkError<PutObjectError>),
    #[error("Failed to list S3 objects")]
    S3ListObjectsError(#[from] SdkError<ListObjectsV2Error>),
    #[error("Failed to build S3 object")]
    S3BuildObjectError(#[from] BuildError),
    #[error("Failed to delete S3 objects")]
    S3DeleteObjectsError(#[from] SdkError<DeleteObjectsError>),
    #[error("No contents found from S3")]
    S3NoContentsError,
    #[error("Failed getting region")]
    NoRegionError,
    #[error("Failed parsing Nonce from base64")]
    NonceParseError(#[from] base64::DecodeError),
    #[error("Failed to read file: {0}")]
    FileReadError(String, #[source] io::Error),
    #[error("Failed to read from stdin")]
    StdinReadError(#[from] io::Error),
    #[error("Deployed stack version not found in the stack data")]
    StackVersionNotFoundError,
    #[error("CloudFormation error: {0}")]
    CloudFormationError(#[from] Box<cloudformationError>),
    #[error("CloudFormation stack update failed: {0}")]
    UpdateStackError(#[from] SdkError<UpdateStackError>),
    #[error("Account ID missing from caller ID")]
    MissingAccountIdError,
    #[error("Failed to get called ID: {0}")]
    CallerIdError(#[from] SdkError<GetCallerIdentityError>),
    #[error("Failed to create stack: {0}")]
    CreateStackError(#[from] SdkError<CreateStackError>),
}
