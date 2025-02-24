use std::io;
use std::string::FromUtf8Error;

use aws_sdk_cloudformation::Error as cloudformationError;
use aws_sdk_cloudformation::error::SdkError;
use aws_sdk_cloudformation::operation::create_stack::CreateStackError;
use aws_sdk_cloudformation::operation::delete_stack::DeleteStackError;
use aws_sdk_cloudformation::operation::describe_stacks::DescribeStacksError;
use aws_sdk_cloudformation::operation::list_stacks::ListStacksError;
use aws_sdk_cloudformation::operation::update_stack::UpdateStackError;
use aws_sdk_kms::operation::decrypt::DecryptError;
use aws_sdk_kms::operation::encrypt::EncryptError;
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
    KeyArnMissingError,
    #[error("Failed to generate KMS Data key")]
    KmsGenerateDataKeyError(#[from] SdkError<GenerateDataKeyError>),
    #[error("Failed to decrypt Ciphertext with KMS")]
    KmsDecryptError(#[from] SdkError<DecryptError>),
    #[error("Failed to encrypt data with KMS")]
    KmsEncryptError(#[from] SdkError<EncryptError>),
    #[error("No Plaintext for generated data key")]
    KmsDataKeyPlainTextMissingError,
    #[error("No ciphertextBlob for generated data key")]
    KmsDataKeyCiphertextBlobMissingError,
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
    #[error("Key does not exist in S3: '{name}'")]
    S3DeleteObjectKeyMissingError { name: String },
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
    #[error("Failed to get stack ID for new vault stack")]
    MissingStackIdError,
    #[error("Failed to get stack status for vault stack")]
    MissingStackStatusError,
    #[error("Deprecated encryption method for secret. Secret needs to be re-encrypted!")]
    DeprecatedEncryptionError,
    #[error("Key does not exist in S3")]
    KeyDoesNotExistError,
    #[error("Failed to list stacks: {0}")]
    ListVaultStacksError(#[from] SdkError<ListStacksError>),
    #[error("Failed to delete stack: {0}")]
    DeleteVaultStackError(#[from] SdkError<DeleteStackError>),
}
