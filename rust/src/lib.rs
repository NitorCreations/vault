pub mod errors;
mod value;
mod vault;

// Expose `Vault` and `Value` so they can be used as if they were defined here
pub use crate::value::Value;
pub use crate::vault::Vault;

use std::fmt;

use aws_config::SdkConfig;
use aws_sdk_cloudformation::types::Output;
use aws_sdk_cloudformation::Client as CloudFormationClient;
use aws_sdk_s3::types::ObjectIdentifier;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::errors::VaultError;

#[derive(Debug, Clone)]
pub struct CloudFormationParams {
    bucket_name: String,
    key_arn: Option<String>,
}

#[derive(Debug, Clone)]
struct EncryptObject {
    data_key: Vec<u8>,
    aes_gcm_ciphertext: Vec<u8>,
    meta: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    alg: String,
    nonce: String,
}

#[derive(Debug, Clone)]
struct S3DataKeys {
    key: String,
    cipher: String,
    meta: String,
}

impl CloudFormationParams {
    #[must_use]
    pub const fn new(bucket_name: String, key_arn: Option<String>) -> Self {
        Self {
            bucket_name,
            key_arn,
        }
    }

    pub fn from(bucket_name: &str, key_arn: Option<&str>) -> Self {
        Self {
            bucket_name: bucket_name.to_owned(),
            key_arn: key_arn.map(std::borrow::ToOwned::to_owned),
        }
    }

    /// Get `CloudFormation` parameters based on config and stack name
    async fn get_from_stack(config: &SdkConfig, stack: &str) -> Result<Self, VaultError> {
        let describe_stack_output = CloudFormationClient::new(config)
            .describe_stacks()
            .stack_name(stack)
            .send()
            .await?;

        let stack_output = describe_stack_output
            .stacks()
            .iter()
            .next()
            .map(aws_sdk_cloudformation::types::Stack::outputs)
            .ok_or(VaultError::StackOutputsMissingError)?;

        let bucket_name = Self::parse_output_value_from_key("vaultBucketName", stack_output)
            .ok_or(VaultError::BucketNameMissingError)?;

        let key_arn = Self::parse_output_value_from_key("kmsKeyArn", stack_output);

        Ok(Self::new(bucket_name, key_arn))
    }

    fn parse_output_value_from_key(key: &str, out: &[Output]) -> Option<String> {
        out.iter()
            .find(|output| output.output_key() == Some(key))
            .map(|output| output.output_value().unwrap_or_default().to_owned())
    }
}

impl Meta {
    pub fn new(algorithm: &str, nonce: &[u8]) -> Self {
        Self {
            alg: algorithm.to_owned(),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        }
    }

    pub fn aesgcm(nonce: &[u8]) -> Self {
        Self::new("AESGCM", nonce)
    }

    /// Serialize Meta to JSON string.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self)
    }
}

impl S3DataKeys {
    fn new(name: &str) -> Self {
        Self {
            key: format!("{name}.key"),
            cipher: format!("{name}.aesgcm.encrypted"),
            meta: format!("{name}.meta"),
        }
    }

    /// Return key strings as an array for easy iteration.
    fn as_array(&self) -> [&str; 3] {
        [&self.key, &self.cipher, &self.meta]
    }

    /// Convert keys to S3 object identifiers.
    fn to_object_identifiers(&self) -> Result<Vec<ObjectIdentifier>, VaultError> {
        self.as_array()
            .iter()
            .map(|key| {
                ObjectIdentifier::builder()
                    .set_key(Some((*key).to_string()))
                    .build()
                    .map_err(VaultError::from)
            })
            .collect()
    }
}

impl fmt::Display for CloudFormationParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "bucket: {}\nkey: {}",
            self.bucket_name,
            self.key_arn.as_ref().map_or("None", |k| k)
        )
    }
}
