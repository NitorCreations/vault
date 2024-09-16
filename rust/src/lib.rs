pub mod errors;

use std::env;
use std::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::{cipher, Aes256};
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aws_config::meta::region::RegionProviderChain;
use aws_config::{Region, SdkConfig};
use aws_sdk_cloudformation::types::Output;
use aws_sdk_cloudformation::Client as CloudFormationClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::Client as S3Client;
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::try_join;

use crate::errors::VaultError;

#[derive(Debug)]
pub struct Vault {
    /// AWS region to use with Vault.
    /// Will fall back to default provider if nothing is specified.
    region: Region,
    cloudformation_params: CloudFormationParams,
    s3: S3Client,
    kms: KmsClient,
}

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

impl Meta {
    pub fn new(algorithm: &str, nonce: &[u8]) -> Self {
        Self {
            alg: algorithm.to_owned(),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        }
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

impl fmt::Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "region: {}\n{}", self.region, self.cloudformation_params)
    }
}

impl Vault {
    pub async fn new(
        vault_stack: Option<&str>,
        region_opt: Option<&str>,
    ) -> Result<Self, VaultError> {
        let config = aws_config::from_env()
            .region(get_region_provider(region_opt))
            .load()
            .await;

        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let vault_stack_from_env = get_env_variable("VAULT_STACK");
        let vault_bucket_from_env = get_env_variable("VAULT_BUCKET");
        let vault_key_from_env = get_env_variable("VAULT_KEY");

        let cloudformation_params =
            if let (Some(bucket), Some(key)) = (vault_bucket_from_env, vault_key_from_env) {
                CloudFormationParams::new(bucket, Some(key))
            } else {
                let stack_name = vault_stack_from_env
                    .as_deref()
                    .or(vault_stack)
                    .unwrap_or("vault");

                CloudFormationParams::get_from_stack(&config, stack_name).await?
            };

        Ok(Self {
            region,
            cloudformation_params,
            s3: S3Client::new(&config),
            kms: KmsClient::new(&config),
        })
    }

    pub async fn from_cli_params(
        bucket: &str,
        key_arn: Option<&str>,
        region_opt: Option<&str>,
    ) -> Result<Self, VaultError> {
        Self::from_params(CloudFormationParams::from(bucket, key_arn), region_opt).await
    }

    pub async fn from_params(
        cloudformation_params: CloudFormationParams,
        region_opt: Option<&str>,
    ) -> Result<Self, VaultError> {
        let config = aws_config::from_env()
            .region(get_region_provider(region_opt))
            .load()
            .await;
        Ok(Self {
            region: config.region().ok_or(VaultError::NoRegionError)?.to_owned(),
            cloudformation_params,
            s3: S3Client::new(&config),
            kms: KmsClient::new(&config),
        })
    }

    /// Get all available secrets
    pub async fn all(&self) -> Result<Vec<String>, VaultError> {
        let output = self
            .s3
            .list_objects_v2()
            .bucket(&self.cloudformation_params.bucket_name)
            .send()
            .await?;
        Ok(output
            .contents()
            .iter()
            .filter_map(|object| -> Option<String> {
                object.key().and_then(|key| {
                    if key.ends_with(".aesgcm.encrypted") {
                        key.strip_suffix(".aesgcm.encrypted")
                            .map(std::borrow::ToOwned::to_owned)
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>())
    }

    /// Get `CloudFormation` stack information
    #[must_use]
    pub fn stack_info(&self) -> CloudFormationParams {
        self.cloudformation_params.clone()
    }

    /// Encrypt data
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptObject, VaultError> {
        let key_dict = self
            .kms
            .generate_data_key()
            .key_id(
                self.cloudformation_params
                    .key_arn
                    .clone()
                    .ok_or(VaultError::KeyARNMissingError)?,
            )
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await?;

        let plaintext = key_dict
            .plaintext()
            .ok_or(VaultError::KMSDataKeyPlainTextMissingError)?;

        let aesgcm_cipher: AesGcm<Aes256, cipher::typenum::U12> =
            AesGcm::new_from_slice(plaintext.as_ref())?;
        let nonce = Self::create_random_nonce();
        let nonce = Nonce::from_slice(nonce.as_slice());
        let meta = Meta::new("AESGCM", nonce).to_json()?;
        let aes_gcm_ciphertext = aesgcm_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: meta.as_bytes(),
                },
            )
            .map_err(|_| VaultError::CiphertextEncryptionError)?;

        let data_key = key_dict
            .ciphertext_blob()
            .ok_or(VaultError::CiphertextEncryptionError)?
            .to_owned()
            .into_inner();

        Ok(EncryptObject {
            data_key,
            aes_gcm_ciphertext,
            meta,
        })
    }

    /// Get S3 Object data for given key as a vec of bytes
    async fn get_s3_object(&self, key: String) -> Result<Vec<u8>, VaultError> {
        self.s3
            .get_object()
            .bucket(self.cloudformation_params.bucket_name.clone())
            .key(&key)
            .send()
            .await?
            .body
            .collect()
            .await
            .map_err(|_| VaultError::S3GetObjectBodyError)
            .map(aws_sdk_s3::primitives::AggregatedBytes::to_vec)
    }

    /// Get decrypted data
    async fn direct_decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.kms
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_data))
            .send()
            .await?
            .plaintext()
            .map(|blob| blob.to_owned().into_inner())
            .ok_or(VaultError::KMSDataKeyPlainTextMissingError)
    }

    /// Send PUT request with the given byte data
    async fn put_s3_object(
        &self,
        body: ByteStream,
        key: String,
    ) -> Result<PutObjectOutput, VaultError> {
        Ok(self
            .s3
            .put_object()
            .bucket(&self.cloudformation_params.bucket_name)
            .key(key)
            .acl(aws_sdk_s3::types::ObjectCannedAcl::Private)
            .body(body)
            .send()
            .await?)
    }

    /// Check if key already exists in bucket
    // TODO: somewhat bad implementation, can fail for other reasons as well?
    pub async fn exists(&self, name: &str) -> Result<bool, VaultError> {
        if let Err(e) = self
            .s3
            .head_object()
            .bucket(self.cloudformation_params.bucket_name.clone())
            .key(format!("{name}.key"))
            .send()
            .await
        {
            let service_error = e.into_service_error();
            if service_error.is_not_found() {
                Ok(false)
            } else {
                Err(VaultError::S3HeadObjectError(service_error))
            }
        } else {
            Ok(true)
        }
    }

    /// Store encrypted data in S3
    pub async fn store(&self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        let encrypted = self.encrypt(data).await?;
        let first = self.put_s3_object(
            ByteStream::from(encrypted.aes_gcm_ciphertext),
            format!("{name}.aesgcm.encrypted"),
        );
        let second =
            self.put_s3_object(ByteStream::from(encrypted.data_key), format!("{name}.key"));
        let third = self.put_s3_object(
            ByteStream::from(encrypted.meta.into_bytes()),
            format!("{name}.meta"),
        );
        try_join!(first, second, third)?;

        Ok(())
    }

    /// Delete data in S3 for given key
    pub async fn delete(&self, name: &str) -> Result<(), VaultError> {
        if !self.exists(name).await? {
            return Err(VaultError::S3DeleteObjectKeyMissingError);
        }

        let keys = S3DataKeys::new(name);
        let identifiers = keys.to_object_identifiers()?;
        self.s3
            .delete_objects()
            .bucket(&self.cloudformation_params.bucket_name)
            .delete(Delete::builder().set_objects(Some(identifiers)).build()?)
            .send()
            .await?;

        Ok(())
    }

    /// Return value for given key name
    pub async fn lookup(&self, name: &str) -> Result<String, VaultError> {
        let keys = S3DataKeys::new(name);
        let data_key = self.get_s3_object(keys.key);
        let cipher_text = self.get_s3_object(keys.cipher);
        let meta_add = self.get_s3_object(keys.meta);
        let (data_key, cipher_text, meta_add) = try_join!(data_key, cipher_text, meta_add)?;
        let meta: Meta = serde_json::from_slice(&meta_add)?;
        let cipher: AesGcm<Aes256, cipher::typenum::U12> =
            AesGcm::new_from_slice(self.direct_decrypt(&data_key).await?.as_slice())?;
        let nonce = base64::engine::general_purpose::STANDARD.decode(meta.nonce)?;
        let nonce = Nonce::from_slice(nonce.as_slice());
        let res = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &cipher_text,
                    aad: &meta_add,
                },
            )
            .map_err(|_| VaultError::NonceDecryptError)?;
        Ok(String::from_utf8(res)?)
    }

    fn create_random_nonce() -> [u8; 12] {
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::thread_rng();
        rng.fill(nonce.as_mut_slice());
        nonce
    }
}

fn get_region_provider(region_opt: Option<&str>) -> RegionProviderChain {
    RegionProviderChain::first_try(region_opt.map(|r| Region::new(r.to_owned())))
        .or_default_provider()
}

/// Return possible env variable value as Option
fn get_env_variable(name: &str) -> Option<String> {
    env::var(name).ok()
}
