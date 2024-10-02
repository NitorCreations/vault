use std::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::{cipher, Aes256};
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aws_config::Region;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Delete;
use aws_sdk_s3::Client as S3Client;
use base64::Engine;
use rand::Rng;
use tokio::try_join;

use crate::errors::VaultError;
use crate::value::Value;
use crate::{CloudFormationParams, EncryptObject, Meta, S3DataKeys};

#[derive(Debug)]
pub struct Vault {
    /// AWS region to use with Vault.
    /// Will fall back to default provider if nothing is specified.
    region: Region,
    cloudformation_params: CloudFormationParams,
    s3: S3Client,
    kms: KmsClient,
}

impl Vault {
    pub async fn new(
        vault_stack: Option<&str>,
        region_opt: Option<&str>,
    ) -> Result<Self, VaultError> {
        let config = aws_config::from_env()
            .region(crate::get_region_provider(region_opt))
            .load()
            .await;

        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let vault_stack_from_env = crate::get_env_variable("VAULT_STACK");
        let vault_bucket_from_env = crate::get_env_variable("VAULT_BUCKET");
        let vault_key_from_env = crate::get_env_variable("VAULT_KEY");

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
            .region(crate::get_region_provider(region_opt))
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
        let meta = Meta::aesgcm(nonce).to_json()?;
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
    pub async fn exists(&self, name: &str) -> Result<bool, VaultError> {
        match self
            .s3
            .head_object()
            .bucket(self.cloudformation_params.bucket_name.clone())
            .key(format!("{name}.key"))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let service_error = e.into_service_error();
                if service_error.is_not_found() {
                    // The object does not exist
                    Ok(false)
                } else {
                    // Propagate other errors like networking or permissions
                    Err(VaultError::S3HeadObjectError(service_error))
                }
            }
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

    /// Return value for the given key name.
    /// If the data is valid UTF-8, it will be returned as a string.
    /// Otherwise, the raw bytes will be returned.
    pub async fn lookup(&self, name: &str) -> Result<Value, VaultError> {
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

        match String::from_utf8(res) {
            Ok(valid_string) => Ok(Value::Utf8(valid_string)),
            Err(from_utf8_error) => Ok(Value::Binary(from_utf8_error.into_bytes())),
        }
    }

    fn create_random_nonce() -> [u8; 12] {
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::thread_rng();
        rng.fill(nonce.as_mut_slice());
        nonce
    }
}

impl fmt::Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "region: {}\n{}", self.region, self.cloudformation_params)
    }
}
