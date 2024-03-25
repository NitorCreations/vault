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
use aws_sdk_kms::Client as kmsClient;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{Delete, ObjectIdentifier};
use aws_sdk_s3::Client as s3Client;
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
    s3: s3Client,
    kms: kmsClient,
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
    pub fn new(bucket_name: String, key_arn: Option<String>) -> CloudFormationParams {
        CloudFormationParams {
            bucket_name,
            key_arn,
        }
    }

    pub fn from(bucket_name: &str, key_arn: Option<&str>) -> CloudFormationParams {
        CloudFormationParams {
            bucket_name: bucket_name.to_owned(),
            key_arn: key_arn.map(|x| x.to_owned()),
        }
    }
}

impl fmt::Display for CloudFormationParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "bucket: {}\nkey: {}",
            self.bucket_name,
            match &self.key_arn {
                None => "None",
                Some(k) => k,
            }
        )
    }
}

impl Meta {
    pub fn new_json(algorithm: &str, nonce: &[u8]) -> serde_json::Result<String> {
        let meta = Meta {
            alg: algorithm.to_owned(),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        };

        serde_json::to_string(&meta)
    }
}

impl S3DataKeys {
    pub fn new(name: &str) -> S3DataKeys {
        S3DataKeys {
            key: format!("{name}.key"),
            cipher: format!("{name}.aesgcm.encrypted"),
            meta: format!("{name}.meta"),
        }
    }

    /// Return key strings as an array for easy iteration.
    pub fn as_array(&self) -> [&str; 3] {
        [&self.key, &self.cipher, &self.meta]
    }

    /// Return keys as S3 object identifiers.
    pub fn as_object_identifiers(&self) -> Vec<ObjectIdentifier> {
        self.as_array()
            .iter()
            .map(|key| {
                ObjectIdentifier::builder()
                    .set_key(Some(key.to_string()))
                    .build()
                    .unwrap_or_else(|_| panic!("Failed to create ObjectIdentifier for '{key}'"))
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
    ) -> Result<Vault, VaultError> {
        let config = aws_config::from_env()
            .region(Self::get_region_provider(region_opt))
            .load()
            .await;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let vault_stack_from_env = Self::get_env_variable("VAULT_STACK");
        let vault_bucket_from_env = Self::get_env_variable("VAULT_BUCKET");
        let vault_key_from_env = Self::get_env_variable("VAULT_KEY");

        let cloudformation_params = match (vault_bucket_from_env, vault_key_from_env) {
            (Some(bucket), Some(key)) => CloudFormationParams::new(bucket, Some(key)),
            (_, _) => {
                let stack_name = vault_stack_from_env
                    .as_deref()
                    .or(vault_stack)
                    .unwrap_or("vault");

                Self::get_cloudformation_params(&config, stack_name).await?
            }
        };

        Ok(Vault {
            region: config.region().unwrap().to_owned(),
            cloudformation_params,
            s3: s3Client::new(&config),
            kms: kmsClient::new(&config),
        })
    }

    pub async fn from_params(
        cloudformation_params: CloudFormationParams,
        region_opt: Option<&str>,
    ) -> Result<Vault, VaultError> {
        let config = aws_config::from_env()
            .region(Self::get_region_provider(region_opt))
            .load()
            .await;
        Ok(Vault {
            region: config.region().ok_or(VaultError::NoRegionError)?.to_owned(),
            cloudformation_params,
            s3: s3Client::new(&config),
            kms: kmsClient::new(&config),
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
                if let Some(key) = object.key() {
                    if key.ends_with(".aesgcm.encrypted") {
                        key.strip_suffix(".aesgcm.encrypted")
                            .map(|stripped| stripped.to_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }

    /// Get CloudFormation stack information
    pub fn stack_info(&self) -> CloudFormationParams {
        self.cloudformation_params.to_owned()
    }

    /// Encrypt data
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptObject, VaultError> {
        let key_dict = self
            .kms
            .generate_data_key()
            .key_id(
                self.cloudformation_params
                    .key_arn
                    .to_owned()
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
        let meta = Meta::new_json("AESGCM", nonce)?;
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
            .bucket(self.cloudformation_params.bucket_name.to_owned())
            .key(&key)
            .send()
            .await?
            .body
            .collect()
            .await
            .map_err(|_| VaultError::S3GetObjectBodyError)
            .map(|bytes| bytes.to_vec())
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
            .bucket(self.cloudformation_params.bucket_name.to_owned())
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
        self.s3
            .delete_objects()
            .bucket(&self.cloudformation_params.bucket_name)
            .delete(
                Delete::builder()
                    .set_objects(Some(keys.as_object_identifiers()))
                    .build()?,
            )
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

    /// Get CloudFormation parameters based on config and stack name
    async fn get_cloudformation_params(
        config: &SdkConfig,
        stack: &str,
    ) -> Result<CloudFormationParams, VaultError> {
        let describe_stack_output = CloudFormationClient::new(config)
            .describe_stacks()
            .stack_name(stack)
            .send()
            .await?;

        let stack_output = describe_stack_output
            .stacks()
            .iter()
            .next()
            .map(|stack| stack.outputs())
            .ok_or(VaultError::StackOutputsMissingError)?;

        let bucket_name = Self::parse_output_value_from_key("vaultBucketName", stack_output)
            .ok_or(VaultError::BucketNameMissingError)?;

        let key_arn = Self::parse_output_value_from_key("kmsKeyArn", stack_output);

        Ok(CloudFormationParams::new(bucket_name, key_arn))
    }

    fn get_region_provider(region_opt: Option<&str>) -> RegionProviderChain {
        RegionProviderChain::first_try(region_opt.map(|r| Region::new(r.to_owned())))
            .or_default_provider()
    }

    fn parse_output_value_from_key(key: &str, out: &[Output]) -> Option<String> {
        out.iter()
            .find(|output| output.output_key() == Some(key))
            .map(|output| output.output_value().unwrap_or_default().to_owned())
    }

    fn create_random_nonce() -> [u8; 12] {
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::thread_rng();
        rng.fill(nonce.as_mut_slice());
        nonce
    }

    /// Return possible env variable value as Option
    fn get_env_variable(name: &str) -> Option<String> {
        env::var(name).ok()
    }
}
