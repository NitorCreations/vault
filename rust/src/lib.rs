use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::{cipher, Aes256};
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aws_config::meta::region::RegionProviderChain;
use aws_config::SdkConfig;
use aws_sdk_cloudformation::types::Output;
use aws_sdk_cloudformation::Client as CloudFormationClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as kmsClient;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as s3Client;
use base64::{engine::general_purpose, Engine as _};
use errors::VaultError;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use tokio::try_join;

pub mod errors;

#[derive(Debug)]
pub struct Vault {
    /// AWS region to use with Vault. Will fallback to default provider if nothing is specified.
    region: Region,
    cloudformation_params: CloudFormationParams,
    s3: s3Client,
    kms: kmsClient,
}

#[derive(Debug, Clone)]
pub struct CloudFormationParams {
    bucket_name: String,
    key_arn: Option<String>,
    // deployed_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    alg: String,
    nonce: String,
}

#[derive(Debug)]
struct EncryptObject {
    data_key: Vec<u8>,
    aes_gcm_ciphertext: Vec<u8>,
    meta: String,
}

impl CloudFormationParams {
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
                None => "None".to_string(),
                Some(k) => k.to_string(),
            }
        )
    }
}

impl Vault {
    pub async fn new(
        vault_stack: Option<&str>,
        region_opt: Option<&str>,
    ) -> Result<Vault, VaultError> {
        let config = aws_config::from_env()
            .region(get_region_provider(region_opt))
            .load()
            .await;
        let cloudformation_params =
            get_cloudformation_params(&config, vault_stack.unwrap_or("vault")).await?;
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
            .region(get_region_provider(region_opt))
            .load()
            .await;
        Ok(Vault {
            region: config.region().ok_or(VaultError::NoRegionError)?.to_owned(),
            cloudformation_params,
            s3: s3Client::new(&config),
            kms: kmsClient::new(&config),
        })
    }

    /// Print debug information: region, CloudFormation parameters and S3 client.
    pub fn test(&self) {
        println!(
            "region: {}\nvault_stack: {:#?}\ns3: {:#?}",
            self.region, self.cloudformation_params, self.s3
        );
    }

    /// Get all available secrets
    pub async fn all(&self) -> Result<Vec<String>, VaultError> {
        let output = self
            .s3
            .list_objects_v2()
            .bucket(&self.cloudformation_params.bucket_name)
            .send()
            .await?;
        output
            .contents()
            .map(|objects| {
                objects
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
                    .collect()
            })
            .ok_or(VaultError::S3NoContentsError)
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
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::thread_rng();
        rng.fill(nonce.as_mut_slice());
        let nonce = Nonce::from_slice(nonce.as_slice());

        let meta = serde_json::to_string(&Meta {
            alg: "AESGCM".to_owned(),
            nonce: general_purpose::STANDARD.encode(nonce),
        })?;

        let aes_gcm_ciphertext = aesgcm_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: meta.as_bytes(),
                },
            )
            .map_err(|_| VaultError::CiphertextEncryptionError)?;
        Ok(EncryptObject {
            data_key: key_dict
                .ciphertext_blob()
                .ok_or(VaultError::CiphertextEncryptionError)?
                .to_owned()
                .into_inner(),
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
            ByteStream::from(encrypted.meta.as_bytes().to_owned()),
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
        for key in get_s3_data_keys(name) {
            self.s3
                .delete_object()
                .bucket(&self.cloudformation_params.bucket_name)
                .key(key)
                .send()
                .await?;
        }
        Ok(())
    }

    pub async fn lookup(&self, name: &str) -> Result<String, VaultError> {
        let key = name;
        let data_key = self.get_s3_object(format!("{key}.key"));
        let ciphertext = self.get_s3_object(format!("{key}.aesgcm.encrypted"));
        let meta_add = self.get_s3_object(format!("{key}.meta"));
        let (data_key, ciphertext, meta_add) = try_join!(data_key, ciphertext, meta_add)?;
        let meta: Meta = serde_json::from_slice(&meta_add)?;
        let cipher: AesGcm<Aes256, cipher::typenum::U12> =
            AesGcm::new_from_slice(self.direct_decrypt(&data_key).await?.as_slice())?;
        let nonce = general_purpose::STANDARD.decode(meta.nonce)?;
        let nonce = Nonce::from_slice(nonce.as_slice());
        let res = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &meta_add,
                },
            )
            .map_err(|_| VaultError::NonceDecryptError)?;
        Ok(String::from_utf8(res)?)
    }
}

async fn get_cloudformation_params(
    config: &SdkConfig,
    stack: &str,
) -> Result<CloudFormationParams, VaultError> {
    let stack_output = CloudFormationClient::new(config)
        .describe_stacks()
        .stack_name(stack)
        .send()
        .await?
        .stacks()
        .and_then(|stacks| stacks.first())
        .and_then(|stack| stack.outputs())
        .ok_or(VaultError::StackOutputsMissingError)?
        .to_owned();

    Ok(CloudFormationParams {
        bucket_name: parse_output_value_from_key("vaultBucketName", &stack_output)
            .ok_or(VaultError::BucketNameMissingError)?,
        key_arn: parse_output_value_from_key("kmsKeyArn", &stack_output),
        // deployed_version: parse_output_value_from_key("vaultStackVersion", &stack_output),
    })
}

fn get_region_provider(region_opt: Option<&str>) -> RegionProviderChain {
    RegionProviderChain::first_try(region_opt.map(|r| Region::new(r.to_owned())))
        .or_default_provider()
        .or_else("eu-west-1")
}

fn parse_output_value_from_key(key: &str, out: &[Output]) -> Option<String> {
    out.iter()
        .find(|output| output.output_key() == Some(key))
        .map(|output| output.output_value().unwrap_or_default().to_owned())
}

/// Helper function to get all three key names for S3 data
fn get_s3_data_keys(name: &str) -> [String; 3] {
    [
        format!("{name}.aesgcm.encrypted"),
        format!("{name}.key"),
        format!("{name}.meta"),
    ]
}
