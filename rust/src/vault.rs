use std::{env, fmt};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::{cipher, Aes256};
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aws_config::meta::region::RegionProviderChain;
use aws_config::Region;
use aws_sdk_cloudformation::operation::describe_stacks::DescribeStacksOutput;
use aws_sdk_cloudformation::types::{Capability, Parameter, StackStatus};
use aws_sdk_cloudformation::Client as CloudFormationClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Delete;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sts::Client as stsClient;
use base64::Engine;
use rand::Rng;
use tokio::try_join;

use crate::errors::VaultError;
use crate::template::{template, VAULT_STACK_VERSION};
use crate::value::Value;
use crate::{CloudFormationParams, CloudFormationStackData, EncryptObject, Meta, S3DataKeys};

#[derive(Debug)]
pub struct Vault {
    /// AWS region to use with Vault.
    /// Will fall back to default provider if nothing is specified.
    region: Region,
    /// Prefix for key name
    prefix: String,
    cloudformation_params: CloudFormationParams,
    cf: CloudFormationClient,
    kms: KmsClient,
    s3: S3Client,
}

impl Vault {
    /// Construct Vault with defaults for an existing stack.
    /// This will try reading environment variables for the config values,
    /// and otherwise fall back to current AWS config.
    ///
    /// The Default trait can't be implemented for Vault since it can fail.
    pub async fn default() -> Result<Self, VaultError> {
        Self::new(None, None, None, None, None).await
    }

    /// Construct Vault with optional arguments for an existing stack.
    /// This will try reading environment variables for the config values if they are `None`.
    pub async fn new(
        vault_stack: Option<String>,
        region: Option<String>,
        bucket: Option<String>,
        key: Option<String>,
        prefix: Option<String>,
    ) -> Result<Self, VaultError> {
        let config = aws_config::from_env()
            .region(get_region_provider(region))
            .load()
            .await;

        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let stack_name = vault_stack
            .or_else(|| get_env_variable("VAULT_STACK"))
            .unwrap_or_else(|| "vault".to_string());
        let bucket = bucket.or_else(|| get_env_variable("VAULT_BUCKET"));
        let key = key.or_else(|| get_env_variable("VAULT_KEY"));
        let mut prefix = prefix
            .or_else(|| get_env_variable("VAULT_PREFIX"))
            .unwrap_or_default();

        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }

        let cf_client = CloudFormationClient::new(&config);
        let cloudformation_params = if let (Some(bucket), Some(key)) = (bucket, key) {
            CloudFormationParams::new(bucket, Some(key), stack_name)
        } else {
            CloudFormationParams::from_stack(&cf_client, stack_name).await?
        };

        Ok(Self {
            region,
            prefix,
            cloudformation_params,
            cf: cf_client,
            kms: KmsClient::new(&config),
            s3: S3Client::new(&config),
        })
    }

    /// Initialize new Vault stack
    pub async fn init(
        vault_stack: Option<String>,
        region: Option<String>,
        bucket: Option<String>,
    ) -> Result<(), VaultError> {
        let config = aws_config::from_env()
            .region(get_region_provider(region))
            .load()
            .await;

        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let stack_name = vault_stack
            .or_else(|| get_env_variable("VAULT_STACK"))
            .unwrap_or_else(|| "vault".to_string());

        let bucket = bucket
            .or_else(|| get_env_variable("VAULT_BUCKET"))
            .unwrap_or({
                let sts_client = stsClient::new(&config);
                let identity = sts_client
                    .get_caller_identity()
                    .send()
                    .await
                    .map_err(VaultError::from)?;
                if let Some(account_id) = identity.account() {
                    let bucket = format!("{stack_name}-{region}-{account_id}");
                    println!("Using bucket name: {bucket}");
                    bucket
                } else {
                    return Err(VaultError::MissingAccountIdError);
                }
            });

        let cf_client = CloudFormationClient::new(&config);

        if Self::describe_stack(&cf_client, &stack_name).await.is_ok() {
            println!("Vault stack '{stack_name}' already initialized");
        } else {
            let parameters = Parameter::builder()
                .parameter_key("paramBucketName")
                .parameter_value(bucket)
                .build();

            let response = cf_client
                .create_stack()
                .stack_name(&stack_name)
                .template_body(template())
                .parameters(parameters)
                .capabilities(Capability::CapabilityIam)
                .send()
                .await
                .map_err(VaultError::from)?;

            if let Some(stack_id) = response.stack_id {
                println!("{stack_id}");
            }

            println!("Vault stack '{stack_name}' created");
        }

        match Self::get_cloudformation_stack_data(&cf_client, &stack_name).await {
            Ok(stack_data) => {
                println!("{stack_data}");
            }
            Err(err) => return Err(err),
        }

        Ok(())
    }

    pub async fn update_stack(&self) -> Result<(), VaultError> {
        let stack_name = &self.cloudformation_params.stack_name;
        let stack_data = Self::get_cloudformation_stack_data(&self.cf, stack_name).await?;
        println!("{stack_data}");
        let deployed_version = stack_data
            .deployed_version
            .map_or_else(|| Err(VaultError::StackVersionNotFoundError), Ok)?;

        if deployed_version < VAULT_STACK_VERSION {
            let parameter = Parameter::builder()
                .parameter_key("paramBucketName")
                .use_previous_value(true)
                .build();

            let response = self
                .cf
                .update_stack()
                .stack_name(stack_name)
                .template_body(template())
                .parameters(parameter)
                .capabilities(Capability::CapabilityIam)
                .capabilities(Capability::CapabilityNamedIam)
                .send()
                .await?;

            if let Some(stack_id) = response.stack_id {
                println!("{stack_id}");
            }

            println!("Updated vault stack '{stack_name}' version from {deployed_version} to {VAULT_STACK_VERSION}");
        } else {
            println!("Current stack version {deployed_version} does not need to be updated to version {VAULT_STACK_VERSION}");
        }

        Ok(())
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

    /// Check if key already exists in bucket
    pub async fn exists(&self, name: &str) -> Result<bool, VaultError> {
        let name = self.full_key_name(name);
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

        let key = &self.full_key_name(name);
        let keys = S3DataKeys::new(key);

        let put_cipher =
            self.put_s3_object(keys.cipher, ByteStream::from(encrypted.aes_gcm_ciphertext));
        let put_key = self.put_s3_object(keys.key, ByteStream::from(encrypted.data_key));
        let put_meta = self.put_s3_object(keys.meta, ByteStream::from(encrypted.meta.into_bytes()));

        try_join!(put_cipher, put_key, put_meta)?;

        Ok(())
    }

    /// Delete data in S3 for given key
    pub async fn delete(&self, name: &str) -> Result<(), VaultError> {
        if !self.exists(name).await? {
            return Err(VaultError::S3DeleteObjectKeyMissingError);
        }

        let key = &self.full_key_name(name);
        let identifiers = S3DataKeys::new(key).to_object_identifiers()?;
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
        let key = &self.full_key_name(name);
        let keys = S3DataKeys::new(key);

        let data_key = self.get_s3_object(keys.key);
        let cipher_text = self.get_s3_object(keys.cipher);
        let meta_add = self.get_s3_object(keys.meta);
        let (data_key, cipher_text, meta_add) = try_join!(data_key, cipher_text, meta_add)?;

        let meta: Meta = serde_json::from_slice(&meta_add)?;
        let cipher: AesGcm<Aes256, cipher::typenum::U12> =
            AesGcm::new_from_slice(self.direct_decrypt(&data_key).await?.as_slice())?;
        let nonce = base64::engine::general_purpose::STANDARD.decode(meta.nonce)?;
        let nonce = Nonce::from_slice(nonce.as_slice());
        let decrypted_bytes = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &cipher_text,
                    aad: &meta_add,
                },
            )
            .map_err(|_| VaultError::NonceDecryptError)?;

        match String::from_utf8(decrypted_bytes) {
            Ok(valid_string) => Ok(Value::Utf8(valid_string)),
            Err(from_utf8_error) => Ok(Value::Binary(from_utf8_error.into_bytes())),
        }
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
        let nonce = create_random_nonce();
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

    /// Send PUT request with the given byte data
    async fn put_s3_object(
        &self,
        key: String,
        body: ByteStream,
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

    /// Add prefix to key if prefix has been specified.
    fn full_key_name(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}{}", self.prefix, name)
        }
    }

    async fn describe_stack(
        cf_client: &CloudFormationClient,
        stack_name: &str,
    ) -> Result<DescribeStacksOutput, VaultError> {
        cf_client
            .describe_stacks()
            .stack_name(stack_name)
            .send()
            .await
            .map_err(VaultError::from)
    }

    /// Extract relevant information from `CloudFormation` stack outputs
    async fn get_cloudformation_stack_data(
        cf_client: &CloudFormationClient,
        stack_name: &str,
    ) -> Result<CloudFormationStackData, VaultError> {
        let stack_response = cf_client
            .describe_stacks()
            .stack_name(stack_name)
            .send()
            .await?;

        let mut data = CloudFormationStackData::default();
        if let Some(stacks) = stack_response.stacks {
            if let Some(stack) = stacks.first() {
                data.status.clone_from(&stack.stack_status);
                if let Some(outputs) = &stack.outputs {
                    for output in outputs {
                        if let Some(output_key) = output.output_key() {
                            match output_key {
                                "vaultBucketName" => {
                                    if let Some(output_value) = output.output_value() {
                                        data.bucket_name = Some(output_value.to_string());
                                    }
                                }
                                "kmsKeyArn" => {
                                    if let Some(output_value) = output.output_value() {
                                        data.key_arn = Some(output_value.to_string());
                                    }
                                }
                                "vaultStackVersion" => {
                                    if let Some(output_value) = output.output_value() {
                                        if let Ok(version) = output_value.parse::<u32>() {
                                            data.deployed_version = Some(version);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }

        Ok(data)
    }
}

impl fmt::Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "region: {}\n{}", self.region, self.cloudformation_params)
    }
}

fn create_random_nonce() -> [u8; 12] {
    let mut nonce: [u8; 12] = [0; 12];
    let mut rng = rand::thread_rng();
    rng.fill(nonce.as_mut_slice());
    nonce
}

/// Get AWS region from optional argument or fallback to default
fn get_region_provider(region: Option<String>) -> RegionProviderChain {
    RegionProviderChain::first_try(region.map(Region::new)).or_default_provider()
}

/// Return possible env variable value as Option
fn get_env_variable(name: &str) -> Option<String> {
    env::var(name).ok()
}
