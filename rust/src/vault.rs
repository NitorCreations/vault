use std::fmt;

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aws_config::Region;
use aws_sdk_cloudformation::Client as CloudFormationClient;
use aws_sdk_cloudformation::types::{Capability, Parameter, StackStatus};
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::operation::put_object::PutObjectOutput;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::Delete;
use aws_sdk_sts::Client as stsClient;
use base64::Engine;
use rand::Rng;

use crate::cloudformation;
use crate::cloudformation::{CloudFormationParams, CloudFormationStackData};
use crate::errors::VaultError;
use crate::template::{VAULT_STACK_VERSION, template};
use crate::value::Value;
use crate::{CreateStackResult, EncryptObject, Meta, S3DataKeys, UpdateStackResult, VaultConfig};

#[derive(Debug)]
pub struct Vault {
    /// AWS region to use with Vault.
    /// Will fall back to default provider if nothing is specified.
    pub region: Region,
    /// Prefix for key name
    pub prefix: String,
    pub cloudformation_params: CloudFormationParams,
    cf: CloudFormationClient,
    kms: KmsClient,
    s3: S3Client,
}

impl Vault {
    /// Construct Vault for an existing vault stack with defaults.
    ///
    /// This will try reading environment variables for the config values,
    /// and otherwise fall back to current AWS config and/or retrieve config values from the
    /// Cloudformation stack description.
    ///
    // The Default trait can't be implemented for Vault since it can fail.
    pub async fn default() -> Result<Self, VaultError> {
        Self::new(None, None, None, None, None, None, None, None).await
    }

    /// Construct Vault for an existing vault stack with optional arguments.
    ///
    /// This will try reading environment variables for the config values that are `None`.
    pub async fn new(
        vault_stack: Option<String>,
        region: Option<String>,
        bucket: Option<String>,
        key: Option<String>,
        prefix: Option<String>,
        profile: Option<String>,
        iam_id: Option<String>,
        iam_secret: Option<String>,
    ) -> Result<Self, VaultError> {
        let config = crate::resolve_aws_config_from_args(region, profile, iam_id, iam_secret).await;
        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let stack_name = vault_stack
            .or_else(|| crate::get_env_variable("VAULT_STACK"))
            .unwrap_or_else(|| "vault".to_string());
        let bucket = bucket.or_else(|| crate::get_env_variable("VAULT_BUCKET"));
        let key = key.or_else(|| crate::get_env_variable("VAULT_KEY"));
        let mut prefix = prefix
            .or_else(|| crate::get_env_variable("VAULT_PREFIX"))
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

    /// Construct Vault for an existing vault stack from given `VaultConfig`.
    pub async fn from_config(config: VaultConfig) -> Result<Self, VaultError> {
        Self::new(
            config.vault_stack,
            config.region,
            config.bucket,
            config.key,
            config.prefix,
            config.profile,
            config.iam_id,
            config.iam_secret,
        )
        .await
    }

    /// Initialize new Vault stack.
    /// This will create all required resources in AWS,
    /// after which the Vault can be used to store and lookup values.
    ///
    /// Returns a `CreateStackResult` with relevant data whether a new vault stack was initialized,
    /// or it already exists.
    pub async fn init(
        vault_stack: Option<String>,
        region: Option<String>,
        bucket: Option<String>,
        profile: Option<String>,
        iam_id: Option<String>,
        iam_secret: Option<String>,
    ) -> Result<CreateStackResult, VaultError> {
        let config = crate::resolve_aws_config_from_args(region, profile, iam_id, iam_secret).await;
        let region = config
            .region()
            .map(ToOwned::to_owned)
            .ok_or_else(|| VaultError::NoRegionError)?;

        // Check env variables directly in case the library is not used through the CLI.
        // These are also handled in the CLI, so they are documented in the CLI help.
        let stack_name = vault_stack
            .or_else(|| crate::get_env_variable("VAULT_STACK"))
            .unwrap_or_else(|| "vault".to_string());

        let bucket = bucket
            .or_else(|| crate::get_env_variable("VAULT_BUCKET"))
            .unwrap_or({
                let sts_client = stsClient::new(&config);
                let identity = sts_client
                    .get_caller_identity()
                    .send()
                    .await
                    .map_err(VaultError::from)?;
                if let Some(account_id) = identity.account() {
                    format!("{stack_name}-{region}-{account_id}")
                } else {
                    return Err(VaultError::MissingAccountIdError);
                }
            });

        let cf_client = CloudFormationClient::new(&config);

        if let Ok(data) = cloudformation::get_stack_data(&cf_client, &stack_name).await {
            return if let Some(ref status) = data.status {
                match status {
                    // Stack might exist but not be in a usable state.
                    StackStatus::CreateFailed
                    | StackStatus::RollbackFailed
                    | StackStatus::DeleteFailed
                    | StackStatus::DeleteInProgress
                    | StackStatus::DeleteComplete => {
                        Ok(CreateStackResult::ExistsWithFailedState { data })
                    }
                    _ => Ok(CreateStackResult::Exists { data }),
                }
            } else {
                Err(VaultError::MissingStackStatusError)
            };
        }

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

        let stack_id = response.stack_id.ok_or(VaultError::MissingStackIdError)?;

        Ok(CreateStackResult::Created {
            stack_name,
            stack_id,
            region,
        })
    }

    /// Update the vault Cloudformation stack with the current template.
    ///
    /// Returns an `UpdateStackResult` enum that indicates if the vault was updated,
    /// or is already up to date.
    pub async fn update_stack(&self) -> Result<UpdateStackResult, VaultError> {
        let stack_name = &self.cloudformation_params.stack_name;
        let stack_data = cloudformation::get_stack_data(&self.cf, stack_name).await?;
        let deployed_version = stack_data
            .version
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

            let stack_id = response.stack_id.ok_or(VaultError::MissingStackIdError)?;
            Ok(UpdateStackResult::Updated {
                stack_id,
                previous_version: deployed_version,
                new_version: VAULT_STACK_VERSION,
            })
        } else {
            Ok(UpdateStackResult::UpToDate { data: stack_data })
        }
    }

    /// Get Cloudformation vault stack status.
    pub async fn stack_status(&self) -> Result<CloudFormationStackData, VaultError> {
        cloudformation::get_stack_data(&self.cf, &self.cloudformation_params.stack_name).await
    }

    /// Get all available secrets.
    ///
    /// Returns a list of key names.
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

    /// Get Cloudformation parameters.
    #[must_use]
    pub fn stack_info(&self) -> CloudFormationParams {
        self.cloudformation_params.clone()
    }

    /// Check if the given key name already exists in the S3 bucket.
    ///
    /// Returns `true` if the key exists, `false` otherwise.
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

    /// Store encrypted data with given key name in S3
    pub async fn store(&self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        let encrypted = self.encrypt(data).await?;

        let key = &self.full_key_name(name);
        let keys = S3DataKeys::new(key);

        let put_cipher =
            self.put_s3_object(keys.cipher, ByteStream::from(encrypted.aes_gcm_ciphertext));
        let put_key = self.put_s3_object(keys.key, ByteStream::from(encrypted.data_key));
        let put_meta = self.put_s3_object(keys.meta, ByteStream::from(encrypted.meta.into_bytes()));

        tokio::try_join!(put_cipher, put_key, put_meta)?;

        Ok(())
    }

    /// Delete data in S3 for given key name.
    pub async fn delete(&self, name: &str) -> Result<(), VaultError> {
        if !self.exists(name).await? {
            return Err(VaultError::S3DeleteObjectKeyMissingError {
                name: name.to_string(),
            });
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

    /// Delete data for multiple keys.
    pub async fn delete_many(&self, names: &[String]) -> Result<(), VaultError> {
        for name in names {
            self.delete(name).await?;
        }
        Ok(())
    }

    /// Return value for the given key name.
    /// If the data is valid UTF-8, it will be returned as a string.
    /// Otherwise, the raw bytes will be returned.
    pub async fn lookup(&self, name: &str) -> Result<Value, VaultError> {
        let key = &self.full_key_name(name);
        let keys = S3DataKeys::new(key);

        let data_key = self.get_s3_object(keys.key).await?;

        let cipher_text = self.get_s3_object(keys.cipher);
        let meta_add = self.get_s3_object(keys.meta);

        match tokio::try_join!(cipher_text, meta_add) {
            Ok((cipher_text, meta_add)) => {
                self.lookup_aesgcm_data(&data_key, &cipher_text, &meta_add)
                    .await
            }
            Err(err) => {
                if matches!(err, VaultError::KeyDoesNotExistError) {
                    // Data key exists but other AES-GCM files do not:
                    // This secret has been encrypted with the old deprecated method
                    Err(VaultError::DeprecatedEncryptionError)
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn lookup_aesgcm_data(
        &self,
        data_key: &[u8],
        cipher_text: &Vec<u8>,
        meta_add: &Vec<u8>,
    ) -> Result<Value, VaultError> {
        let meta: Meta = serde_json::from_slice(meta_add)?;
        let cipher: AesGcm<Aes256, U12> =
            AesGcm::new_from_slice(self.direct_decrypt(data_key).await?.as_slice())?;
        let nonce = base64::engine::general_purpose::STANDARD.decode(meta.nonce)?;
        let nonce = Nonce::from_slice(nonce.as_slice());
        let decrypted_bytes = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: cipher_text,
                    aad: meta_add,
                },
            )
            .map_err(|_| VaultError::NonceDecryptError)?;

        match String::from_utf8(decrypted_bytes) {
            Ok(valid_string) => Ok(Value::Utf8(valid_string)),
            Err(from_utf8_error) => Ok(Value::Binary(from_utf8_error.into_bytes())),
        }
    }

    /// Decrypt data with KMS.
    pub async fn direct_decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, VaultError> {
        self.kms
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_data))
            .send()
            .await?
            .plaintext()
            .map(|blob| blob.to_owned().into_inner())
            .ok_or(VaultError::KmsDataKeyPlainTextMissingError)
    }

    /// Encrypt data with KMS.
    pub async fn direct_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, VaultError> {
        let key = self
            .cloudformation_params
            .key_arn
            .as_ref()
            .ok_or(VaultError::KeyArnMissingError)?;

        let response = self
            .kms
            .encrypt()
            .key_id(key)
            .plaintext(Blob::new(data))
            .send()
            .await
            .map_err(VaultError::from)?;

        let ciphertext = response
            .ciphertext_blob
            .ok_or(VaultError::CiphertextEncryptionError)?
            .into_inner();

        Ok(ciphertext)
    }

    /// Get S3 Object data for given key as a vec of bytes.
    async fn get_s3_object(&self, key: String) -> Result<Vec<u8>, VaultError> {
        let response = self
            .s3
            .get_object()
            .bucket(self.cloudformation_params.bucket_name.clone())
            .key(&key)
            .send()
            .await
            .map_err(|err| {
                if let Some(service_error) = err.as_service_error() {
                    if service_error.is_no_such_key() {
                        VaultError::KeyDoesNotExistError
                    } else {
                        VaultError::S3GetObjectError(err)
                    }
                } else {
                    VaultError::S3GetObjectError(err)
                }
            })?;

        let body = response
            .body
            .collect()
            .await
            .map_err(|_| VaultError::S3GetObjectBodyError)?;

        Ok(body.to_vec())
    }

    /// Encrypt data
    async fn encrypt(&self, data: &[u8]) -> Result<EncryptObject, VaultError> {
        let key = self
            .cloudformation_params
            .key_arn
            .clone()
            .ok_or(VaultError::KeyArnMissingError)?;

        let key_dict = self
            .kms
            .generate_data_key()
            .key_id(key)
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await?;

        let plaintext = key_dict
            .plaintext()
            .ok_or(VaultError::KmsDataKeyPlainTextMissingError)?;

        let aesgcm_cipher: AesGcm<Aes256, U12> = AesGcm::new_from_slice(plaintext.as_ref())?;
        let nonce = Self::create_random_nonce();
        let meta = Meta::aesgcm(&nonce).to_json()?;
        let aes_gcm_ciphertext = aesgcm_cipher
            .encrypt(
                &nonce,
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

    /// Send PUT request with the given byte data.
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

    #[inline]
    fn create_random_nonce() -> Nonce<U12> {
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::rng();
        rng.fill(&mut nonce);
        Nonce::from(nonce)
    }
}

impl fmt::Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "region: {}\n{}", self.region, self.cloudformation_params)?;
        if !self.prefix.is_empty() {
            write!(f, "\nprefix: {}", self.prefix)?;
        }
        Ok(())
    }
}
