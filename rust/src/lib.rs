use aes_gcm::{
    aead::{Aead, Payload},
    aes::{cipher::typenum, Aes256},
    AesGcm, KeyInit, Nonce,
};
use aws_config::{meta::region::RegionProviderChain, SdkConfig};
use aws_sdk_cloudformation::{model::Output, Client as cfClient};
use aws_sdk_kms::{model::DataKeySpec, types::Blob, Client as kmsClient};
use aws_sdk_s3::{types::ByteStream, Client as s3Client, Region};
use base64::{engine::general_purpose, Engine as _};
use errors::VaultError;
use rand::Rng;
use serde::{Deserialize, Serialize};

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

impl CloudFormationParams {
    pub fn from(bucket_name: &str, key_arn: Option<&str>) -> CloudFormationParams {
        CloudFormationParams {
            bucket_name: bucket_name.to_owned(),
            key_arn: key_arn.map(|x| x.to_owned()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Meta {
    alg: String,
    nonce: String,
}

fn get_region_provider(region_opt: Option<&str>) -> RegionProviderChain {
    RegionProviderChain::first_try(region_opt.map(|r| Region::new(r.to_owned())))
        .or_default_provider()
        .or_else("eu-west-1")
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

    pub fn test(&self) {
        println!(
            "region: {}\nvault_stack: {:#?}\ns3: {:#?}",
            self.region, self.cloudformation_params, self.s3
        );
    }

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

    pub fn stack_info(&self) -> CloudFormationParams {
        self.cloudformation_params.to_owned()
    }

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
        let aesgcm_cipher: AesGcm<Aes256, typenum::U12> =
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

    async fn get_s3_obj_as_vec(&self, key: String) -> Result<Vec<u8>, VaultError> {
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

    async fn put_s3_obj(
        &self,
        body: aws_sdk_s3::types::ByteStream,
        key: &str,
    ) -> Result<aws_sdk_s3::output::PutObjectOutput, VaultError> {
        Ok(self
            .s3
            .put_object()
            .bucket(&self.cloudformation_params.bucket_name)
            .key(key)
            .acl(aws_sdk_s3::model::ObjectCannedAcl::Private)
            .body(body)
            .send()
            .await?)
    }

    // somewhat bad implementation, can fail for other reasons as well?
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

    pub async fn store(&self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        let encrypted = self.encrypt(data).await?;
        self.put_s3_obj(
            ByteStream::from(encrypted.aes_gcm_ciphertext),
            &format!("{}.aesgcm.encrypted", name),
        )
        .await?;

        self.put_s3_obj(
            ByteStream::from(encrypted.data_key),
            &format!("{}.key", name),
        )
        .await?;

        self.put_s3_obj(
            ByteStream::from(encrypted.meta.as_bytes().to_owned()),
            &format!("{}.meta", name),
        )
        .await?;

        Ok(())
    }
    pub async fn delete(&self, name: &str) -> Result<(), VaultError> {
        if !self.exists(name).await? {
            return Err(VaultError::S3DeleteObjectKeyMissingError);
        }
        self.s3
            .delete_object()
            .bucket(&self.cloudformation_params.bucket_name)
            .key(format!("{name}.aesgcm.encrypted"))
            .send()
            .await?;

        self.s3
            .delete_object()
            .bucket(&self.cloudformation_params.bucket_name)
            .key(format!("{name}.key"))
            .send()
            .await?;

        self.s3
            .delete_object()
            .bucket(&self.cloudformation_params.bucket_name)
            .key(format!("{name}.meta"))
            .send()
            .await?;
        Ok(())
    }

    pub async fn lookup(&self, name: &str) -> Result<String, VaultError> {
        let key = name;
        let data_key = self.get_s3_obj_as_vec(format!("{key}.key"));
        let ciphertext = self.get_s3_obj_as_vec(format!("{key}.aesgcm.encrypted"));
        let meta_add = self.get_s3_obj_as_vec(format!("{key}.meta")).await?;
        let meta: Meta = serde_json::from_slice(&meta_add)?;
        let cipher: AesGcm<Aes256, typenum::U12> =
            AesGcm::new_from_slice(self.direct_decrypt(&data_key.await?).await?.as_slice())?;
        let nonce = general_purpose::STANDARD.decode(meta.nonce)?;
        let nonce = Nonce::from_slice(nonce.as_slice());
        let res = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext.await?,
                    aad: &meta_add,
                },
            )
            .map_err(|_| VaultError::NonceDecryptError)?;
        Ok(String::from_utf8(res)?)
    }
}

struct EncryptObject {
    data_key: Vec<u8>,
    aes_gcm_ciphertext: Vec<u8>,
    meta: String,
}

fn parse_output_value_from_key(key: &str, out: &[Output]) -> Option<String> {
    out.iter()
        .find(|output| output.output_key() == Some(key))
        .map(|output| output.output_value().unwrap_or_default().to_owned())
}

async fn get_cloudformation_params(
    config: &SdkConfig,
    stack: &str,
) -> Result<CloudFormationParams, VaultError> {
    let stack_output = cfClient::new(config)
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
