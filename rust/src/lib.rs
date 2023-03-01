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
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Vault {
    region: Region,
    cf_params: CfParams,
    config: SdkConfig,
    s3: s3Client,
    kms: kmsClient,
}
#[derive(Debug)]
struct CfParams {
    bucket_name: String,
    key_arn: Option<String>,
    // deployed_version: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Meta {
    alg: String,
    nonce: String,
}

impl Vault {
    pub async fn new(vault_stack: Option<&str>) -> Vault {
        let region_provider = RegionProviderChain::default_provider().or_else("eu-west-1");
        let config = aws_config::from_env().region(region_provider).load().await;
        let cf_params = get_cf_params(&config, vault_stack.unwrap_or("vault")).await;
        Vault {
            region: config.region().unwrap().to_owned(),
            cf_params,
            s3: s3Client::new(&config),
            kms: kmsClient::new(&config),
            config,
        }
    }
    pub fn test(&self) {
        println!(
            "region:{},vault_stack:{:?},s3:{:?}",
            self.region, self.cf_params, self.s3
        );
    }

    pub async fn list_all(&self) {
        println!("{}", self.all().await.join("\n"));
    }
    async fn all(&self) -> Vec<String> {
        let mut res: Vec<String> = Vec::new();

        self.s3
            .list_objects_v2()
            .bucket(&self.cf_params.bucket_name)
            .send()
            .await
            .expect("failed to list buckets")
            .contents()
            .unwrap()
            .iter()
            .for_each(|object| {
                if let Some(key) = object.key() {
                    if key.ends_with(".aesgcm.encrypted")
                        && !res.contains(&key[..key.len() - 17].to_owned())
                    {
                        res.push(key[..key.len() - 17].to_owned());
                    } else if key.ends_with(".encrypted")
                        && !res.contains(&key[..key.len() - 10].to_owned())
                    {
                        res.push(key[..key.len() - 10].to_owned());
                    }
                }
            });
        res
    }
    pub async fn stack_info(&self) {
        println!("{:?}", get_cf_params(&self.config, "vault").await)
    }

    async fn encrypt(&self, data: &[u8]) -> EncryptObject {
        let key_dict = self
            .kms
            .generate_data_key()
            .key_id(self.cf_params.key_arn.to_owned().unwrap())
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .expect("error getting key from KMS");
        let plaintext = key_dict.plaintext().unwrap().as_ref();
        let aesgcm_cipher: AesGcm<Aes256, typenum::U12> =
            AesGcm::new_from_slice(plaintext).unwrap();
        let mut nonce: [u8; 12] = [0; 12];
        let mut rng = rand::thread_rng();
        rng.fill(nonce.as_mut_slice());
        let nonce = Nonce::from_slice(nonce.as_slice());
        let meta = serde_json::to_string(&Meta {
            alg: "AESGCM".to_owned(),
            nonce: general_purpose::STANDARD.encode(nonce),
        })
        .unwrap();
        let aes_gcm_ciphertext = aesgcm_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: meta.as_bytes(),
                },
            )
            .unwrap()
            .to_vec();
        EncryptObject {
            data_key: key_dict.ciphertext_blob().unwrap().to_owned().into_inner(),
            aes_gcm_ciphertext,
            meta: meta,
        }
    }
    async fn get_s3_obj_as_vec(&self, key: String) -> Vec<u8> {
        self.s3
            .get_object()
            .bucket(self.cf_params.bucket_name.to_owned())
            .key(&key)
            .send()
            .await
            .unwrap_or_else(|_| panic!("no such key:{}", key))
            .body
            .collect()
            .await
            .unwrap()
            .to_vec()
    }
    async fn direct_decrypt(&self, encrypted_data: &[u8]) -> Vec<u8> {
        self.kms
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_data))
            .send()
            .await
            .unwrap()
            .plaintext()
            .unwrap()
            .to_owned()
            .into_inner()
    }
    async fn put_s3_obj(&self, body: aws_sdk_s3::types::ByteStream, key: &str) {
        self.s3
            .put_object()
            .bucket(&self.cf_params.bucket_name)
            .key(key)
            .acl(aws_sdk_s3::model::ObjectCannedAcl::Private)
            .body(body)
            .send()
            .await
            .expect("error saving key");
    }
    pub async fn store(&self, name: &str, data: &[u8]) {
        let encrypted = self.encrypt(data).await;
        self.put_s3_obj(
            ByteStream::from(encrypted.aes_gcm_ciphertext),
            &format!("{}.aesgcm.encrypted", name),
        )
        .await;
        self.put_s3_obj(
            ByteStream::from(encrypted.data_key),
            &format!("{}.key", name),
        )
        .await;
        self.put_s3_obj(
            ByteStream::from(encrypted.meta.as_bytes().to_owned()),
            &format!("{}.meta", name),
        )
        .await;
    }
    pub async fn lookup(&self, name: &str) -> String {
        let key = name;
        let data_key = self.get_s3_obj_as_vec(format!("{key}.key")).await;
        let meta_add = self.get_s3_obj_as_vec(format!("{key}.meta")).await;
        let ciphertext = self
            .get_s3_obj_as_vec(format!("{key}.aesgcm.encrypted"))
            .await;
        let meta: Meta = serde_json::from_slice(&meta_add).unwrap();
        let cipher: AesGcm<Aes256, typenum::U12> =
            AesGcm::new_from_slice(self.direct_decrypt(&data_key).await.as_slice()).unwrap();
        let nonce = general_purpose::STANDARD.decode(meta.nonce).unwrap();
        let nonce = Nonce::from_slice(nonce.as_slice());
        let res = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &meta_add,
                },
            )
            .unwrap();
        String::from_utf8(res).unwrap()
    }
}

struct EncryptObject {
    data_key: Vec<u8>,
    aes_gcm_ciphertext: Vec<u8>,
    meta: String,
}

fn parse_output_value_from_key(key: &str, out: &Vec<Output>) -> Option<String> {
    out.iter()
        .find(|output| output.output_key() == Some(key))
        .map(|output| output.output_value().unwrap_or_default().to_owned())
}

async fn get_cf_params(config: &SdkConfig, stack: &str) -> CfParams {
    let stack_output = cfClient::new(config)
        .describe_stacks()
        .stack_name(stack)
        .send()
        .await
        .expect("error getting stack information")
        .stacks()
        .unwrap_or_default()
        .first()
        .expect("stack not found")
        .outputs()
        .unwrap()
        .to_owned();

    CfParams {
        bucket_name: parse_output_value_from_key("vaultBucketName", &stack_output)
            .expect("Error getting bucket name from stack"),
        key_arn: parse_output_value_from_key("kmsKeyArn", &stack_output),
        // deployed_version: parse_output_value_from_key("vaultStackVersion", &stack_output),
    }
}
