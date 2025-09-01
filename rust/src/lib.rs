pub mod args;
pub mod cli;
pub mod cloudformation;
pub mod errors;

mod template;
mod value;
mod vault;

// Expose `Vault` and `Value` so they can be used as if they were defined here
pub use crate::args::run_cli;
pub use crate::args::run_cli_with_args;
pub use crate::value::Value;
pub use crate::vault::Vault;

use aws_config::meta::region::RegionProviderChain;
use aws_config::{Region, SdkConfig};
use aws_sdk_s3::types::ObjectIdentifier;
use aws_sdk_sts::config::Credentials;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::cloudformation::CloudFormationStackData;
use crate::errors::VaultError;

/// Result data for initializing a new vault stack.
#[derive(Debug, Clone)]
pub enum CreateStackResult {
    /// Vault stack has already been initialized.
    Exists { data: CloudFormationStackData },
    /// Vault stack exists but is not in a usable state.
    ExistsWithFailedState { data: CloudFormationStackData },
    /// A new vault stack has been created.
    Created {
        stack_name: String,
        stack_id: String,
        region: Region,
    },
}

/// Result data for updating the vault stack.
#[derive(Debug, Clone)]
pub enum UpdateStackResult {
    /// Vault stack is up to date. No update needed.
    UpToDate { data: CloudFormationStackData },
    /// Vault stack was updated.
    Updated {
        stack_id: String,
        previous_version: u32,
        new_version: u32,
    },
}

/// Optional parameters for a `Vault` instance.
#[derive(Debug, Default, Clone)]
pub struct VaultConfig {
    pub vault_stack: Option<String>,
    pub region: Option<String>,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub prefix: Option<String>,
    pub profile: Option<String>,
    pub iam_id: Option<String>,
    pub iam_secret: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct EncryptObject {
    data_key: Vec<u8>,
    aes_gcm_ciphertext: Vec<u8>,
    meta: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Meta {
    alg: String,
    nonce: String,
}

/// S3 object identifier names for a single value.
#[derive(Debug, Clone)]
pub(crate) struct S3DataKeys {
    key: String,
    cipher: String,
    meta: String,
}

impl Meta {
    #[must_use]
    fn new(algorithm: &str, nonce: &[u8]) -> Self {
        Self {
            alg: algorithm.to_owned(),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        }
    }

    /// Shorthand to initialize new Meta with AES-GCM algorithm.
    #[must_use]
    fn aesgcm(nonce: &[u8]) -> Self {
        Self::new("AESGCM", nonce)
    }

    /// Serialize Meta to JSON string.
    fn to_json(&self) -> serde_json::Result<String> {
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
    const fn as_array(&self) -> [&str; 3] {
        [self.key.as_str(), self.cipher.as_str(), self.meta.as_str()]
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

/// Return possible env variable value as Option.
#[inline]
#[must_use]
pub fn get_env_variable(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Get AWS SDK config from optional arguments.
///
/// Uses the following priority:
/// 1. Use `id` and `secret` if provided.
/// 2. Use the specified profile name if available.
/// 3. Fallback to environment variables and defaults.
#[must_use]
pub async fn resolve_aws_config_from_args(
    region: Option<String>,
    profile: Option<String>,
    iam_id: Option<String>,
    iam_secret: Option<String>,
) -> SdkConfig {
    if let (Some(id), Some(secret)) = (iam_id, iam_secret) {
        get_aws_config_from_credentials(&id, &secret, region).await
    } else {
        get_aws_config(region, profile).await
    }
}

/// Return AWS SDK config with optional region name to use.
#[inline]
#[must_use]
pub async fn get_aws_config(region: Option<String>, profile: Option<String>) -> SdkConfig {
    profile
        .map_or_else(aws_config::from_env, |profile| {
            aws_config::from_env().profile_name(profile)
        })
        .region(get_region_provider(region))
        .load()
        .await
}

/// Return AWS SDK config from id and secret with optional region name to use.
#[inline]
#[must_use]
async fn get_aws_config_from_credentials(
    id: &str,
    secret: &str,
    region: Option<String>,
) -> SdkConfig {
    let credentials_provider = Credentials::new(id, secret, None, None, "manual");
    aws_config::from_env()
        .region(get_region_provider(region))
        .credentials_provider(credentials_provider)
        .load()
        .await
}

#[inline]
/// Get AWS region from optional argument or fallback to default.
fn get_region_provider(region: Option<String>) -> RegionProviderChain {
    RegionProviderChain::first_try(region.map(Region::new)).or_default_provider()
}
