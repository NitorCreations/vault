use std::collections::HashMap;

use nitor_vault::cloudformation::CloudFormationStackData;
use nitor_vault::errors::VaultError;
use nitor_vault::{CreateStackResult, UpdateStackResult, Value, Vault};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
}

fn to_hash_map(stack_data: CloudFormationStackData, result: String) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("result".to_string(), result);
    map.insert(
        "bucket_name".to_string(),
        stack_data.bucket_name.clone().unwrap_or_default(),
    );
    map.insert(
        "key_arn".to_string(),
        stack_data.key_arn.clone().unwrap_or_default(),
    );
    map.insert(
        "version".to_string(),
        stack_data
            .version
            .map_or_else(String::new, |v| v.to_string()),
    );
    map.insert(
        "status".to_string(),
        stack_data
            .status
            .as_ref()
            .map_or_else(String::new, std::string::ToString::to_string),
    );
    map.insert(
        "status_reason".to_string(),
        stack_data.status_reason.unwrap_or_default(),
    );

    map
}

#[pyfunction(signature = (name, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn delete(
    name: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        Ok(
            Vault::new(vault_stack, region, bucket, key, prefix, profile)
                .await
                .map_err(vault_error_to_anyhow)?
                .delete(name)
                .await
                .map_err(vault_error_to_anyhow)?,
        )
    })
}

#[pyfunction(signature = (names, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
#[allow(clippy::needless_pass_by_value)]
fn delete_many(
    names: Vec<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        Ok(
            Vault::new(vault_stack, region, bucket, key, prefix, profile)
                .await
                .map_err(vault_error_to_anyhow)?
                .delete_many(&names)
                .await
                .map_err(vault_error_to_anyhow)?,
        )
    })
}

#[pyfunction(signature = (name, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn exists(
    name: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<bool> {
    Runtime::new()?.block_on(async {
        let result: bool = Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .exists(name)
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, profile=None))]
fn init(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    profile: Option<String>,
) -> PyResult<HashMap<String, String>> {
    Runtime::new()?.block_on(async {
        let result = Vault::init(vault_stack, region, bucket, profile)
            .await
            .map_err(vault_error_to_anyhow)?;
        match result {
            CreateStackResult::Exists { data } => Ok(to_hash_map(data, "exists".to_string())),
            CreateStackResult::ExistsWithFailedState { data } => {
                Ok(to_hash_map(data, "error".to_string()))
            }
            CreateStackResult::Created {
                stack_name,
                stack_id,
                region,
            } => {
                let mut dict = HashMap::new();
                dict.insert("result".to_string(), "created".to_string());
                dict.insert("stack_name".to_string(), stack_name);
                dict.insert("stack_id".to_string(), stack_id);
                dict.insert("region".to_string(), region.to_string());
                Ok(dict)
            }
        }
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn list_all(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<Vec<String>> {
    Runtime::new()?.block_on(async {
        let result = Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .all()
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pyfunction(signature = (name, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn lookup(
    name: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<String> {
    Runtime::new()?.block_on(async {
        let result: Value = Box::pin(
            Vault::new(vault_stack, region, bucket, key, prefix, profile)
                .await
                .map_err(vault_error_to_anyhow)?
                .lookup(name),
        )
        .await
        .map_err(vault_error_to_anyhow)?;

        Ok(result.to_string())
    })
}

#[pyfunction]
/// Run Vault CLI with given args.
fn run(args: Vec<String>) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        nitor_vault::run_cli_with_args(args).await?;
        Ok(())
    })
}

#[pyfunction(signature = (name, value, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn store(
    name: &str,
    value: &[u8],
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        Ok(Box::pin(
            Vault::new(vault_stack, region, bucket, key, prefix, profile)
                .await
                .map_err(vault_error_to_anyhow)?
                .store(name, value),
        )
        .await
        .map_err(vault_error_to_anyhow)?)
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn update(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<HashMap<String, String>> {
    Runtime::new()?.block_on(async {
        let result = Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .update_stack()
            .await
            .map_err(vault_error_to_anyhow)?;

        match result {
            UpdateStackResult::UpToDate { data } => Ok(to_hash_map(data, "up-to-date".to_string())),
            UpdateStackResult::Updated {
                stack_id,
                previous_version,
                new_version,
            } => {
                let mut map = HashMap::new();
                map.insert("result".to_string(), "updated".to_string());
                map.insert("stack_id".to_string(), stack_id);
                map.insert("previous_version".to_string(), previous_version.to_string());
                map.insert("new_version".to_string(), new_version.to_string());
                Ok(map)
            }
        }
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn nitor_vault_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(delete, m)?)?;
    m.add_function(wrap_pyfunction!(delete_many, m)?)?;
    m.add_function(wrap_pyfunction!(exists, m)?)?;
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(list_all, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(store, m)?)?;
    m.add_function(wrap_pyfunction!(update, m)?)?;
    Ok(())
}
