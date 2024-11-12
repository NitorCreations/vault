use nitor_vault::errors::VaultError;
use nitor_vault::{Value, Vault};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
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

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn nitor_vault_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(delete, m)?)?;
    m.add_function(wrap_pyfunction!(delete_many, m)?)?;
    m.add_function(wrap_pyfunction!(exists, m)?)?;
    m.add_function(wrap_pyfunction!(list_all, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(store, m)?)?;
    Ok(())
}
