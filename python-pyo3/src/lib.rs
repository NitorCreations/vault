use nitor_vault::errors::VaultError;
use nitor_vault::{Value, Vault};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
}

#[pyfunction]
fn delete(name: &str) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        Ok(Vault::default()
            .await
            .map_err(vault_error_to_anyhow)?
            .delete(name)
            .await
            .map_err(vault_error_to_anyhow)?)
    })
}

#[pyfunction]
fn exists(name: &str) -> PyResult<bool> {
    Runtime::new()?.block_on(async {
        let result: bool = Vault::default()
            .await
            .map_err(vault_error_to_anyhow)?
            .exists(name)
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pyfunction]
fn list_all() -> PyResult<Vec<String>> {
    Runtime::new()?.block_on(async {
        let result = Vault::default()
            .await
            .map_err(vault_error_to_anyhow)?
            .all()
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pyfunction]
fn lookup(name: &str) -> PyResult<String> {
    Runtime::new()?.block_on(async {
        let result: Value = Box::pin(
            Vault::default()
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

#[pyfunction]
fn store(key: &str, value: &[u8]) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        Ok(Box::pin(
            Vault::default()
                .await
                .map_err(vault_error_to_anyhow)?
                .store(key, value),
        )
        .await
        .map_err(vault_error_to_anyhow)?)
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn nitor_vault_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(delete, m)?)?;
    m.add_function(wrap_pyfunction!(exists, m)?)?;
    m.add_function(wrap_pyfunction!(list_all, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(store, m)?)?;
    Ok(())
}
