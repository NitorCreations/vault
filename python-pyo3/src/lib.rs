use nitor_vault::errors::VaultError;
use nitor_vault::{Value, Vault};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
}

#[pyfunction]
fn run(args: Vec<String>) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        nitor_vault::run_cli_with_args(args).await?;
        Ok(())
    })
}

#[pyfunction]
fn lookup(name: &str) -> PyResult<String> {
    Runtime::new()?.block_on(async {
        let result: Value = Vault::default()
            .await
            .map_err(vault_error_to_anyhow)?
            .lookup(name)
            .map_err(vault_error_to_anyhow)?;

        Ok(result.to_string())
    })
}

#[pyfunction]
fn list_all() -> PyResult<Vec<String>> {
    Runtime::new()?.block_on(async {
        let result = Vault::default()
            .await
            .map_err(vault_error_to_anyhow)?
            .all()
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(list_all, m)?)?;
    Ok(())
}
