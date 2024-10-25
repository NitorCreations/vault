use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use nitor_vault::errors::VaultError;
use nitor_vault::{cli, Vault};

/// Convert `anyhow::Error` to `PyErr` for PyO3
fn anyhow_to_py_err(err: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(format!("{err:?}"))
}

/// Convert `VaultError` to `PyErr` for PyO3
fn vault_error_to_py_err(err: VaultError) -> PyErr {
    let anyhow_error: anyhow::Error = err.into();
    PyRuntimeError::new_err(format!("{anyhow_error:?}"))
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, key=None, prefix=None))]
fn all(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::list_all_keys(&vault).await.map_err(anyhow_to_py_err)?;

        Ok(())
    })
}

#[pyfunction(signature = (region=None, quiet=false))]
fn id(region: Option<String>, quiet: bool) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        cli::get_aws_account_id(region, quiet)
            .await
            .map_err(anyhow_to_py_err)?;
        Ok(())
    })
}

#[pyfunction(signature = (name=None, vault_stack=None, region=None, bucket=None, quiet=false))]
fn init(
    name: Option<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    quiet: bool,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        cli::init_vault_stack(vault_stack.or(name), region, bucket, quiet)
            .await
            .map_err(anyhow_to_py_err)?;

        Ok(())
    })
}

#[pyfunction(signature = (key, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None, outfile=None))]
fn lookup(
    key: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
    outfile: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::lookup(&vault, key, outfile)
            .await
            .map_err(anyhow_to_py_err)?;

        Ok(())
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None, quiet=false))]
fn status(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
    quiet: bool,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        let status = vault.stack_status().await.map_err(vault_error_to_py_err)?;

        if !quiet {
            println!("{status}");
        }

        Ok(())
    })
}

#[pymodule]
fn nvault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(all, m)?)?;
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(id, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;
    Ok(())
}
