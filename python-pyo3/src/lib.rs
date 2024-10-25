use std::path::Path;

use nitor_vault::errors::VaultError;
use nitor_vault::{cli, Vault};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tokio::runtime::Runtime;

/// Convert `anyhow::Error` to `PyErr` for PyO3
fn anyhow_to_py_err(err: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(format!("Error: {}", err))
}

/// Convert `VaultError` to `PyErr` for PyO3
fn vault_error_to_py_err(err: VaultError) -> PyErr {
    PyRuntimeError::new_err(format!("Error: {}", err))
}

#[pyfunction]
fn all() -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::default()
            .await
            .map_err(|e| vault_error_to_py_err(e))?;
        cli::list_all_keys(&vault)
            .await
            .map_err(|e| anyhow_to_py_err(e))?;

        Ok(())
    })
}

#[pyfunction]
#[pyo3(signature = (key, outfile=None))]
fn lookup(key: &str, outfile: Option<&str>) -> PyResult<()> {
    let rt = Runtime::new().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Runtime creation failed: {e}"))
    })?;

    rt.block_on(async {
        let vault = Vault::default().await.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Vault initialization failed: {e}",
            ))
        })?;
        let result = Box::pin(vault.lookup(key)).await.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to lookup key '{key}': {e}",
            ))
        })?;
        if let Some(path) = outfile {
            let path = Path::new(path);
            result.output_to_file(path).map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to output value: {e}"
                ))
            })?;
        } else {
            result.output_to_stdout().map_err(|e| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                    "Failed to print value: {e}"
                ))
            })?;
        }
        Ok(())
    })
}

#[pyfunction]
fn status() -> PyResult<()> {
    let rt = Runtime::new().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Runtime creation failed: {e}"))
    })?;

    rt.block_on(async {
        let vault = Vault::default().await.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Vault initialization failed: {e}",
            ))
        })?;
        let status = vault.stack_status().await.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Fetching stack status failed: {e}",
            ))
        })?;
        println!("{status}");
        Ok(())
    })
}

#[pyfunction(signature = (region=None))]
fn id(region: Option<String>) -> PyResult<()> {
    let rt = Runtime::new().map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Runtime creation failed: {e}"))
    })?;

    rt.block_on(async {
        let config = nitor_vault::get_aws_config(region).await;
        let client = nitor_vault::aws_sts_client(&config);
        let result = client.get_caller_identity().send().await.map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!(
                "Failed to get caller identity: {e}",
            ))
        })?;
        println!(
            "user: {}\naccount: {}\narn: {}",
            result.user_id.unwrap_or_else(|| "None".to_string()),
            result.account.unwrap_or_else(|| "None".to_string()),
            result.arn.unwrap_or_else(|| "None".to_string())
        );
        Ok(())
    })
}

#[pymodule]
fn nvault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(all, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(id, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;
    Ok(())
}
