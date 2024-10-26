use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tokio::runtime::Runtime;

use nitor_vault::errors::VaultError;
use nitor_vault::{cli, Vault};

// Retrieve version from Cargo.toml at compile time
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[pyfunction]
fn version_number() -> &'static str {
    VERSION
}

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

#[pyfunction(signature = (key, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn delete(
    key: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::delete(&vault, key).await.map_err(anyhow_to_py_err)?;

        Ok(())
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn describe(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        println!("{}", vault.stack_info());
        Ok(())
    })
}

#[pyfunction(signature = (value_positional=None, value_argument=None, file=None, outfile=None, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn decrypt(
    value_positional: Option<String>,
    value_argument: Option<String>,
    file: Option<String>,
    outfile: Option<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::decrypt(&vault, value_positional, value_argument, file, outfile)
            .await
            .map_err(anyhow_to_py_err)?;
        Ok(())
    })
}

#[pyfunction(signature = (value_positional=None, value_argument=None, file=None, outfile=None, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn encrypt(
    value_positional: Option<String>,
    value_argument: Option<String>,
    file: Option<String>,
    outfile: Option<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::encrypt(&vault, value_positional, value_argument, file, outfile)
            .await
            .map_err(anyhow_to_py_err)?;
        Ok(())
    })
}

#[pyfunction(signature = (key, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None, quiet=false))]
fn exists(
    key: &str,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
    quiet: bool,
) -> PyResult<bool> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        let exists = cli::exists(&vault, key, quiet)
            .await
            .map_err(anyhow_to_py_err)?;
        Ok(exists)
    })
}

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn info(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack, region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        println!("{vault}");
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

#[pyfunction(signature = (key, outfile=None, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None))]
fn lookup(
    key: &str,
    outfile: Option<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
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

#[pyfunction(signature = (key=None, value_positional=None, value_argument=None, file=None, overwrite=false, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None, quiet=false))]
fn store(
    key: Option<String>,
    value_positional: Option<String>,
    value_argument: Option<String>,
    file: Option<String>,
    overwrite: bool,
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

        cli::store(
            &vault,
            key,
            value_positional,
            value_argument,
            file,
            overwrite,
            quiet,
        )
        .await
        .map_err(anyhow_to_py_err)?;
        Ok(())
    })
}

#[pyfunction(signature = (name=None, vault_stack=None, region=None, bucket=None, vault_key=None, prefix=None, quiet=false))]
fn update(
    name: Option<String>,
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    vault_key: Option<String>,
    prefix: Option<String>,
    quiet: bool,
) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        let vault = Vault::new(vault_stack.or(name), region, bucket, vault_key, prefix)
            .await
            .map_err(vault_error_to_py_err)?;

        cli::update_vault_stack(&vault, quiet)
            .await
            .map_err(anyhow_to_py_err)?;
        Ok(())
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault")]
fn vault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(all, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(delete, m)?)?;
    m.add_function(wrap_pyfunction!(describe, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(exists, m)?)?;
    m.add_function(wrap_pyfunction!(id, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;
    m.add_function(wrap_pyfunction!(store, m)?)?;
    m.add_function(wrap_pyfunction!(update, m)?)?;
    m.add_function(wrap_pyfunction!(version_number, m)?)?;
    Ok(())
}
