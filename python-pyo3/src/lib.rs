use pyo3::prelude::*;
use tokio::runtime::Runtime;

use nitor_vault::errors::VaultError;
use nitor_vault::{cli, Vault};

// Retrieve version from Cargo.toml at compile time
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[pyfunction]
const fn version() -> &'static str {
    VERSION
}

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
}

// These signatures can be removed in a future version since these are all required arguments
// https://github.com/PyO3/pyo3/blob/main/guide/src/function/signature.md#trailing-optional-arguments
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
            .map_err(vault_error_to_anyhow)?;

        cli::list_all_keys(&vault).await?;
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
            .map_err(vault_error_to_anyhow)?;

        cli::delete(&vault, key).await?;
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
            .map_err(vault_error_to_anyhow)?;

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
            .map_err(vault_error_to_anyhow)?;

        cli::decrypt(&vault, value_positional, value_argument, file, outfile).await?;
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
            .map_err(vault_error_to_anyhow)?;

        cli::encrypt(&vault, value_positional, value_argument, file, outfile).await?;
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
            .map_err(vault_error_to_anyhow)?;

        let exists = cli::exists(&vault, key, quiet).await?;
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
            .map_err(vault_error_to_anyhow)?;

        println!("{vault}");
        Ok(())
    })
}

#[pyfunction(signature = (region=None, quiet=false))]
fn id(region: Option<String>, quiet: bool) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        cli::print_aws_account_id(region, quiet).await?;
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
        cli::init_vault_stack(vault_stack.or(name), region, bucket, quiet).await?;
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
            .map_err(vault_error_to_anyhow)?;

        cli::lookup(&vault, key, outfile).await?;

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
            .map_err(vault_error_to_anyhow)?;

        let status = vault.stack_status().await.map_err(vault_error_to_anyhow)?;
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
            .map_err(vault_error_to_anyhow)?;

        cli::store(
            &vault,
            key,
            value_positional,
            value_argument,
            file,
            overwrite,
            quiet,
        )
        .await?;
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
            .map_err(vault_error_to_anyhow)?;

        cli::update_vault_stack(&vault, quiet).await?;
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
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
