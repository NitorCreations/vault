use nitor_vault::cloudformation::CloudFormationStackData;
use nitor_vault::errors::VaultError;
use nitor_vault::{CreateStackResult, UpdateStackResult, Value, Vault};
use pyo3::prelude::*;
use pyo3::types::{IntoPyDict, PyDict};
use tokio::runtime::Runtime;

/// Convert `VaultError` to `anyhow::Error`
fn vault_error_to_anyhow(err: VaultError) -> anyhow::Error {
    err.into()
}

/// Convert `CloudFormationStackData` to a Python dictionary.
// Lifetime annotations are required due to `&str` usage,
// could be left out if passing a `String` for result message.
fn stack_data_to_to_pydict<'a>(
    py: Python<'a>,
    data: CloudFormationStackData,
    result: &'a str,
) -> Bound<'a, PyDict> {
    let key_vals: Vec<(&str, PyObject)> = vec![
        ("result", result.to_string().to_object(py)),
        ("bucket", data.bucket_name.to_object(py)),
        ("key", data.key_arn.to_object(py)),
        (
            "status",
            data.status.map(|status| status.to_string()).to_object(py),
        ),
        ("status_reason", data.status_reason.to_object(py)),
        ("version", data.version.to_object(py)),
    ];
    key_vals.into_py_dict_bound(py)
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

#[pyfunction(signature = (data, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn direct_decrypt(
    data: &[u8],
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<Vec<u8>> {
    Runtime::new()?.block_on(async {
        let result = Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .direct_decrypt(data)
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
    })
}

#[pyfunction(signature = (data, vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn direct_encrypt(
    data: &[u8],
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<Vec<u8>> {
    Runtime::new()?.block_on(async {
        let result = Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .direct_encrypt(data)
            .await
            .map_err(vault_error_to_anyhow)?;

        Ok(result)
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
) -> PyResult<PyObject> {
    let result = Runtime::new()?.block_on(async {
        Vault::init(vault_stack, region, bucket, profile)
            .await
            .map_err(vault_error_to_anyhow)
    })?;
    Python::with_gil(|py| match result {
        CreateStackResult::Exists { data } => {
            let dict = stack_data_to_to_pydict(py, data, "EXISTS");
            Ok(dict.into())
        }
        CreateStackResult::ExistsWithFailedState { data } => {
            let dict = stack_data_to_to_pydict(py, data, "EXISTS_WITH_FAILED_STATE");
            Ok(dict.into())
        }
        CreateStackResult::Created {
            stack_name,
            stack_id,
            region,
        } => {
            let key_vals: Vec<(&str, PyObject)> = vec![
                ("result", "CREATED".to_string().to_object(py)),
                ("stack_name", stack_name.to_object(py)),
                ("stack_id", stack_id.to_object(py)),
                ("region", region.to_string().to_object(py)),
            ];
            let dict = key_vals.into_py_dict_bound(py);
            Ok(dict.into())
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

        // Binary data will get base64 encoded in the Display trait implementation
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

#[pyfunction(signature = (vault_stack=None, region=None, bucket=None, key=None, prefix=None, profile=None))]
fn stack_status(
    vault_stack: Option<String>,
    region: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    prefix: Option<String>,
    profile: Option<String>,
) -> PyResult<PyObject> {
    let data = Runtime::new()?.block_on(async {
        Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .stack_status()
            .await
            .map_err(vault_error_to_anyhow)
    })?;

    Python::with_gil(|py| {
        let dict = stack_data_to_to_pydict(py, data, "SUCCESS");
        Ok(dict.into())
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
) -> PyResult<PyObject> {
    let result = Runtime::new()?.block_on(async {
        Vault::new(vault_stack, region, bucket, key, prefix, profile)
            .await
            .map_err(vault_error_to_anyhow)?
            .update_stack()
            .await
            .map_err(vault_error_to_anyhow)
    })?;

    Python::with_gil(|py| match result {
        UpdateStackResult::UpToDate { data } => {
            let dict = stack_data_to_to_pydict(py, data, "UP_TO_DATE");
            Ok(dict.into())
        }
        UpdateStackResult::Updated {
            stack_id,
            previous_version,
            new_version,
        } => {
            let key_vals: Vec<(&str, PyObject)> = vec![
                ("result", "UPDATED".to_string().to_object(py)),
                ("stack_id", stack_id.to_object(py)),
                ("previous_version", previous_version.to_object(py)),
                ("new_version", new_version.to_object(py)),
            ];
            let dict = key_vals.into_py_dict_bound(py);
            Ok(dict.into())
        }
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn nitor_vault_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(delete, m)?)?;
    m.add_function(wrap_pyfunction!(delete_many, m)?)?;
    m.add_function(wrap_pyfunction!(direct_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(direct_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(exists, m)?)?;
    m.add_function(wrap_pyfunction!(init, m)?)?;
    m.add_function(wrap_pyfunction!(list_all, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(stack_status, m)?)?;
    m.add_function(wrap_pyfunction!(store, m)?)?;
    m.add_function(wrap_pyfunction!(update, m)?)?;
    Ok(())
}
