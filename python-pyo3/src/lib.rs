use pyo3::prelude::*;
use tokio::runtime::Runtime;

#[pyfunction]
fn run(args: Vec<String>) -> PyResult<()> {
    Runtime::new()?.block_on(async {
        nitor_vault::run_cli_with_args(args).await?;
        Ok(())
    })
}

#[pymodule]
#[pyo3(name = "nitor_vault_rs")]
fn vault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run, m)?)?;
    Ok(())
}
