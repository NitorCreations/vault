use nitor_vault::{Vault};
use pyo3::prelude::*;
use tokio::runtime::Runtime;

#[pyfunction]
fn status() -> PyResult<()> {
    let rt = Runtime::new()?;

    rt.block_on(async {
        let vault = Vault::default().await.unwrap();
        let status = vault.stack_status().await.unwrap();
        println!("{status}");
        Ok(())
    })
}

#[pymodule]
fn nvault(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(status, m)?)?;
    Ok(())
}
