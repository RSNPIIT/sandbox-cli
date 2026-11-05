use pyo3::prelude::*;

#[pyfunction]
fn version() -> PyResult<String> {
    Ok("sandbox_engine v0.1.0 (Rust Engine)".to_string())
}

#[pymodule]
fn sandbox_engine(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
