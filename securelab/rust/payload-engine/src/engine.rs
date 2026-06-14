use pyo3::prelude::*;

use crate::result::PayloadResult;
use crate::spec::PayloadSpec;

#[pyclass]
pub struct PayloadEngine {}

#[pymethods]
impl PayloadEngine {
    #[new]
    pub fn new() -> Self {
        PayloadEngine {}
    }

    pub fn generate(&self, spec: &PayloadSpec) -> PyResult<PayloadResult> {
        let _ = spec;
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "payload generation lands in v1.0.0",
        ))
    }

    pub fn mutate(&self, payload: Vec<u8>, strategy: &str) -> PyResult<Vec<u8>> {
        let _ = (payload, strategy);
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "payload mutation lands in v1.0.0",
        ))
    }
}
