use pyo3::prelude::*;

#[pyclass]
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PayloadSpec {
    #[pyo3(get, set)]
    pub technique_id: String,
    #[pyo3(get, set)]
    pub target: String,
    #[pyo3(get, set)]
    pub parameters: String,
}

#[pymethods]
impl PayloadSpec {
    #[new]
    pub fn new(technique_id: String, target: String, parameters: String) -> Self {
        PayloadSpec {
            technique_id,
            target,
            parameters,
        }
    }
}
