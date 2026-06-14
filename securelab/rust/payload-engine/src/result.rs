use pyo3::prelude::*;

#[pyclass]
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct PayloadResult {
    #[pyo3(get)]
    pub payload_id: String,
    #[pyo3(get)]
    pub bytes: Vec<u8>,
    #[pyo3(get)]
    pub technique_id: String,
    #[pyo3(get)]
    pub checksum_sha256: String,
}

#[pymethods]
impl PayloadResult {
    #[new]
    pub fn new(
        payload_id: String,
        bytes: Vec<u8>,
        technique_id: String,
        checksum_sha256: String,
    ) -> Self {
        PayloadResult {
            payload_id,
            bytes,
            technique_id,
            checksum_sha256,
        }
    }
}
