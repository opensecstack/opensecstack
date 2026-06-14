use pyo3::prelude::*;

pub mod engine;
pub mod result;
pub mod spec;

use engine::PayloadEngine;
use result::PayloadResult;
use spec::PayloadSpec;

#[pymodule]
fn payload_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PayloadEngine>()?;
    m.add_class::<PayloadSpec>()?;
    m.add_class::<PayloadResult>()?;
    Ok(())
}
