// Host function registry.
// Each sub-module registers a group of host-callable functions with
// the wasmtime Linker.  In v1.0.0 these are real enforcement points;
// the current skeleton contains the module structure and deny-by-default
// stubs with TODO markers.

pub mod fs_sandbox;
pub mod fuel_check;
pub mod network_deny;
