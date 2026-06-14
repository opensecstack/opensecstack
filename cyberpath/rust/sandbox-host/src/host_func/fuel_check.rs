// Fuel budget enforcement.
//
// wasmtime's fuel mechanism deducts one unit per Wasm instruction.
// When fuel reaches zero the instance traps with OutOfFuel.  The host
// sets the per-command fuel budget in Store::add_fuel before invoking
// the module's export; this module provides helpers to inspect and
// report remaining fuel.
//
// TODO(v1.0.0): call check_fuel() before each guest function invocation
// and surface FuelExhausted as a clean session error (not a host panic).

use anyhow::{bail, Result};

/// Minimum fuel level considered "safe to proceed".
/// Below this threshold the host proactively refuses new commands
/// rather than letting the guest trap mid-execution.
const FUEL_RESERVE_THRESHOLD: u64 = 1_000;

/// Checks whether `remaining_fuel` is above the safety threshold.
/// Returns Ok(()) if the session may proceed, Err if fuel is exhausted.
pub fn check_fuel(remaining_fuel: u64) -> Result<()> {
    if remaining_fuel < FUEL_RESERVE_THRESHOLD {
        bail!(
            "fuel exhausted: {} units remaining (threshold {})",
            remaining_fuel,
            FUEL_RESERVE_THRESHOLD
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuel_ok_above_threshold() {
        assert!(check_fuel(1_000_000).is_ok());
    }

    #[test]
    fn fuel_error_at_zero() {
        assert!(check_fuel(0).is_err());
    }

    #[test]
    fn fuel_error_below_threshold() {
        assert!(check_fuel(FUEL_RESERVE_THRESHOLD - 1).is_err());
    }

    #[test]
    fn fuel_ok_at_exact_threshold() {
        assert!(check_fuel(FUEL_RESERVE_THRESHOLD).is_ok());
    }

    #[test]
    fn fuel_ok_far_above_threshold() {
        assert!(check_fuel(u64::MAX / 2).is_ok());
    }

    #[test]
    fn fuel_error_message_contains_remaining_units() {
        let err = check_fuel(42).unwrap_err();
        assert!(
            err.to_string().contains("42"),
            "error message must include remaining fuel count: {err}"
        );
    }

    #[test]
    fn fuel_error_message_contains_threshold() {
        let err = check_fuel(0).unwrap_err();
        assert!(
            err.to_string().contains(&FUEL_RESERVE_THRESHOLD.to_string()),
            "error message must include threshold: {err}"
        );
    }
}
