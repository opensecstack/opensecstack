//! VertGuard prompt-injection pattern-matching engine.
//!
//! STATUS: Phase 4.1 scaffold. The `Engine::scan` API surface is
//! stable; pattern population lands across Phase 4.1 releases.
//!
//! See `docs/module-3-prompt-injection.md` for the design and
//! `docs/owasp-llm-top10-coverage.md` for the target coverage matrix.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Scan result — a collection of matches plus aggregated confidence.
///
/// The Go orchestrator maps `matches[i].confidence` through its
/// scoring layer and produces the final classification
/// (CLEAN / SUSPICIOUS / BLOCKED). The Rust engine is stateless over
/// pattern semantics — it surfaces what matched and leaves the
/// "so what" to the caller.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScanResult {
    pub matches: Vec<PatternMatch>,
}

/// A single pattern match within the scanned input.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PatternMatch {
    pub pattern_id:    String,
    pub category:      String,      // e.g. "OWASP-LLM01"
    pub description:   String,
    pub byte_range:    (usize, usize),
    pub confidence:    f32,          // 0.0..1.0
    pub atlas_technique: Option<String>,
}

/// OWASP LLM Top 10 categories.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum OwaspCategory {
    LLM01, LLM02, LLM03, LLM04, LLM05,
    LLM06, LLM07, LLM08, LLM09, LLM10,
    Custom,
}

impl OwaspCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            OwaspCategory::LLM01 => "OWASP-LLM01",
            OwaspCategory::LLM02 => "OWASP-LLM02",
            OwaspCategory::LLM03 => "OWASP-LLM03",
            OwaspCategory::LLM04 => "OWASP-LLM04",
            OwaspCategory::LLM05 => "OWASP-LLM05",
            OwaspCategory::LLM06 => "OWASP-LLM06",
            OwaspCategory::LLM07 => "OWASP-LLM07",
            OwaspCategory::LLM08 => "OWASP-LLM08",
            OwaspCategory::LLM09 => "OWASP-LLM09",
            OwaspCategory::LLM10 => "OWASP-LLM10",
            OwaspCategory::Custom => "CUSTOM",
        }
    }
}

/// Engine is the pattern-matching entry point.
pub struct Engine {
    // TODO(phase-4.1): load patterns from YAML registry + compile
    // regex/AC automata at construction time.
    _placeholder: (),
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Create a new engine with the default pattern library.
    ///
    /// TODO(phase-4.1): replace with `new_from_registry(path)` that
    /// loads patterns from the YAML registry.
    pub fn new() -> Self {
        Self { _placeholder: () }
    }

    /// Scan an input string against the loaded pattern library.
    ///
    /// TODO(VG-003): this crate is a PLACEHOLDER. The Go-native
    /// `internal/prompt` package is the production implementation for
    /// Module 3 in v0.1.0-alpha.x. This Rust port is tracked as a
    /// future hot-path optimisation; do NOT rely on the result of
    /// this method — it always returns an empty `ScanResult` and will
    /// silently miss every injection pattern.
    ///
    /// See `docs/module-3-prompt-injection.md` for the production
    /// engine; this crate ships compiled solely so downstream Rust
    /// consumers can lock in the API surface.
    pub fn scan(&self, _input: &str) -> Result<ScanResult, ScanError> {
        // TODO(VG-003): wire to the YAML pattern registry + compile
        // regex/AC automata at construction time, then evaluate here.
        Ok(ScanResult::default())
    }
}

/// Errors returned by the scan engine.
#[derive(Debug, Error)]
pub enum ScanError {
    #[error("input exceeds maximum size of {0} bytes")]
    InputTooLarge(usize),

    #[error("pattern library not loaded")]
    NotInitialised,

    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_empty_result() {
        let engine = Engine::new();
        let result = engine.scan("").expect("scan failed");
        assert!(result.matches.is_empty());
    }

    #[test]
    fn engine_constructs_cleanly() {
        let _e = Engine::new();
    }

    // TODO(phase-4.1): add tests as patterns come online:
    //   - instruction_override variations
    //   - jailbreak pattern set
    //   - indirect injection cases
    //   - false-positive corpus (/tests/fp)
}
