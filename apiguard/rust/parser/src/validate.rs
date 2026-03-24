use crate::error::ParseError;
use crate::ir::ApiGuardIR;

/// Validate the IR before returning it to callers.
///
/// Checks:
/// - At least one endpoint exists
/// - All security references on endpoints resolve to a defined auth scheme
/// - base_url is parseable as a URL (or relative path)
pub fn validate_ir(ir: &ApiGuardIR) -> Result<(), ParseError> {
    let mut errors = Vec::new();

    // Must have at least one endpoint.
    if ir.endpoints.is_empty() {
        errors.push("schema defines no endpoints (paths is empty)".to_string());
    }

    // Collect all auth scheme names.
    let scheme_names: std::collections::HashSet<&str> = ir
        .auth_schemes
        .iter()
        .map(|s| s.name.as_str())
        .collect();

    // Verify every endpoint's security references resolve.
    for ep in &ir.endpoints {
        for sec in &ep.security {
            if !scheme_names.contains(sec.as_str()) {
                errors.push(format!(
                    "endpoint {} {} references undefined security scheme `{sec}`",
                    ep.method_str(),
                    ep.path
                ));
            }
        }
    }

    // Validate base_url is parseable (allow relative paths like "/api/v1").
    if !ir.metadata.base_url.is_empty() && !ir.metadata.base_url.starts_with('/') {
        if url::Url::parse(&ir.metadata.base_url).is_err() {
            errors.push(format!(
                "base_url `{}` is not a valid URL",
                ir.metadata.base_url
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ParseError::InvalidSchema { errors })
    }
}

impl crate::ir::Endpoint {
    /// Helper to get method as a string (for error messages).
    pub fn method_str(&self) -> &'static str {
        match self.method {
            crate::ir::HttpMethod::Get => "GET",
            crate::ir::HttpMethod::Post => "POST",
            crate::ir::HttpMethod::Put => "PUT",
            crate::ir::HttpMethod::Patch => "PATCH",
            crate::ir::HttpMethod::Delete => "DELETE",
            crate::ir::HttpMethod::Head => "HEAD",
            crate::ir::HttpMethod::Options => "OPTIONS",
        }
    }
}
