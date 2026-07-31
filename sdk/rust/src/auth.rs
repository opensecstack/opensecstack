use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// A cached JWT access token with its expiry timestamp.
#[derive(Debug, Clone)]
pub(crate) struct CachedToken {
    pub access_token: String,
    /// UNIX timestamp (seconds) at which the token expires.
    pub expires_at: u64,
}

impl CachedToken {
    /// Returns `true` when the token is still valid with at least a 60-second
    /// safety buffer before the server-side expiry.
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now + 60 < self.expires_at
    }
}

/// Thread-safe token store. `None` means "not yet authenticated".
pub(crate) type TokenCache = Mutex<Option<CachedToken>>;

/// Parses the `exp` claim from a JWT's payload (URL-safe base64, no padding).
/// Returns `None` on any parse failure — callers should fall back to a fixed TTL.
pub(crate) fn parse_jwt_exp(token: &str) -> Option<u64> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("exp")?.as_u64()
}
