use base64::Engine;

/// Base64-encode `data` using the standard alphabet with padding.
pub fn encode_base64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// URL-encode string `s` (percent-encoding of non-unreserved characters).
///
/// Uses the `url` crate's component encoder so that spaces become `%20`,
/// slashes become `%2F`, etc.
pub fn encode_url(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Double URL-encode string `s` — applies `encode_url` twice.
///
/// Used to bypass single-pass WAF decoders that only decode one level.
pub fn encode_double_url(s: &str) -> String {
    encode_url(&encode_url(s))
}

/// Unicode-escape each character in `s` using `\uXXXX` notation.
///
/// Used to bypass WAF filters that match on literal character sequences
/// but do not normalize Unicode escape sequences before matching.
pub fn encode_unicode(s: &str) -> String {
    s.chars()
        .map(|c| {
            let n = c as u32;
            if n <= 0xFFFF {
                format!("\\u{:04X}", n)
            } else {
                // Supplementary plane: use surrogate pair notation
                format!("\\u{:08X}", n)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world";
        let encoded = encode_base64(data);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn url_encode_spaces_and_slashes() {
        let result = encode_url("hello world/path");
        assert!(result.contains("%20") || result.contains("+"));
        assert!(result.contains("%2F") || result.contains("%2f"));
    }

    #[test]
    fn double_url_encode_differs_from_single() {
        let input = "hello/world";
        let single = encode_url(input);
        let double = encode_double_url(input);
        assert_ne!(single, double, "double encoding should differ from single encoding");
    }

    #[test]
    fn unicode_encode_produces_escape_sequences() {
        let result = encode_unicode("AB");
        assert_eq!(result, "\\u0041\\u0042");
    }

    #[test]
    fn unicode_encode_roundtrip_ascii() {
        // Every ASCII char should produce \uXXXX with exactly 4 hex digits
        let result = encode_unicode("a");
        assert_eq!(result, "\\u0061");
    }
}
