// Network egress enforcement.
//
// In v1.0.0 all outbound network is denied by default.  Labs that
// legitimately need egress (see docs/wasm-sandbox.md §Network egress
// whitelist) will have network_allow = true in their CapabilityBag and
// an explicit egress allowlist.
//
// TODO(v1.0.0): Intercept wasi:sockets/0.2.0 calls from the guest and
// either deny them (network_allow = false) or forward through the
// host-side proxy (network_allow = true + egress whitelist check).

/// Loopback and meta-addresses that are always denied, regardless of
/// `network_allow`, to prevent SSRF into the host network namespace.
const BLOCKED_HOSTS: &[&str] = &[
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "localhost",
    "::ffff:127.0.0.1",
];

/// Returns true if the connection to `host`:`port` is permitted by the
/// capability bag.
///
/// When `network_allow` is false the connection is always denied.
/// When `network_allow` is true loopback and wildcard addresses are still
/// denied; all other hosts are permitted (per-host granularity is enforced
/// at the host-side proxy layer via `CapabilityBag::egress_whitelist`).
pub fn is_egress_allowed(host: &str, port: u16, network_allow: bool) -> bool {
    if !network_allow {
        tracing::warn!(host, port, "network_deny: egress blocked (network_allow=false)");
        return false;
    }
    if BLOCKED_HOSTS.contains(&host) {
        tracing::warn!(host, port, "network_deny: loopback/meta-address blocked");
        return false;
    }
    tracing::info!(host, port, "network_deny: egress permitted");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── network_allow = false: all egress blocked ─────────────────────

    #[test]
    fn egress_denied_when_network_allow_false() {
        assert!(!is_egress_allowed("example.com", 443, false));
    }

    #[test]
    fn egress_denied_dns_port_no_network() {
        assert!(!is_egress_allowed("8.8.8.8", 53, false));
    }

    #[test]
    fn egress_denied_arbitrary_port_no_network() {
        assert!(!is_egress_allowed("taxii.lab.opensecstack.io", 8080, false));
    }

    // ── network_allow = true: loopback always blocked ─────────────────

    #[test]
    fn loopback_ipv4_blocked_even_with_network_allow() {
        assert!(!is_egress_allowed("127.0.0.1", 8080, true));
    }

    #[test]
    fn loopback_ipv6_blocked_even_with_network_allow() {
        assert!(!is_egress_allowed("::1", 8080, true));
    }

    #[test]
    fn localhost_blocked_even_with_network_allow() {
        assert!(!is_egress_allowed("localhost", 5432, true));
    }

    #[test]
    fn all_interfaces_blocked_even_with_network_allow() {
        assert!(!is_egress_allowed("0.0.0.0", 80, true));
    }

    // ── network_allow = true: legitimate external host allowed ────────

    #[test]
    fn external_host_allowed_when_network_allow_true() {
        assert!(is_egress_allowed("taxii.lab.opensecstack.io", 443, true));
    }

    #[test]
    fn external_ip_allowed_when_network_allow_true() {
        assert!(is_egress_allowed("8.8.8.8", 53, true));
    }
}
