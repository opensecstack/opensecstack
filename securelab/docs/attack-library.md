# Attack Library

SecureLab ships 15 built-in attack types. Each maps to one or more MITRE ATT&CK techniques and is used as a `kind` value in scenario YAML files.

## Attack Types

| # | Kind | MITRE Technique | Description | Configurable Params | Expected Detections |
|---|---|---|---|---|---|
| 1 | `bola` | T1078 — Valid Accounts | BOLA via sequential integer ID or UUID enumeration on REST object endpoints. Low-privilege token accesses resources owned by other users. | `endpoint`, `id_type`, `id_range`, `uuid_count`, `auth_token_param` | APIGuard OWASP A1 alert; OpenScrub anomalous access pattern |
| 2 | `jwt_none` | T1078.001 — Default Accounts | JWT `alg:none` bypass. Strips signature and sets algorithm to `none` to impersonate any user. | `endpoint`, `original_token_param`, `claims_override` | APIGuard JWT validation alert; OpenScrub auth anomaly |
| 3 | `jwt_brute` | T1110.001 — Password Guessing | JWT weak secret brute force. Iterates a wordlist to forge a valid HS256 token. | `endpoint`, `wordlist`, `algorithm`, `claims_template` | APIGuard brute force detection; ThreatFlow IOC match on source IP |
| 4 | `mass_assignment` | T1548 — Abuse Elevation Control Mechanism | Mass assignment targeting privilege fields. Injects `role`, `is_admin`, or similar into update requests. | `endpoint`, `method`, `base_payload`, `injected_fields` | APIGuard OWASP A3 alert; OpenScrub privilege escalation pattern |
| 5 | `ssrf` | T1552.005 — Cloud Instance Metadata API | SSRF to internal endpoints. Default target: AWS IMDSv1 at `169.254.169.254`. | `endpoint`, `url_param`, `target_url`, `follow_redirects` | APIGuard SSRF detection; ThreatFlow IOC on metadata endpoint |
| 6 | `rate_limit_bypass` | T1110 — Brute Force | Rate limit bypass via `X-Forwarded-For` and similar headers to cycle through fake IPs. | `endpoint`, `request_count`, `rotation_headers`, `ip_pool_size` | APIGuard rate limit bypass alert; OpenScrub header anomaly |
| 7 | `syn_flood` | T1498.001 — Direct Network Flood | SYN flood at configurable PPS rate. Tests DoS detection thresholds. | `target_port`, `packets_per_second`, `duration`, `source_ip_spoof` | ThreatFlow DoS IOC; network IDS SYN flood signature |
| 8 | `udp_flood` | T1498.001 — Direct Network Flood | UDP flood simulation. Tests volumetric DDoS detection. | `target_port`, `packets_per_second`, `packet_size_bytes`, `duration` | ThreatFlow DoS IOC; network IDS UDP flood signature |
| 9 | `http_flood` | T1499.002 — Service Exhaustion Flood | HTTP application-layer flood with configurable concurrency and rate. | `endpoint`, `concurrency`, `duration`, `requests_per_second` | APIGuard HTTP flood detection; OpenScrub request surge alert |
| 10 | `slowloris` | T1499.002 — Service Exhaustion Flood | Slowloris holds connections open by sending partial HTTP headers at long intervals. | `target_port`, `connection_count`, `send_interval`, `duration` | Network IDS Slowloris signature; OpenScrub connection exhaustion alert |
| 11 | `port_scan` | T1046 — Network Service Discovery | TCP or UDP port scan over a configurable port range. | `port_range`, `protocol`, `concurrency`, `timeout_per_port` | ThreatFlow network scan IOC; IDS port scan detection |
| 12 | `api_enum` | T1595.003 — Wordlist Scanning | API endpoint enumeration using a built-in or custom wordlist. | `base_path`, `wordlist`, `methods`, `concurrency` | APIGuard enumeration alert; OpenScrub 404 surge detection |
| 13 | `auth_bypass` | T1078.001 — Default Accounts | Generic authentication bypass wrapper. Delegates to a specific technique (`jwt_none`, etc.). | `endpoint`, `bypass_technique`, `original_token_param`, `claims_override` | APIGuard auth bypass alert |
| 14 | `data_exfil` | T1041 — Exfiltration Over C2 Channel | Data exfiltration simulation — calls an export endpoint with a privileged token. | `endpoint`, `method`, `auth_token_param`, `expected_data_fields` | OpenScrub data exfiltration pattern; ThreatFlow exfil IOC |
| 15 | `fuzzer` | T1190 — Exploit Public-Facing Application | Sends mutated/fuzzed request bodies to an endpoint to probe for parsing vulnerabilities. Uses the Rust payload generator for mutation. | `endpoint`, `base_payload`, `iterations`, `mutation_strategies` | APIGuard WAF alert; OpenScrub malformed request pattern |

## Notes

- All attacks run inside an isolated Docker test environment. They never reach production systems.
- The `fuzzer` kind uses the `rust/payload-gen` crate for payload mutation via the `generate_bola_payloads`, `mutate`, and encoder functions.
- Detection expectations listed above are the alerts SecureLab will assert when running detection validation. A missing alert is recorded as a detection gap.
- MITRE technique IDs reference ATT&CK v14+. Sub-technique IDs (e.g. `T1078.001`) are used where applicable.
