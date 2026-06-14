# MITRE ATT&CK Mapping

Full mapping of SecureLab attack kinds to MITRE ATT&CK techniques (ATT&CK v14+).

## Mapping Table

| Attack Kind | MITRE Technique ID | MITRE Technique Name | Tactic | Notes |
|---|---|---|---|---|
| `bola` | T1078 | Valid Accounts | Initial Access, Privilege Escalation | Abuses valid but low-privilege credentials to access unauthorized objects |
| `jwt_none` | T1078.001 | Default Accounts | Initial Access | Exploits a JWT implementation flaw to impersonate any account |
| `jwt_brute` | T1110.001 | Password Guessing | Credential Access | Brute-forces the HMAC signing secret to forge tokens |
| `mass_assignment` | T1548 | Abuse Elevation Control Mechanism | Privilege Escalation | Injects privileged fields into API update requests |
| `ssrf` | T1552.005 | Cloud Instance Metadata API | Credential Access | Coerces the server to access internal cloud metadata |
| `rate_limit_bypass` | T1110 | Brute Force | Credential Access | Evades per-IP rate limits via header manipulation |
| `syn_flood` | T1498.001 | Direct Network Flood | Impact | Exhausts TCP connection resources |
| `udp_flood` | T1498.001 | Direct Network Flood | Impact | Volumetric UDP flood |
| `http_flood` | T1499.002 | Service Exhaustion Flood | Impact | Application-layer HTTP flood |
| `slowloris` | T1499.002 | Service Exhaustion Flood | Impact | Holds connections open via partial HTTP headers |
| `port_scan` | T1046 | Network Service Discovery | Discovery | Maps open ports and services |
| `api_enum` | T1595.003 | Wordlist Scanning | Reconnaissance | Discovers undocumented API endpoints |
| `auth_bypass` | T1078.001 | Default Accounts | Initial Access | Generic wrapper for authentication bypass techniques |
| `data_exfil` | T1041 | Exfiltration Over C2 Channel | Exfiltration | Simulates bulk data export from a compromised privileged session |
| `fuzzer` | T1190 | Exploit Public-Facing Application | Initial Access | Sends malformed/mutated payloads to probe for parsing vulnerabilities |

## Tactic Coverage

| Tactic | Coverage |
|---|---|
| Reconnaissance | `api_enum`, `port_scan` |
| Initial Access | `bola`, `jwt_none`, `auth_bypass`, `fuzzer` |
| Credential Access | `jwt_brute`, `ssrf`, `rate_limit_bypass` |
| Privilege Escalation | `bola`, `mass_assignment` |
| Discovery | `port_scan` |
| Exfiltration | `data_exfil` |
| Impact | `syn_flood`, `udp_flood`, `http_flood`, `slowloris` |

## Notes

- Sub-technique IDs (e.g. `T1078.001`) are used in scenario YAML `mitre_technique_ids` fields where applicable.
- Multi-stage scenarios (e.g. `apt-simulation`, `full-kill-chain`) reference multiple technique IDs and cover multiple tactics.
- The MITRE ATT&CK coverage report (available at `GET /api/v1/coverage`) shows which techniques have been executed and whether detections were confirmed.
