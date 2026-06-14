# Scenario Specification

This document defines the full YAML scenario format used by SecureLab.

## Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique scenario identifier. Lowercase, hyphen-separated. |
| `description` | string | yes | Human-readable description of what the scenario tests. |
| `mitre_technique_ids` | string[] | yes | One or more MITRE ATT&CK technique IDs (e.g. `T1078`, `T1078.001`). |
| `tags` | string[] | no | Free-form tags for filtering and categorization. |
| `severity` | enum | yes | `low`, `medium`, `high`, or `critical`. |
| `timeout` | duration | yes | Maximum wall-clock time for the entire scenario (e.g. `5m`, `30s`). |
| `steps` | Step[] | yes | Ordered list of attack steps. Executed sequentially. |

## Step fields

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | yes | Attack type. See step kinds below. |
| `name` | string | no | Human-readable step label used in run reports. |
| `params` | object | yes | Parameters for the step kind. See per-kind reference below. |
| `timeout` | duration | no | Per-step timeout. Overrides scenario-level default. |
| `on_failure` | enum | no | `stop` (default) or `continue`. |

## Step kinds and parameters

### `bola`

Broken Object Level Authorization — attempts to access objects belonging to other users.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path with `{id}` placeholder. |
| `id_type` | enum | `integer` (default) or `uuid`. |
| `id_range` | [int, int] | Start and end for integer enumeration. |
| `uuid_count` | int | Number of random UUIDs to try (when `id_type: uuid`). |
| `auth_token_param` | string | Name of the JWT parameter from the environment context. |
| `expected_leak_field` | string | Response field that indicates unauthorized access. |

### `jwt_none`

JWT `alg:none` bypass — strips the signature and sets algorithm to `none`.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path to test. |
| `original_token_param` | string | Name of the JWT parameter from context. |
| `claims_override` | object | Claims to inject into the forged token. |
| `expected_bypass` | bool | Whether a successful bypass is expected. |

### `jwt_brute`

JWT weak secret brute force — attempts to forge a valid signature from a wordlist.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path to test. |
| `wordlist` | string[] | List of secrets to try. |
| `algorithm` | string | JWT algorithm (e.g. `HS256`). |
| `claims_template` | object | Claims for the forged token. |
| `success_indicator.status_code` | int | HTTP status that indicates success. |

### `mass_assignment`

Mass assignment — injects extra fields into an update request.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path. |
| `method` | string | HTTP method (`PUT`, `PATCH`, `POST`). |
| `base_payload` | object | Legitimate fields to include. |
| `injected_fields` | object | Privileged fields to attempt injecting. |
| `auth_token_param` | string | JWT parameter name. |
| `success_indicator.response_contains` | string | Substring that indicates privilege escalation succeeded. |

### `ssrf`

Server-Side Request Forgery — coerces the server into making an internal request.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path of the vulnerable endpoint. |
| `url_param` | string | Request parameter that accepts a URL. |
| `target_url` | string | Internal URL to attempt to reach. |
| `auth_token_param` | string | JWT parameter name. |
| `follow_redirects` | bool | Whether to follow HTTP redirects. |
| `expected_leak_indicator` | string | Substring in response indicating SSRF success. |

### `rate_limit_bypass`

Rate limit bypass via IP spoofing headers.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path. |
| `method` | string | HTTP method. |
| `request_count` | int | Total requests to send. |
| `rotation_headers` | string[] | Headers to rotate for IP spoofing. |
| `ip_pool_size` | int | Number of distinct fake IPs to cycle through. |
| `payload` | object | Request body. |
| `success_indicator.min_requests_through` | int | Minimum requests that must succeed. |

### `syn_flood`

SYN flood denial-of-service simulation.

| Param | Type | Description |
|---|---|---|
| `target_port` | int | TCP port to flood. |
| `packets_per_second` | int | Desired packet rate. |
| `duration` | duration | How long to run the flood. |
| `source_ip_spoof` | bool | Whether to spoof source IPs. |
| `source_ip_range` | string | CIDR range for spoofed IPs. |

### `udp_flood`

UDP flood simulation.

| Param | Type | Description |
|---|---|---|
| `target_port` | int | UDP port to flood. |
| `packets_per_second` | int | Desired packet rate. |
| `packet_size_bytes` | int | Payload size per packet. |
| `duration` | duration | How long to run the flood. |
| `payload_type` | enum | `random` or `zeros`. |

### `http_flood`

HTTP application-layer flood.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path to flood. |
| `method` | string | HTTP method. |
| `concurrency` | int | Number of concurrent goroutines. |
| `duration` | duration | How long to run. |
| `requests_per_second` | int | Target rate. |
| `randomize_user_agent` | bool | Rotate User-Agent headers. |

### `slowloris`

Slowloris connection exhaustion.

| Param | Type | Description |
|---|---|---|
| `target_port` | int | TCP port. |
| `connection_count` | int | Number of connections to hold open. |
| `send_interval` | duration | How often to send partial headers to keep connections alive. |
| `duration` | duration | Total attack duration. |

### `port_scan`

TCP port scan.

| Param | Type | Description |
|---|---|---|
| `port_range` | [int, int] | Start and end port. |
| `protocol` | string | `tcp` or `udp`. |
| `concurrency` | int | Number of concurrent probes. |
| `timeout_per_port` | duration | Per-port connect timeout. |
| `record_open_ports` | bool | Store open ports in run result. |

### `api_enum`

API endpoint enumeration.

| Param | Type | Description |
|---|---|---|
| `base_path` | string | Base URL path prefix. |
| `wordlist` | string | Wordlist name or `builtin:<name>`. |
| `methods` | string[] | HTTP methods to try. |
| `concurrency` | int | Number of concurrent requests. |
| `record_status_codes` | int[] | Status codes to record. |
| `interesting_status_codes` | int[] | Status codes that indicate a finding. |

### `auth_bypass`

Generic authentication bypass wrapper.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path. |
| `bypass_technique` | string | Technique name (e.g. `jwt_none`). |
| `original_token_param` | string | JWT parameter name. |
| `claims_override` | object | Claims to inject. |

### `data_exfil`

Data exfiltration simulation.

| Param | Type | Description |
|---|---|---|
| `endpoint` | string | URL path. |
| `method` | string | HTTP method. |
| `auth_token_param` | string | JWT parameter name. |
| `expected_data_fields` | string[] | Fields expected in a successful exfiltration response. |

## Duration format

Durations use Go duration syntax: `30s`, `5m`, `1h30m`, `500ms`.

## Example: full scenario

```yaml
name: my-scenario
description: "Demonstrate a BOLA finding"
mitre_technique_ids: ["T1078"]
tags: [api, bola]
severity: high
timeout: 5m
steps:
  - kind: bola
    name: "Enumerate user objects"
    params:
      endpoint: /api/v1/users/{id}
      id_type: integer
      id_range: [1, 50]
      auth_token_param: low_privilege_jwt
    on_failure: stop
```
