---
id: 02-network-forensics-tools
order: 2
duration_minutes: 100
---

# Lesson 2: PCAP Analysis Tools, IDS Rules, and Host-Network Correlation

## Tshark and Wireshark: the core analysis tools

Wireshark is the de facto standard GUI tool for interactive PCAP analysis. `tshark` is its command-line equivalent, essential for scriptable analysis, processing large PCAP files, and running in headless environments. Both use the same dissector library and produce identical protocol interpretations.

The most important tshark operations for incident investigation:

```bash
# Basic file information
tshark -r capture.pcap -c 10     # show first 10 packets

# Display filter: show only DNS traffic
tshark -r capture.pcap -Y "dns"

# Show HTTP requests with source IP, destination, and URI
tshark -r capture.pcap -Y "http.request" \
  -T fields -e ip.src -e http.host -e http.request.uri

# Extract all DNS queries and count by queried name
tshark -r capture.pcap -Y "dns.qry.type == 1" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Find all TCP connections to port 4444 (common C2 port)
tshark -r capture.pcap -Y "tcp.port == 4444" -T fields \
  -e ip.src -e ip.dst -e tcp.dstport -e frame.time

# Extract TLS SNI (Server Name Indication) — reveals hostname even in encrypted traffic
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

# Follow a TCP stream (reassemble the conversation)
tshark -r capture.pcap -z follow,tcp,ascii,0
```

## zeek (formerly Bro): structured network logging

Zeek is a network analysis framework that processes PCAP files or live traffic and produces structured log files for each protocol. Unlike Wireshark/tshark — which give you access to raw packet data — Zeek extracts meaningful fields into tab-separated log files that are directly queryable.

```bash
# Process a PCAP file with Zeek
zeek -r capture.pcap

# Zeek produces logs in the current directory:
ls *.log
# conn.log    — every TCP/UDP/ICMP connection
# dns.log     — every DNS query and response
# http.log    — every HTTP request/response
# ssl.log     — every TLS session (JA3 hashes included)
# files.log   — every file transferred over monitored protocols
# weird.log   — protocol violations and anomalies
```

The `conn.log` is the starting point for most investigations — it lists every connection with source/destination, duration, bytes transferred, and connection state:

```bash
# Find the top 10 external IPs by bytes sent (potential exfiltration)
zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes < conn.log | \
  awk '{print $2, $3}' | sort -rn -k2 | head -10

# Find all connections to port 80/443 from an internal host
zeek-cut id.orig_h id.resp_h id.resp_p service < conn.log | \
  grep "^192.168.1.50" | grep -E "80|443"
```

## Reading Suricata and Snort IDS rules

IDS rules define the patterns that trigger alerts. Reading rules fluently is a critical skill: it lets you understand what your IDS is detecting, write custom rules for newly identified TTPs, and tune rules to reduce false positives.

Suricata rules follow this structure:

```text
action protocol src_ip src_port direction dst_ip dst_port (options)
```

Example: detecting Cobalt Strike beaconing pattern:

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Cobalt Strike Beacon Checkin";
  flow:established,to_server;
  content:"GET";
  http_method;
  content:"/pixel.gif";
  http_uri;
  content:"Mozilla/5.0";
  http_header;
  pcre:"/^Cookie\x3a\s[a-zA-Z0-9+\/]{100,}/Hm";
  classtype:trojan-activity;
  sid:2025001;
  rev:1;
)
```

Breaking down this rule:
- `alert http` — generate an alert for HTTP traffic
- `$HOME_NET any -> $EXTERNAL_NET any` — from internal network, any port, to external network, any port
- `flow:established,to_server` — only matching traffic in the direction of the server in an established TCP connection
- `content:"GET"; http_method;` — the HTTP method must be GET
- `content:"/pixel.gif"; http_uri;` — the URI must contain `/pixel.gif`
- `pcre:"/^Cookie\x3a\s[a-zA-Z0-9+\/]{100,}/Hm";` — the Cookie header must match a base64-like pattern of at least 100 characters (characteristic of Cobalt Strike session token encoding)

Writing a custom rule for DGA-like DNS queries:

```text
alert dns $HOME_NET any -> any 53 (
  msg:"Possible DGA Domain Query";
  dns_query;
  content:".net";
  pcre:"/^[a-z]{12,20}\.(net|com|org)$/i";
  threshold:type both,track by_src,count 20,seconds 60;
  classtype:policy-violation;
  sid:9000001;
  rev:1;
)
```

This rule alerts when a single source host queries more than 20 domains matching a pattern of 12–20 random lowercase characters in 60 seconds — consistent with DGA activity.

## Host-network correlation: tying network evidence to host artefacts

The most powerful investigative technique is correlating network evidence with host forensic artefacts. Network evidence shows what happened at the protocol level; host evidence shows what process caused it, what files were accessed, and what registry keys were modified.

The correlation pivot is time: every network event has a timestamp; every host event has a timestamp. By aligning timestamps, an analyst can answer questions like:

- "Which process initiated this outbound connection to 185.220.101.47 at 03:47:22?" → Check the process list or EDR telemetry for the process holding the socket at that time
- "What executable was responsible for these DNS queries?" → correlate DNS timestamps from Zeek dns.log with process-level DNS calls in Sysmon Event ID 22 (DNSEvent)
- "What file was written immediately before this HTTP POST?" → correlate the HTTP POST timestamp with filesystem audit events or Sysmon Event ID 11 (FileCreate)

```python
# Example: correlating Zeek DNS log timestamps with Windows Sysmon Event ID 22
import pandas as pd

# Load Zeek DNS log
zeek_dns = pd.read_csv("dns.log", sep="\t", comment="#",
    names=["ts","uid","src","src_port","dst","dst_port","proto","trans_id",
           "query","qclass","qtype","rcode","answers","ttls","rejected"])

# Load Sysmon DNS events (exported as CSV)
sysmon_dns = pd.read_csv("sysmon_eid22.csv")

# Find Zeek DNS entries with no matching Sysmon event (potential covert channel)
zeek_dns["ts_rounded"] = pd.to_datetime(zeek_dns["ts"], unit="s").dt.round("1s")
sysmon_dns["ts_rounded"] = pd.to_datetime(sysmon_dns["UtcTime"]).dt.round("1s")

unmatched = zeek_dns[~zeek_dns["ts_rounded"].isin(sysmon_dns["ts_rounded"])]
print(unmatched[["ts_rounded", "query"]].head(20))
```

DNS queries appearing in the network record but absent from the process-level event log indicate a process bypassing the OS resolver — a characteristic of C2 malware that performs raw DNS queries to avoid detection by endpoint monitoring tools.
