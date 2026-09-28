# `$log-virtual-patch` — Application Firewall Virtual Patch

Virtual-patch logs capture App Firewall (WAF) virtual patch events — security policy violations detected by FortiGate's virtual patching engine. These logs are generated when the Application Firewall profile's virtual patch feature matches traffic against known vulnerability signatures (e.g., SQL injection, XSS, command injection in web applications).

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`vwpolicyid`** | Nullable(UInt32) | Virtual patch policy ID |
| **`vwpolicyname`** | LowCardinality(String) | Virtual patch policy name — use `nullifna()` |
| **`vwpv`** | LowCardinality(String) | Virtual patch version/identifier |
| **`vwpvname`** | LowCardinality(String) | Virtual patch name (vulnerability signature) — use `nullifna()` |
| **`vwpvaction`** | LowCardinality(String) | Action taken by virtual patch |
| **`vwpvseverity`** | LowCardinality(String) | Severity of the virtual patch match |
| **`vwpvcate`** | LowCardinality(String) | Virtual patch category — OWASP category or similar |
| **`vwpvattack`** | LowCardinality(String) | Virtual patch attack name — exploit description |
| **`vwpvruleid`** | Nullable(UInt32) | Virtual patch rule ID |
| **`vwpvprotocol`** | Nullable(String) | Protocol matched by virtual patch |
| **`vwpvport`** | Nullable(UInt16) | Port matched by virtual patch |
| `srcip` | Nullable(IPv6) | Source IP — always use `ipstr()` for display |
| `dstip` | Nullable(IPv6) | Destination IP — always use `ipstr()` for display |
| `srcport` | Nullable(UInt16) | Source port |
| `dstport` | Nullable(UInt16) | Destination port |
| `proto` | Nullable(UInt8) | IP protocol number |
| `service` | Nullable(String) | Service name |
| `app` | LowCardinality(String) | Application name — may be `"N/A"`, use `nullifna()` |
| `user` | LowCardinality(String) | Authenticated user — may be `"N/A"` |
| `action` | LowCardinality(String) | Overall action: `accept`, `close`, `client-rst`, `server-rst`, `deny`, `timeout` |
| `level` | LowCardinality(String) | Logging level |
| `devname` | LowCardinality(String) | Device name |
| `vd` | LowCardinality(String) | VDOM name |
| `sessionid` | Nullable(UInt64) | Session ID |
| `policyid` | Nullable(UInt32) | Firewall policy ID |
| `duration` | Nullable(UInt32) | Session duration in seconds |
| `sentbyte` / `rcvdbyte` | Nullable(UInt64) | Bytes sent/received |
| `sentdelta` / `rcvddelta` | Nullable(UInt64) | Delta bytes for long-lived sessions |
| `sentpkt` / `rcvdpkt` | Nullable(UInt64) | Packets sent/received |
| `srccountry` | LowCardinality(String) | Source country name |
| `dstcountry` | LowCardinality(String) | Destination country name |
| `srcintf` | LowCardinality(String) | Source interface |
| `dstintf` | LowCardinality(String) | Destination interface |
| `srczone` | Nullable(String) | Source zone |
| `dstzone` | Nullable(String) | Destination zone |
| `srcmac` | Nullable(String) | Source MAC address |
| `dstmac` | Nullable(String) | Destination MAC address |
| `httpmethod` | Nullable(String) | HTTP method (`GET`, `POST`, etc.) |
| `url` | Nullable(String) | Request URL |
| `hostname` | Nullable(String) | Host header |
| `statuscode` | Nullable(UInt16) | HTTP status code |
| `catdesc` | Nullable(String) | Application category description |
| `appcat` | Nullable(String) | Application category |
| `apprisk` | Nullable(String) | Application risk level |
| `attack` | Nullable(String) | Attack/signature name (if correlated) |
| `severity` | Nullable(String) | Overall severity |
| `utmaction` | LowCardinality(String) | UTM action: `allow`, `block`, `blocked`, `pass`, `passthrough`, `quarantined`, `reset` |
| `utmevent` | LowCardinality(String) | UTM event type: `app-ctrl`, `appfirewall`, `ips`, `webfilter` |
| `crscore` | Nullable(UInt32) | Campaign rule score |
| `craction` | Nullable(UInt32) | Campaign rule action |
| `crlevel` | Nullable(String) | Campaign rule level |
| `vrf` | Nullable(UInt32) | VRF ID |
| `slot` | Nullable(UInt32) | Hardware slot |
| `logid` | Nullable(String) | Log ID |
| `policytype` | Nullable(String) | Policy type |
| `policymode` | LowCardinality(String) | Policy mode: `flow`, `proxy` |
| `transid` | Nullable(UInt32) | Transaction ID |
| `tz` | LowCardinality(String) | Timezone |
| `custom_field1` | Nullable(String) | Custom field 1 |
| `dtime` | Nullable(DateTime64(3)) | Device time |
| `eventtime` | Nullable(UInt64) | Event timestamp in microseconds |
| `srcname` | LowCardinality(String) | Source hostname / device name |
| `srcdomain` | LowCardinality(String) | Source domain |
| `srcuuid` | Nullable(UUID) | Source address object UUID |
| `dstuuid` | Nullable(UUID) | Destination address object UUID |
| `poluuid` | Nullable(UUID) | Policy UUID |
| `msg` | Nullable(String) | Human-readable log message |

## Zero Data in Last Hour

No virtual-patch log rows were found in the last hour. All fields are documented from the FortiAnalyzer schema only. No real enum values are available — expected values will emerge when virtual-patch logging becomes active.
