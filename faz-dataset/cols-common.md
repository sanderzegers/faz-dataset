# Common Columns — Present on ALL Log Types

These columns exist on every `$log-*` source.

| Column | Type | Description |
|---|---|---|
| **`dvid`** | Int32 | Device ID (join to `devtable_ext.dvid` for device name) |
| **`itime`** | DateTime | Ingestion timestamp — `$filter` filters on this |
| **`dtime`** | DateTime | Device timestamp (when event occurred) — use `from_dtime(dtime)` for display |
| **`euid`** | Int32 | End-user ID — join to `$ADOM_ENDUSER.euid`; values <1024 are system |
| **`epid`** | Int32 | Endpoint ID — join to `$ADOM_ENDPOINT.epid`; values <1024 are system |
| `dsteuid` | Int32 | Destination end-user ID |
| `dstepid` | Int32 | Destination endpoint ID — use `CASE WHEN direction='incoming' THEN epid ELSE dstepid END` for victim in attack queries |
| `sfsid` | Nullable(Int64) | FortiSandbox session ID |
| **`logflag`** | Int32 | Bitmask — see logflag section in faz-sql-reference.md |
| **`type`** | LowCardinality(String) | Log type: `traffic`, `utm`, `event`, etc. |
| **`subtype`** | LowCardinality(String) | Log subtype: `forward`, `webfilter`, `attack`, etc. |
| **`level`** | LowCardinality(String) | Severity: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `information`, `debug` |
| **`action`** | LowCardinality(String) | Action taken: `accept`, `deny`, `block`, `pass`, `detected`, etc. |
| **`logid`** | LowCardinality(String) | Log ID string — use `logid_to_int(logid)` for numeric compare |
| **`srcip`** | Nullable(IPv6) | Source IP — always use `ipstr()` for display |
| **`dstip`** | Nullable(IPv6) | Destination IP — always use `ipstr()` for display |
| **`srcport`** | Nullable(UInt16) | Source port |
| **`dstport`** | Nullable(UInt16) | Destination port |
| `proto` | Nullable(UInt8) | IP protocol: 1=ICMP, 6=TCP, 17=UDP, 47=GRE, 50=ESP |
| **`user`** | LowCardinality(String) | Authenticated username — may be `"N/A"`, use `nullifna()` |
| `unauthuser` | LowCardinality(String) | Unauthenticated username — may be `"N/A"`, use `nullifna()` |
| `group` | LowCardinality(String) | User group |
| **`service`** | LowCardinality(String) | Service name (e.g. `"HTTPS"`, `"DNS"`) |
| **`srcintf`** | LowCardinality(String) | Source interface |
| **`dstintf`** | LowCardinality(String) | Destination interface |
| `srcintfrole` | LowCardinality(String) | Source interface role: `lan`, `wan`, `dmz` |
| `dstintfrole` | LowCardinality(String) | Destination interface role |
| **`srccountry`** | LowCardinality(String) | Source country name |
| **`dstcountry`** | LowCardinality(String) | Destination country name |
| `srccity` / `dstcity` | LowCardinality(String) | Source/destination city |
| `srcgeoid` / `dstgeoid` | Nullable(UInt32) | GeoIP ID |
| `srcname` / `dstname` | LowCardinality(String) | Source/destination hostname/device name |
| `policyid` | Nullable(UInt32) | Firewall policy ID |
| `poluuid` | Nullable(UUID) | Policy UUID — join to `$ADOMTBL_PLHD_POLINFO` on `uuid` |
| `policytype` | LowCardinality(String) | Policy type: `policy`, `local-in`, `DoS` |
| `policymode` | LowCardinality(String) | `flow`, `proxy` |
| `profile` | Nullable(String) | UTM profile name |
| `sessionid` | Nullable(UInt32) | Session ID |
| `fctuid` | Nullable(UUID) | FortiClient UUID |
| `direction` | LowCardinality(String) | Traffic direction: `incoming`, `outgoing` |
| `hostname` | LowCardinality(String) | Destination hostname |
| `url` | Nullable(String) | URL |
| `msg` | Nullable(String) | Human-readable log message |
| `agent` | LowCardinality(String) | HTTP user agent |
| `srczone` / `dstzone` | Nullable(String) | Source/destination zone |
| `srcdomain` | Nullable(String) | Source domain |
| `vsn` | Nullable(String) | Virtual serial number (VDOM) |
| `eventtime` | Nullable(UInt64) | Event timestamp in microseconds |
