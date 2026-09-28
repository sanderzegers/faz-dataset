# `$log-waf` — Web Application Firewall

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`wafaction`** | LowCardinality(String) | WAF action: `block`, `pass` |
| **`wafseverity`** | LowCardinality(String) | WAF severity: `critical`, `high`, `medium`, `low` |
| `wafprofile` | Nullable(String) | WAF profile name applied |
| **`wafvulnerability`** | Nullable(String) | Vulnerability category matched |
| **`wafattack`** | Nullable(String) | Specific OWASP CRS attack name |
| `wafattackid` | Nullable(UInt32) | WAF attack ID |
| `httpmethod` | LowCardinality(String) | HTTP method |
| `statuscode` | Nullable(UInt16) | HTTP response status code |
| **`action`** | LowCardinality(String) | Firewall action: `block`, `pass` |
| **`level`** | LowCardinality(String) | Log severity level |
| `policyid` | Nullable(UInt64) | WAF policy ID |
| `url` | Nullable(String) | Requested URL path |
| `hostname` | Nullable(String) | Requested hostname / virtual IP |
| `dstport` | Nullable(UInt16) | Destination port |
| `dstip` | Nullable(IPv6) | Destination IP |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr()` |
| `srcport` | Nullable(UInt16) | Source port |
| `service` | Nullable(String) | Application service |
| `domain` | Nullable(String) | Request domain |
| `requestbody` | Nullable(String) | HTTP request body (truncated) |
| `requestheader` | Nullable(String) | HTTP request headers |
| `serverip` | Nullable(IPv6) | Server IP (virtual IP) |
| `serverport` | Nullable(UInt16) | Server port |
| `policytype` | Nullable(String) | Policy type |
| `vdom` | Nullable(String) | Virtual domain |
| `device` | Nullable(String) | FortiGate device name |
| `interface` | Nullable(String) | Inbound interface |
| `intfrole` | Nullable(String) | Interface role |

## Key Patterns

```sql
-- Blocked WAF requests grouped by vulnerability
SELECT wafvulnerability, wafattack, wafseverity, count(*) AS cnt
FROM $log-waf
WHERE $filter AND wafaction = 'block'
GROUP BY wafvulnerability, wafattack, wafseverity
ORDER BY cnt DESC

-- Top WAF profiles by block count
SELECT wafprofile, action, count(*) AS cnt
FROM $log-waf
WHERE $filter
GROUP BY wafprofile, action
ORDER BY cnt DESC

-- HTTP method distribution for WAF events
SELECT httpmethod, wafaction, count(*) AS cnt
FROM $log-waf
WHERE $filter
GROUP BY httpmethod, wafaction
ORDER BY cnt DESC
```

## Real Values Discovered from FAZ Instance

### `wafaction` (WAF Action)

Observed values from FAZ WAF logs:

| Value | Notes |
|---|---|
| `block` | Request blocked by WAF policy |
| `pass` | Request passed (allowed through) |

### `wafseverity` (WAF Severity)

Observed values from FAZ WAF logs:

| Value | Notes |
|---|---|
| `critical` | Critical severity matches |
| `high` | High severity matches |
| `medium` | Medium severity matches |
| `low` | Low severity matches |

### `wafvulnerability` (WAF Vulnerability)

Observed vulnerability categories from FAZ WAF logs:

| Value | Notes |
|---|---|
| `SQL Injection` | SQL injection attempts |
| `XSS` | Cross-site scripting |
| `Remote File Inclusion` | RFI attacks |
| `Command Injection` | OS command injection |

### `wafattack` (WAF Attack)

Observed OWASP CRS attack names from FAZ WAF logs:

| Value | Notes |
|---|---|
| `SQL Injection Attack: Common SQL Injection Detected` | SQL injection detection |
| `XSS Attack Detected` | Cross-site scripting detection |
| `Remote File Inclusion Attack Detected` | RFI detection |
| `Command Injection Attack` | Command injection detection |

### `httpmethod` (HTTP Method)

Observed HTTP methods from FAZ WAF logs:

| Value | Notes |
|---|---|
| `GET` | HTTP GET requests |
| `POST` | HTTP POST requests |
| `PUT` | HTTP PUT requests |
| `DELETE` | HTTP DELETE requests |
| `HEAD` | HTTP HEAD requests |
| `OPTIONS` | HTTP OPTIONS requests |
| `PATCH` | HTTP PATCH requests |

### `statuscode` (HTTP Status Code)

Observed status codes from FAZ WAF logs:

| Value | Notes |
|---|---|
| `200` | OK — request succeeded |
| `403` | Forbidden — WAF blocked |
| `404` | Not Found |
| `500` | Internal Server Error |
| `502` | Bad Gateway |
| `503` | Service Unavailable |

### `action` (Firewall Action)

Observed firewall actions from FAZ WAF logs:

| Value | Notes |
|---|---|
| `block` | Request blocked |
| `pass` | Request allowed |

### `level` (Log Severity)

Observed log levels from FAZ WAF logs:

| Value | Notes |
|---|---|
| `information` | Routine WAF events |
| `warning` | WAF alerts and blocks |
