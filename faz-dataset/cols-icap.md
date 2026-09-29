# `$log-icap` — ICAP (Internet Content Adaptation Protocol)

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| `icapstatus` | LowCardinality(String) | ICAP transaction status |
| `icapclient` | LowCardinality(String) | ICAP client type (proxy, antivirus, etc.) |
| `icapserver` | Nullable(String) | ICAP server name or address |
| `icapserverip` | Nullable(IPv6) | ICAP server IP — use `ipstr()` for display |
| `icapserverport` | Nullable(UInt16) | ICAP server port |
| `icapversion` | LowCardinality(String) | ICAP protocol version |
| `icapreqmethod` | LowCardinality(String) | ICAP request method |
| `icapreqstatus` | Nullable(UInt16) | ICAP request HTTP status |
| `icapreqstatusline` | Nullable(String) | ICAP request status line text |
| `icaprequrl` | Nullable(String) | ICAP request URL |
| `icaprespstatus` | Nullable(UInt16) | ICAP response HTTP status |
| `icaprespstatusline` | Nullable(String) | ICAP response status line text |
| `icaprespurl` | Nullable(String) | ICAP response URL |
| `icapmodetype` | LowCardinality(String) | ICAP modification type |
| `icapreqbodyenc` | LowCardinality(String) | ICAP request body encoding |
| `icaprespbodyenc` | LowCardinality(String) | ICAP response body encoding |
| `icapreqbodyformat` | LowCardinality(String) | ICAP request body format |
| `icaprespbodyformat` | LowCardinality(String) | ICAP response body format |
| `icapreqencapsulation` | LowCardinality(String) | ICAP request encapsulation type |
| `icaprespencapsulation` | LowCardinality(String) | ICAP response encapsulation type |
| `icapreqbodylength` | Nullable(UInt64) | ICAP request body length in bytes |
| `icaprespbodylength` | Nullable(UInt64) | ICAP response body length in bytes |
| `icapreqbody` | Nullable(String) | ICAP request body preview |
| `icaprespbody` | Nullable(String) | ICAP response body preview |
| `icapreqbodypreview` | Nullable(String) | Request body preview (alternative name) |
| `icaprespbodypreview` | Nullable(String) | Response body preview (alternative name) |
| `icaprespduration` | Nullable(UInt64) | ICAP transaction duration in microseconds |
| `icapclientreqmethod` | LowCardinality(String) | Original HTTP method from client |
| `icapclientrequrl` | Nullable(String) | Original client request URL |
| `icapclientrequri` | Nullable(String) | Original request URI |
| `icapclientreqhost` | Nullable(String) | Original Host header |
| `icapclientreqbodylength` | Nullable(UInt64) | Original client request body length |
| `icaprespclientreqstatus` | Nullable(UInt16) | Client request status from ICAP response |
| `icaprespclientreqmethod` | LowCardinality(String) | Client method in ICAP response |
| `icaprespclientrequri` | Nullable(String) | Client URI in ICAP response |
| `icaprespclientreqhost` | Nullable(String) | Client Host in ICAP response |
| `icaprespclientbodylength` | Nullable(UInt64) | Client response body length from ICAP |
| `icapreqopts` | LowCardinality(String) | ICAP OPTIONS request flags |
| `icapreqoptions` | Nullable(String) | ICAP OPTIONS details |
| `icapreqservice` | LowCardinality(String) | ICAP request service |
| `icapreqserviceid` | Nullable(String) | ICAP request service identifier |
| `icaprespbodyformatenc` | LowCardinality(String) | ICAP response body format encoding |
| `icapreqbodyformatenc` | LowCardinality(String) | ICAP request body format encoding |
| `icapreqencapsbodylength` | Nullable(UInt64) | ICAP request encapsulated body length |
| `icaprespencapsbodylength` | Nullable(UInt64) | ICAP response encapsulated body length |
| `icapprofile` | Nullable(String) | ICAP profile name |
| `icapprofilegroup` | Nullable(String) | ICAP profile group |

## Key Pattern

```sql
-- ICAP failures by server
SELECT icapserver,
       icapstatus,
       count(*) AS failures
FROM $log-icap
WHERE $filter AND icapstatus != 'success'
GROUP BY icapserver, icapstatus
ORDER BY failures DESC
```

## Real Values Discovered from FAZ Instance

> No ICAP logs were found in the queried time window.
> Values below are from the Fortinet ICAP log schema (FortiGate 7.6.6 reference).

### `icapstatus` (ICAP Status)

| Value | Notes |
|---|---|
| `success` | ICAP transaction completed successfully |
| `fail` | ICAP transaction failed |
| `timeout` | ICAP server did not respond in time |
| `error` | General ICAP error |

### `icapclient` (ICAP Client)

| Value | Notes |
|---|---|
| `antivirus` | AV scanning via ICAP |
| `webfilter` | Web filtering via ICAP |
| `ips` | IPS via ICAP |
| `dlp` | DLP via ICAP |
| `sandbox` | Sandboxing via ICAP |
| `other` | Other ICAP client |

### `icapversion` (ICAP Version)

| Value | Notes |
|---|---|
| `ICAP/1.0` | ICAP protocol version 1.0 |

### `icapreqmethod` (ICAP Request Method)

| Value | Notes |
|---|---|
| `REQMOD` | Request modification |
| `RESPMOD` | Response modification |
| `OPTIONS` | Options request |

### `icapmodetype` (ICAP Modification Type)

| Value | Notes |
|---|---|
| `replace` | Body replacement |
| `insert` | Body insertion |
| `remove` | Body removal |
| `preview` | Preview only |
| `pass` | Pass-through |

### `icaprespbodyformat` / `icapreqbodyformat` (Body Format)

| Value | Notes |
|---|---|
| `http11` | HTTP/1.1 |
| `multipart` | Multipart |
| `tcpip` | TCP/IP |
| `raw` | Raw data |
| `binary` | Binary |

### `icaprespbodyenc` / `icapreqbodyenc` (Body Encoding)

| Value | Notes |
|---|---|
| `identity` | Identity encoding |
| `chunked` | Chunked encoding |
| `compress` | Compressed encoding |

### `icapreqencapsulation` / `icaprespencapsulation` (Encapsulation)

| Value | Notes |
|---|---|
| `http11` | HTTP/1.1 encapsulation |
| `tcpip` | TCP/IP encapsulation |

### `icapreqopts` (ICAP Options)

| Value | Notes |
|---|---|
| `allow-204` | Supports 204 No-Content |
| `get-req-body` | Supports GET request body |
| `res-only` | Response modification only |
| `req-only` | Request modification only |
