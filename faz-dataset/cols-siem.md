# `$log-siem` — SIEM Forwarder Logs

SIEM forwarder logs are structured event records sent from FortiGate or FortiClient to FortiAnalyzer for centralized security information management. No rows in last hour — fields documented from schema only.

## FortiGate SIEM Fields

FortiGate SIEM logs carry 18 public fields plus 7 private fields.

| Column | Type | Description |
|---|---|---|
| **`itime`** | DateTime | Ingestion timestamp |
| **`dtime`** | DateTime | Device timestamp |
| **`devname`** | String | Device name / serial |
| **`devid`** | String | Device identifier |
| **`msg`** | String | Human-readable event message |
| `euid` | Nullable(Int64) | Source end-user ID — join to `$ADOM_ENDUSER.euid` |
| `epid` | Nullable(Int64) | Source endpoint ID — join to `$ADOM_ENDPOINT.epid` |
| `dsteuid` | Nullable(Int64) | Destination end-user ID |
| `dstepid` | Nullable(Int64) | Destination endpoint ID |
| `type` | Nullable(String) | SIEM message type |
| `timestamp` | Nullable(UInt64) | Unix timestamp (microseconds) |
| `tz` | Nullable(String) | Timezone identifier |
| `srccountry` | Nullable(String) | Source country name |
| `dstcountry` | Nullable(String) | Destination country name |
| `srccity` | Nullable(String) | Source city |
| `dstcity` | Nullable(String) | Destination city |
| `srcgeoid` | Nullable(UInt32) | Source GeoIP ID |
| `dstgeoid` | Nullable(UInt32) | Destination GeoIP ID |

Private fields (not directly queryable from `$log-siem`):

| Column | Type | Description |
|---|---|---|
| `logver` | Nullable(String) | Log format version |
| `bid` | Nullable(String) | Batch ID |
| `dvid` | Int32 | Device ID (join to `devtable_ext.dvid`) |
| `logflag` | Int32 | Bitmask — see logflag section in faz-sql-reference.md |
| `csf` | Nullable(String) | CSF (Cloud Security Framework) group name |

```sql
-- SIEM events from FortiGate
SELECT from_dtime(dtime) AS ts, devname, devid, msg, euid, epid,
       srccountry, dstcountry, srccity, dstcity
FROM $log-siem
WHERE $filter AND type = 'FG'  -- FortiGate SIEM messages
ORDER BY dtime DESC
```

## FortiClient SIEM Fields

FortiClient SIEM logs carry 10 fields.

| Column | Type | Description |
|---|---|---|
| **`timestamp`** | Nullable(UInt64) | Event timestamp (microseconds) |
| **`itime`** | DateTime | Ingestion timestamp |
| `emsserial` | Nullable(String) | FortiClient EMS serial |
| **`regdevname`** | String | Registered device name (EMS ID) |
| **`uid`** | String | FortiClient user ID (`fctuid`) |
| **`hostname`** | String | Host device name |
| **`fct_srcname`** | String | Host OS name |
| `fct_srcver` | Nullable(String) | Host OS version |
| `fct_srctype` | Nullable(String) | Host event type |
| **`msg`** | String | Raw SIEM message |

```sql
-- SIEM events from FortiClient
SELECT from_dtime(itime) AS ts, uid, hostname, fct_srcname, fct_srcver,
       fct_srctype, msg
FROM $log-siem
WHERE $filter AND type = 'FC'  -- FortiClient SIEM messages
ORDER BY itime DESC
```

## Key Patterns

```sql
-- Distinguish FortiGate vs FortiClient SIEM
SELECT type, count()
FROM $log-siem
WHERE $filter
GROUP BY type
ORDER BY count() DESC

-- Timezone-aware event clustering
SELECT tz, count(DISTINCT nullifna(devname)) AS device_cnt, count() AS event_cnt
FROM $log-siem
WHERE $filter AND tz IS NOT NULL
GROUP BY tz

-- Endpoint-focused SIEM events
SELECT epid, hostname, fct_srcname, fct_srcver, count() AS evt_cnt
FROM $log-siem
WHERE $filter AND epid > 1024
GROUP BY epid, hostname, fct_srcname, fct_srcver
ORDER BY evt_cnt DESC
```

## Schema Reference

Field type codes from FortiAnalyzer schema (opaque — values 0, 4, 1 observed; no public legend):

| Code | Interpreted Type | Example Fields |
|---|---|---|
| `0` | DateTime / UInt | `itime`, `dtime`, `timestamp`, `euid`, `epid` |
| `1` | UInt32 | `srcgeoid`, `dstgeoid` |
| `4` | String | `devname`, `msg`, `type`, `tz`, `srccountry` |

## Real Values Discovered from FAZ Instance

No SIEM rows found in the last hour. This log type is typically low-volume and may not have recent activity on this instance.
