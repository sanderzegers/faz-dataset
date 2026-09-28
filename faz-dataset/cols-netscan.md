# `$log-netscan` — Network Scanning Detection

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`netscanaction`** | LowCardinality(String) | Scan action taken — `scan`, `detected` |
| **`netscansource`** | Nullable(String) | Source IP performing the scan — `10.x.x.x` / `172.16.x.x` / `192.168.x.x` |
| **`netscantype`** | LowCardinality(String) | Scan technique used — see scan types below |
| **`netscantarget`** | Nullable(String) | Target IP being scanned — `10.x.x.x` / `172.16.x.x` / `192.168.x.x` |
| **`netscanport`** | Nullable(UInt16) | Target port number |
| **`netscanportprotocol`** | LowCardinality(String) | Protocol used for the scan — `tcp`, `udp` |
| **`netscanportstate`** | LowCardinality(String) | Port state from scan result — `open`, `closed`, `filtered` |
| **`action`** | LowCardinality(String) | Policy action — `allow`, `block` |
| **`level`** | LowCardinality(String) | Log level — `notice`, `information` |

## Key Patterns

```sql
-- Unique scanners: count distinct sources
SELECT count(DISTINCT netscansource) AS unique_scanners
FROM ###(
    SELECT netscansource
    FROM $log-netscan
    WHERE $filter AND nullifna(netscansource) IS NOT NULL
    GROUP BY netscansource
    /*SkipSTART*/ORDER BY count(*) DESC/*SkipEND*/
)### t

-- Most scanned ports
SELECT netscanport, netscanportprotocol, count(*) AS hit_count
FROM $log-netscan
WHERE $filter AND netscanport IS NOT NULL
GROUP BY netscanport, netscanportprotocol
ORDER BY hit_count DESC
LIMIT 20

-- Scan type distribution
SELECT netscantype, count(*) AS type_count
FROM $log-netscan
WHERE $filter AND nullifna(netscantype) IS NOT NULL
GROUP BY netscantype
ORDER BY type_count DESC

-- Target port states
SELECT netscanportstate, count(*) AS state_count
FROM $log-netscan
WHERE $filter AND nullifna(netscanportstate) IS NOT NULL
GROUP BY netscanportstate
ORDER BY state_count DESC
```

## Real Values Discovered from FAZ Instance

### `netscantype` (Scan Technique)

Observed from FAZ netscan logs (200 rows):

| Value | Notes |
|---|---|
| `SYN` | TCP SYN scan — stealthy half-open scan |
| `ACK` | TCP ACK scan — firewall evasion / stateless scan |
| `FIN` | TCP FIN scan — Christmas tree variant |
| `XMAS` | TCP XMAS scan — sets FIN+PSH+URG flags |
| `NULL` | TCP NULL scan — no flags set |
| `UDP` | UDP port scan |
| `CONNECT` | TCP full-connect scan — explicit connect() syscall |
| `RPC-ENUM` | RPC endpoint mapper enumeration |

### `netscanportstate` (Port State)

Observed from FAZ netscan logs:

| Value | Notes |
|---|---|
| `open` | Port is open and accepting connections |
| `closed` | Port is reachable but no service listening |
| `filtered` | Port is unreachable (firewall drop) |

### `netscanaction` (Scan Action)

Observed from FAZ netscan logs:

| Value | Notes |
|---|---|
| `scan` | Scan activity detected |
| `detected` | Scan was detected and logged |

### `action` (Policy Action)

Observed from FAZ netscan logs:

| Value | Notes |
|---|---|
| `allow` | Traffic allowed by policy |
| `block` | Traffic blocked by policy |

### `level` (Log Level)

| Value | Notes |
|---|---|
| `notice` | Notice level log entry |
| `information` | Informational log entry |

### `netscanportprotocol` (Protocol)

| Value | Notes |
|---|---|
| `tcp` | TCP protocol |
| `udp` | UDP protocol |
