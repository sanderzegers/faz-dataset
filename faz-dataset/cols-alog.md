# `$log-app-ctrl` — Application Control

Dedicated app-ctrl UTM log (distinct from UTM summary fields on traffic rows). All common columns apply.

| Column | Type | Description |
|---|---|---|
| **`app`** | LowCardinality(String) | Application name — may be `"N/A"`, use `nullifna()` |
| **`appcat`** | LowCardinality(String) | Application category |
| `appid` | Nullable(UInt32) | Numeric application ID |
| **`apprisk`** | LowCardinality(String) | Risk: `critical`, `high`, `medium`, `low`, `elevated` |
| `applist` | LowCardinality(String) | App control profile name |
| **`action`** | LowCardinality(String) | `pass`, `block`, `reset` |
| `eventtype` | LowCardinality(String) | `app-ctrl` |
| `clouduser` | Nullable(String) | Cloud app user identity |
| `cloudaction` | Nullable(String) | Cloud action |
| `clouddevice` | Nullable(String) | Cloud device |
| `sentbyte` | Nullable(UInt64) | Session bytes sent |
| `rcvdbyte` | Nullable(Int64) | Session bytes received |
| `filesize` | Nullable(UInt64) | File size (for file-type detection) |
| `filename` | Nullable(String) | Filename if applicable |
| `crscore` / `craction` / `crlevel` | — | Compound risk score fields |

## Key Pattern

```sql
-- Top apps by bandwidth
SELECT app_group_name(app) AS app_group, appcat, sum(bandwidth) AS bandwidth
FROM ###(
    SELECT app_group_name(app) AS app_group, appcat,
           sum(coalesce(sentbyte,0)+coalesce(rcvdbyte,0)) AS bandwidth
    FROM $log-app-ctrl
    WHERE $filter AND nullifna(app) IS NOT NULL
    GROUP BY app_group, appcat
    /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
)### t
GROUP BY app_group, appcat
ORDER BY bandwidth DESC
```
