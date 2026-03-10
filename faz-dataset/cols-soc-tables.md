# SOC / SIEM Tables

These are **SIEM-layer tables**, distinct from `$log-event` (device logs). They hold alerts and incidents created by the FAZ correlation engine. Backed by PostgreSQL, accessed via ClickHouse proxy tables.

Use `$cust_time_filter(col)` instead of `$filter` for time filtering on these tables.

---

## `$event` — SIEM Alerts

| Column | Type | Description |
|---|---|---|
| **`alertid`** | Int64 | Alert ID |
| **`alerttime`** | Int32 | Alert time (Unix epoch) — use `$cust_time_filter(alerttime)` |
| `updatetime` | Int32 | Last update time |
| **`dvid`** | Int32 | Device ID — join to `devtable_ext` for device name |
| `epid` | Int32 | Endpoint ID |
| `euid` | Int32 | End-user ID |
| **`severity`** | Int16 | **0=Critical, 1=High, 2=Medium, 3=Low** (integer — decode with CASE) |
| `flags` | Int16 | Alert flags bitmask |
| **`triggername`** | Nullable(String) | Alert rule/trigger name |
| `tag` | Nullable(String) | Alert tag |
| `epip` | Nullable(String) | Endpoint IP string |
| `epname` | Nullable(String) | Endpoint name |
| `euname` | Nullable(String) | End-user name |
| **`subject`** | Nullable(String) | Alert subject/title |
| `eventtype` | Nullable(String) | Event type |
| `groupby1` / `groupby2` / `groupby3` | Nullable(String) | Alert grouping fields |
| `eventstatus` | Nullable(String) | Event status |
| `extrainfo` | Nullable(String) | Extra JSON info |
| `logtype` / `devtype` / `subtype` | Nullable(String) | Log/device type |
| `filterkey` | Int64 | Filter key |
| **`firstlogtime`** | Int32 | First log timestamp |
| **`lastlogtime`** | Int32 | Last log timestamp |
| **`logcount`** | Int64 | Number of logs contributing to this alert |
| `assignto` | Nullable(String) | Assigned analyst |
| `ackby` | String | Acknowledged by |
| `acktime` | Int64 | Acknowledged time |
| `indicator` | Nullable(String) | IOC indicator |

> **Severity decode:**
> ```sql
> CASE severity WHEN 0 THEN 'Critical' WHEN 1 THEN 'High' WHEN 2 THEN 'Medium' WHEN 3 THEN 'Low' END AS sev_label
> ```

```sql
-- Top alert triggers with severity
SELECT triggername,
       CASE severity WHEN 0 THEN 'Critical' WHEN 1 THEN 'High'
                     WHEN 2 THEN 'Medium'   WHEN 3 THEN 'Low' END AS sev,
       count(*) AS cnt
FROM $event
WHERE $cust_time_filter(alerttime, TODAY)
GROUP BY triggername, severity
ORDER BY severity, cnt DESC

-- Alerts with device name
SELECT e.triggername, d.devname, e.severity, count(*) AS cnt
FROM $event e
LEFT JOIN devtable_ext d ON e.dvid = d.dvid
WHERE $cust_time_filter(e.alerttime)
GROUP BY e.triggername, d.devname, e.severity
ORDER BY cnt DESC
```

---

## `$incident` — SIEM Incidents

Note: `severity` here is a **String** (unlike `$event` where it's Int16).

| Column | Type | Description |
|---|---|---|
| **`incid`** | Int64 | Incident ID — use `incid_to_str(incid)` for display (e.g. `"INC-00123"`) |
| `epid` | Nullable(Int32) | Endpoint ID |
| `euid` | Nullable(Int32) | End-user ID |
| **`endpoint`** | Nullable(String) | Endpoint name string |
| **`category`** | Nullable(String) | Incident category |
| **`severity`** | Nullable(String) | `critical`, `high`, `medium`, `low` **(String, not int)** |
| **`status`** | Nullable(String) | `draft`, `analysis`, `response`, `closed`, `cancelled` |
| **`description`** | Nullable(String) | Incident description |
| `reporter` | Nullable(String) | Who/what created the incident |
| **`createtime`** | Nullable(Int32) | Creation timestamp — use `$cust_time_filter(createtime)` |
| `lastupdate` | Nullable(Int32) | Last update timestamp |
| `lastuser` | Nullable(String) | Last modifying user |
| **`assigned_to`** | Nullable(String) | Assigned analyst |
| `remedy_action` | Nullable(String) | Remediation action |
| `executor` / `approver` | Nullable(String) | Executor/approver |
| `remedy_time` | Nullable(Int32) | Remediation time |
| `refinfo` | Nullable(String) | Reference info |

```sql
-- Open incidents
SELECT incid_to_str(incid) AS incnum,
       from_itime(createtime) AS ts,
       severity, status, endpoint, description
FROM $incident
WHERE $cust_time_filter(createtime)
  AND status NOT IN ('closed','cancelled')
ORDER BY severity DESC

-- Incident count by status
SELECT status, count(*) AS cnt
FROM $incident
WHERE $cust_time_filter(createtime)
GROUP BY status
ORDER BY cnt DESC
```

---

## `$event_history` — Pre-aggregated Alert Counts

Pre-aggregated counts by time bucket. Fast for trend queries.

| Column | Description |
|---|---|
| **`agg_time`** | Time bucket (Unix epoch) — use `$flex_timescale(agg_time)` for display |
| `num_sev_critical` | Count of critical severity alerts |
| `num_sev_high` | Count of high severity alerts |
| `num_sev_medium` | Count of medium severity alerts |
| `num_sev_low` | Count of low severity alerts |
| **`num_total`** | Total alert count |

```sql
-- Alert trend over time
SELECT $flex_timescale(agg_time) AS hodex,
       max(num_sev_critical) AS critical,
       max(num_sev_high) AS high,
       max(num_total) AS total
FROM $event_history
WHERE $cust_time_filter(agg_time)
GROUP BY hodex
ORDER BY hodex
```

---

## `$incident_history` — Pre-aggregated Incident Counts

| Column | Description |
|---|---|
| **`agg_time`** | Time bucket — use `$flex_timescale(agg_time)` for display |
| `num_sta_draft` | Incidents in draft status |
| `num_sta_analysis` | Incidents in analysis |
| `num_sta_response` | Incidents in response |
| `num_sta_closed` | Closed incidents |
| `num_sta_cancelled` | Cancelled incidents |
| `num_sev_critical` | Critical severity count |
| `num_sev_high` | High severity count |
| `num_sev_medium` | Medium severity count |
| `num_sev_low` | Low severity count |
| `num_endpoint` | Affected endpoint count |

```sql
-- Open incident trend
SELECT $flex_timescale(agg_time) AS hodex,
       max(num_sta_draft) + max(num_sta_analysis) + max(num_sta_response) AS open
FROM $incident_history
WHERE $cust_time_filter(agg_time)
GROUP BY hodex
ORDER BY hodex
```
