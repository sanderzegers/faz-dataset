# FortiAnalyzer SQL Dialect Reference

## Architecture (what happens to your query)

```
GUI Dataset SQL
      ↓ FazReportSQL.parseFazKeyword()   (expands $log, $filter, ${MACRO}, ###...###)
      ↓ sql_rewriter (ANTLR4 Flask service — dialect conversion only)
      ↓ ClickHouse
```

## Core Template Variables

| Variable | Replaced with | Notes |
|---|---|---|
| `$log` | Device+logtype specific view | e.g. `sp1_FGT_tlog` for FGT traffic |
| `$filter` | Time range + device scope filter | Always include in WHERE |
| `$[varname]` | User-defined report variable | Set in report template |

## ${MACRO} Expansions

These expand to ClickHouse-compatible boolean expressions:

| Macro | Expands to | Use when |
|---|---|---|
| `${REPORT_SESSION}` | `(bitAnd(logflag,1)>0)` | Count sessions, sum bytes — report-worthy traffic |
| `${BLOCKED_ACTION}` | `(bitAnd(logflag,2)>0)` | Blocked/denied traffic only |
| `${IS_FCT_ENDUSER}` | `(logflag is null or bitAnd(logflag,8)=0)` | Exclude FCT system users |
| `${IS_BOTNET}` | `(bitAnd(logflag,16)>0)` | Botnet sessions only |
| `${REPORT_SESSION_WITH_LONGLIVE}` | `(bitAnd(logflag,bitOr(1,32))>0)` | Sessions + long-lived sessions |
| `${WEB_UTM_EVENT}` | `utmevent in ('webfilter','banned-word','web-content','command-block','script-filter')` | Web filter events |
| `${AV_UTM_EVENT}` | `utmevent is not null and virus is not null` | Antivirus events |
| `${APPCTRL_UTM_EVENT}` | `utmevent in ('app-ctrl')` | Application control events |
| `${ATTACK_UTM_EVENT}` | `utmevent in ('ips')` | IPS/attack events |
| `${EMAIL_SEND_SERVICE}` | `('smtp','SMTP','25/tcp','587/tcp','smtps','SMTPS','465/tcp')` | Email send services (use with `service IN ${EMAIL_SEND_SERVICE}`) |

## logflag Bit Flags (raw, if needed)

| Bit | Value | Meaning |
|---|---|---|
| 0 | 1 | `REPORT_SESSION` — session counted in reports |
| 1 | 2 | `BLOCKED_ACTION` — action was blocked |
| 2 | 4 | `CLOUD_APP` — cloud app session |
| 3 | 8 | `FCT_SYSUSR` — FortiClient system user |
| 4 | 16 | `BOTNET` — botnet session |
| 5 | 32 | `LONGLIVE_SESSION` — long-lived session |

## hcache / ###...### Mechanism

Used to cache expensive subquery results across multiple datasets in the same report run.

```sql
-- Anonymous hcache (hash-based key)
WHERE srcip IN ###(SELECT srcip FROM $log WHERE $filter AND action='deny')###

-- Named hcache (reused across datasets with same label)
WHERE srcip IN ###base(/*tag:top_blocked_ips*/SELECT srcip FROM $log WHERE $filter AND action='deny')base###
```

- The inner query is executed ONCE and cached; subsequent datasets reuse the cache.
- The outer query is still a normal ClickHouse query.

## ADOM_* Placeholder Tables

These are FAZ query-engine placeholders (resolved before ClickHouse). Use in GUI queries only:

| Placeholder | Resolves to |
|---|---|
| `$ADOM_ENDPOINT` | `faz_fabric_endpoints` |
| `$ADOM_ENDUSER` | `faz_fabric_endusers` |
| `$ADOM_EPEU_DEVMAP` | `faz_fabric_epeudevmap` |
| `ADOM_INTF_INFO` | Interface info for current ADOM |
| `ADOMTBL_PLHD_POLINFO` | Policy info for current ADOM |

**Do NOT use raw table names** like `sp1_FGT_tlog` in GUI datasets — use `$log`.

## $log — Log Table Mapping

When creating a dataset in the GUI, you select the **Log Type**. `$log` maps to:

| GUI Log Type | Example resolved table |
|---|---|
| Traffic | `sp1_FGT_tlog` |
| Event | `sp1_FGT_elog` |
| Web Filter (UTM) | `sp1_FGT_wlog` |
| App Control (UTM) | `sp1_FGT_alog` |
| Antivirus (UTM) | `sp1_FGT_vlog` |
| IPS (UTM) | `sp1_FGT_slog` (or `sp1_FGT_elog` for event) |
| FortiProxy Traffic | `sp1_FPX_tlog` |
| FortiWeb Traffic | `sp1_FWB_tlog` |
| FortiMail Event | `sp1_FML_elog` |
| FortiClient Traffic | `sp1_FCT_Tlog` (uppercase T) |
| FortiClient Event | `sp1_FCT_Elog` (uppercase E) |

## ClickHouse SQL Tips (relevant to FAZ)

```sql
-- IP formatting
ipstr(srcip)                          -- → '192.168.1.1' (strips IPv6 ::ffff: prefix)
ipstr(dstip)

-- Datetime formatting
formatDateTime(toDateTime(itime), '%Y-%m-%d %H:%M:%S')
toDateTime(itime)                      -- itime is Unix epoch Int32

-- Conditional
multiIf(condition1, val1, condition2, val2, default)
if(condition, then, else)

-- Bit operations
bitAnd(logflag, 1)                    -- test bit 0
bitOr(1, 32)                          -- combine bits

-- Array columns (tlog)
arrayJoin(threats) AS threat          -- explode array to rows
has(apps, 'BitTorrent')               -- test array membership
arrayStringConcat(apps, ',')          -- join array to string

-- Aggregation
SUM(sentbyte + rcvdbyte) AS bytes
COUNT() AS sessions
COUNT(DISTINCT srcip) AS unique_ips
uniq(srcip) AS approx_unique_ips      -- faster approximate

-- Rounding time to buckets
toStartOfHour(toDateTime(itime)) AS hour
toStartOfDay(toDateTime(itime)) AS day
intDiv(itime, 300) * 300 AS fivemin   -- 5-minute buckets

-- Top N with ties
LIMIT 10 BY srcip                     -- ClickHouse specific
```

## Common Query Skeletons

### Top bandwidth users (traffic)
```sql
SELECT
    ipstr(srcip) AS src,
    SUM(sentbyte) AS sent,
    SUM(rcvdbyte) AS received,
    SUM(sentbyte + rcvdbyte) AS total,
    COUNT() AS sessions
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
GROUP BY srcip
ORDER BY total DESC
LIMIT 50
```

### Top destinations (traffic)
```sql
SELECT
    ipstr(dstip) AS dst,
    dstport,
    app,
    SUM(sentbyte + rcvdbyte) AS bytes,
    COUNT() AS sessions
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
GROUP BY dstip, dstport, app
ORDER BY bytes DESC
LIMIT 100
```

### Blocked connections (traffic)
```sql
SELECT
    itime,
    ipstr(srcip) AS srcip,
    ipstr(dstip) AS dstip,
    dstport,
    proto,
    policyid,
    service
FROM $log
WHERE $filter
  AND ${BLOCKED_ACTION}
ORDER BY itime DESC
LIMIT 500
```

### Web category usage
```sql
SELECT
    catdesc,
    COUNT() AS hits,
    COUNT(DISTINCT srcip) AS users,
    SUM(sentbyte + rcvdbyte) AS bytes
FROM $log
WHERE $filter
  AND ${WEB_UTM_EVENT}
GROUP BY catdesc
ORDER BY hits DESC
LIMIT 50
```

### Application bandwidth
```sql
SELECT
    app,
    appcat,
    SUM(sentbyte + rcvdbyte) AS bytes,
    COUNT() AS sessions,
    COUNT(DISTINCT srcip) AS users
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
  AND app != ''
GROUP BY app, appcat
ORDER BY bytes DESC
LIMIT 100
```

### Virus/threat detections
```sql
SELECT
    itime,
    ipstr(srcip) AS srcip,
    ipstr(dstip) AS dstip,
    virus,
    action,
    filename,
    url
FROM $log
WHERE $filter
  AND ${AV_UTM_EVENT}
ORDER BY itime DESC
LIMIT 500
```

### IPS attacks
```sql
SELECT
    attack,
    severity,
    COUNT() AS hits,
    COUNT(DISTINCT srcip) AS attackers,
    COUNT(DISTINCT dstip) AS targets
FROM $log
WHERE $filter
  AND ${ATTACK_UTM_EVENT}
GROUP BY attack, severity
ORDER BY hits DESC
LIMIT 100
```

### Sessions over time (time series)
```sql
SELECT
    toStartOfHour(toDateTime(itime)) AS hour,
    COUNT() AS sessions,
    SUM(sentbyte + rcvdbyte) AS bytes
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
GROUP BY hour
ORDER BY hour ASC
```

### Policy hit analysis
```sql
SELECT
    policyid,
    policyname,
    COUNT() AS hits,
    SUM(sentbyte + rcvdbyte) AS bytes
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
GROUP BY policyid, policyname
ORDER BY hits DESC
LIMIT 50
```

### User activity (with username)
```sql
SELECT
    user,
    ipstr(srcip) AS srcip,
    COUNT() AS sessions,
    SUM(sentbyte + rcvdbyte) AS bytes,
    COUNT(DISTINCT dstip) AS destinations
FROM $log
WHERE $filter
  AND ${REPORT_SESSION}
  AND user != ''
GROUP BY user, srcip
ORDER BY bytes DESC
LIMIT 100
```
