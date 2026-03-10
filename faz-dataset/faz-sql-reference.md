# FortiAnalyzer SQL Dialect Reference

## Pipeline

```
GUI Dataset SQL
  ↓ FazReportSQL.parseFazKeyword()   (expands $log-*, $filter, ${MACRO}, ###...###)
  ↓ sql_rewriter (ANTLR4 Flask — dialect rewrite to ClickHouse SQL)
  ↓ ClickHouse (log data) / PostgreSQL (identity, SIEM — proxied via CH)
```

---

## Log Source Variables

| Variable | Log Category |
|---|---|
| `$log` | Same as dataset's `log_category` setting |
| `$log-traffic` | Traffic/firewall sessions |
| `$log-webfilter` | Web filter events |
| `$log-app-ctrl` | Application control |
| `$log-attack` | IPS/attack events |
| `$log-virus` | Antivirus events |
| `$log-event` | System/device events |
| `$log-dlp` | Data loss prevention |
| `$log-dns` | DNS filter events |
| `$log-emailfilter` | Email filter |
| `$log-fct-traffic` | FortiClient traffic |
| `$log-fct-event` | FortiClient events |
| `$log-file-filter` | File filter events |

**Rules:**
- Always use `$log-{type}` — never hardcode `sp1_FGT_tlog` etc.
- Set `log_category` on the dataset to match the primary log source.

---

## Filter Variables

| Variable | Use |
|---|---|
| `$filter` | **Always required** on raw log queries — injects time range + device scope |
| `$dev_filter` | Device-only filter (no time range) — for non-log table joins |
| `$last3day_period $filter` | Rolling 3-day lookback (prepend before `$filter`) |
| `$pre_period` | Period before current window — for before/after comparisons |
| `$filter-drilldown` | Drilldown filter on outer query only (built-in datasets only) |
| `$cust_time_filter(col)` | Time filter for non-log tables (`$event`, `$incident`) |
| `$cust_time_filter(col, TODAY)` | Same with preset: `TODAY`, `YESTERDAY`, `LAST_N_PERIOD,1` |
| `$adom_oid` | Integer ADOM OID — rarely needed directly |

```sql
-- 3-day lookback pattern
WHERE $last3day_period $filter AND logid_to_int(logid) = 26001

-- Before/after comparison
WHERE ($pre_period OR $filter) AND (bitAnd(logflag,1)>0)
```

---

## Time Variables

| Variable | Use |
|---|---|
| `$flex_timestamp` | Groups rows into time buckets — use in inner GROUP BY |
| `$flex_timescale(col)` | Formats bucketed timestamp for display — use in outer SELECT |
| `$fv_line_timescale(col)` | Like `$flex_timescale` but for `fv_*` materialized views |
| `$hour_of_day` | Hour 0–23 bucket |
| `$hour_of_day(col)` | Hour from explicit column |
| `$day_of_week` | Day 0–6 (0=Sunday) |
| `$DAY_OF_MONTH` | Day 1–31 |
| `$calendar_time` | Calendar-aligned bucket (midnight/hour boundary) |
| `$flex_timestamp(col)` | Bucket by explicit column instead of `itime` |
| `$start_time` / `$end_time` | Report period start/end Unix timestamps |
| `$timespan` | Report period duration in seconds |

```sql
-- Standard time series pattern
SELECT $flex_timescale(timestamp) AS hodex, sum(bytes) AS bytes
FROM ###(
    SELECT $flex_timestamp AS timestamp, sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bytes
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp
)### t
GROUP BY hodex
HAVING sum(bytes) > 0
ORDER BY hodex
```

---

## ${MACRO} Expansions

| Macro | Expands to |
|---|---|
| `${REPORT_SESSION}` | `(bitAnd(logflag,1)>0)` |
| `${REPORT_SESSION_WITH_LONGLIVE}` | `(bitAnd(logflag,bitOr(1,32))>0)` |
| `${BLOCKED_ACTION}` | `(bitAnd(logflag,2)>0)` |
| `${IS_BOTNET}` | `(bitAnd(logflag,16)>0)` |
| `${IS_FCT_ENDUSER}` | `(logflag is null or bitAnd(logflag,8)=0)` |
| `${WEB_UTM_EVENT}` | `utmevent in ('webfilter','banned-word','web-content','command-block','script-filter')` |
| `${AV_UTM_EVENT}` | `utmevent is not null and virus is not null` |
| `${APPCTRL_UTM_EVENT}` | `utmevent in ('app-ctrl')` |
| `${ATTACK_UTM_EVENT}` | `utmevent in ('ips')` |
| `${EMAIL_SEND_SERVICE}` | `service IN ('smtp','SMTP','25/tcp','587/tcp','smtps','SMTPS','465/tcp')` |

---

## logflag Bitmask (traffic log)

| Bit | Value | Meaning | Use when |
|---|---|---|---|
| 0 | 1 | `REPORT_SESSION` | Session counted in reports | Almost always |
| 1 | 2 | `BLOCKED_ACTION` | Action was blocked | Blocked-only queries |
| 2 | 4 | `CLOUD_APP` | Cloud app session | Cloud app queries |
| 3 | 8 | `FCT_SYSUSR` | FortiClient system user | Exclude for end-user only |
| 4 | 16 | `BOTNET` | Botnet session | Botnet queries |
| 5 | 32 | `LONGLIVE_SESSION` | Long-lived session | Include with bandwidth |

```sql
WHERE $filter AND (bitAnd(logflag,1)>0)              -- sessions
WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)    -- sessions + long-lived (bandwidth)
WHERE $filter AND (bitAnd(logflag,2)>0)              -- blocked only
WHERE $filter AND (bitAnd(logflag,1)>0) AND (bitAnd(logflag,8)=0)  -- exclude FCT system users
```

---

## HCache Mechanism (`###...###`)

Executes inner subquery once, caches result, outer query reads from cache. Use when:
- You need to filter on a computed/aliased column
- Two levels of aggregation needed
- Multiple datasets share the same base scan
- Time series queries (standard pattern)

**Basic syntax:**
```sql
SELECT col_a, sum(col_b) AS total
FROM ###(
    SELECT col_a, col_b, col_c
    FROM $log
    WHERE $filter
    GROUP BY col_a, col_b, col_c
    /*SkipSTART*/ORDER BY col_b DESC/*SkipEND*/
)### t
WHERE col_c = 'some_value'
GROUP BY col_a
ORDER BY total DESC
```

The alias `t` after `###` is required.

**Named base cache (shared across datasets in same report):**
```sql
###base(/*tag:rpt_base_t_bndwdth_sess*/
    SELECT $flex_timestamp AS timestamp,
           dvid, srcip, dstip, epid, euid, appcat, apprisk,
           coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           service,
           sum(CASE WHEN (bitAnd(logflag,1)>0) THEN 1 ELSE 0 END) AS sessions,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth,
           sum(coalesce(sentdelta,sentbyte,0)) AS traffic_out,
           sum(coalesce(rcvddelta,rcvdbyte,0)) AS traffic_in
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp, dvid, srcip, dstip, epid, euid, appcat, apprisk, user_src, service
    /*SkipSTART*/ORDER BY bandwidth DESC, sessions DESC/*SkipEND*/
)base###
```

**What goes inside vs outside hcache:**
- Inside: `FROM $log-*` with `$filter`, all columns you may need to filter/group by, `/*SkipSTART*/ORDER BY.../*SkipEND*/`
- Outside: final re-aggregation, `WHERE` on computed columns, `HAVING`, final `ORDER BY`/`LIMIT`, `$flex_timescale()`

---

## `/*SkipSTART*/`/`/*SkipEND*/` Hint

Tells the engine to include ORDER BY when populating hcache but skip it in other contexts. Always use inside `###(...)###` for sorted top-N cache:

```sql
FROM ###(
    SELECT user_src, count(*) AS sessions
    FROM $log WHERE $filter
    GROUP BY user_src
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
```

---

## ADOM Reference Tables

| Variable | Contains |
|---|---|
| `$ADOM_ENDPOINT` | Endpoint devices — join on `epid`; filter `epid > 1024` |
| `$ADOM_ENDUSER` | End users — join on `euid`; filter `euid > 1024` |
| `$ADOM_EPEU_DEVMAP` | Endpoint↔user device mapping |
| `$ADOM_INTF_INFO` | Interface information |
| `$ADOM_INTF_STATS` | Interface statistics |
| `$ADOM_SDWAN_INTF_INFO` | SD-WAN interface info |
| `$ADOMTBL_PLHD_POLINFO` | Policy info — join via `poluuid = polinfo.uuid` |
| `$ADOMTBL_PLHD_AUDIT_HST` | Audit history |
| `$ADOMTBL_PLHD_IOC_VERDICT` | IoC verdict data |

**Endpoint join pattern:**
```sql
LEFT JOIN $ADOM_ENDPOINT ep ON (CASE WHEN epid < 1024 THEN NULL ELSE epid END) = ep.epid
LEFT JOIN $ADOM_ENDUSER eu  ON (CASE WHEN euid < 1024 THEN NULL ELSE euid END) = eu.euid
```

**`devtable_ext`** — resolve `dvid` to device name:
```sql
LEFT JOIN devtable_ext d ON e.dvid = d.dvid
-- columns: dvid, devname, devtype, devid
```

---

## SOC Event and Incident Tables

| Variable | Description | Time filter column |
|---|---|---|
| `$event` | SIEM alerts | `alerttime` |
| `$incident` | SIEM incidents | `createtime` |
| `$event_history` | Pre-aggregated alert counts | `agg_time` |
| `$incident_history` | Pre-aggregated incident counts | `agg_time` |

**`$event` key columns:** `alertid`, `alerttime`, `dvid`, `severity` (0=Critical,1=High,2=Medium,3=Low), `triggername`, `tag`, `epip`, `epname`, `euname`, `subject`, `eventtype`, `groupby1/2/3`, `logcount`, `firstlogtime`, `lastlogtime`, `assignto`

**`$incident` key columns:** `incid` (use `incid_to_str(incid)`), `severity` (String: `critical/high/medium/low`), `status` (`draft/analysis/response/closed/cancelled`), `createtime`, `category`, `endpoint`, `description`, `assigned_to`

**`$event_history` columns:** `agg_time`, `num_sev_critical`, `num_sev_high`, `num_sev_medium`, `num_sev_low`, `num_total`

**`$incident_history` columns:** `agg_time`, `num_sta_draft`, `num_sta_analysis`, `num_sta_response`, `num_sta_closed`, `num_sta_cancelled`, `num_sev_critical`, `num_sev_high`, `num_sev_medium`, `num_sev_low`, `num_endpoint`

```sql
-- Alert severity decode
CASE severity WHEN 0 THEN 'Critical' WHEN 1 THEN 'High' WHEN 2 THEN 'Medium' WHEN 3 THEN 'Low' END

-- Open incidents
SELECT incid_to_str(incid) AS incnum, from_itime(createtime) AS ts, severity, status
FROM $incident
WHERE $cust_time_filter(createtime) AND status NOT IN ('closed','cancelled')
```

---

## `/*fabricStart*/`/`/*fabricEnd*/` Hint

For SOC datasets (`log_category: ""`) that aggregate across all ADOMs. Wraps per-ADOM subquery in a UNION ALL:

```sql
SELECT status, sum(cnt) AS cnt
FROM
  /*fabricStart*/
  (SELECT status, count(*) AS cnt FROM $incident WHERE $filter-drilldown GROUP BY status)
  /*fabricEnd*/
  t
GROUP BY status
```

Do NOT use in `$log-*` datasets — those are already ADOM-scoped via `$filter`.

---

## Multi-Statement Queries (Temp Tables)

```sql
DROP TABLE IF EXISTS rpt_tmptbl_1;
DROP TABLE IF EXISTS rpt_tmptbl_2;

CREATE TEMPORARY TABLE rpt_tmptbl_1 AS
SELECT col FROM ###(...)### t GROUP BY col;

CREATE TEMPORARY TABLE rpt_tmptbl_2 AS
SELECT col FROM ###(...)### t GROUP BY col;

-- Final SELECT (no trailing semicolon)
SELECT t2.col, CASE WHEN t1.col IS NULL THEN 'New' ELSE 'Existing' END AS status
FROM rpt_tmptbl_2 t2
LEFT JOIN rpt_tmptbl_1 t1 ON t2.col = t1.col
```

Rules: always DROP before CREATE, name as `rpt_tmptbl_N`, separate with `;`, final SELECT has no `;`.

---

## Essential Helper Functions

| Function | Use |
|---|---|
| `ipstr(col)` | IPv6 col → clean IPv4/IPv6 string — **always use for display/compare** |
| `nullifna(col)` | Returns NULL if value is `"N/A"`, `"n/a"`, or `"null"` — use on `user`, `app` etc. |
| `coalesce(nullifna(\`user\`), nullifna(\`unauthuser\`), ipstr(\`srcip\`))` | Canonical user identity expression |
| `from_itime(col)` | Unix epoch Int32 → readable datetime string |
| `from_dtime(col)` | Device time → readable datetime string |
| `logid_to_int(logid)` | logid String → Int for numeric compare |
| `root_domain(hostname)` | `mail.google.com` → `google.com` |
| `app_group_name(app)` | App name → application group |
| `virusid_to_str(virusid)` | Numeric virus ID → string name |
| `incid_to_str(incid)` | Numeric incident ID → `"INC-00042"` |
| `get_devtype(n)` | Numeric device type → string |
| `bandwidth_unit(bytes)` | Bytes → human-readable string (display only) |
| `string_agg(distinct col, ',')` | Concat distinct string values |
| `arrayJoin(array_col)` | Unnest array to rows |
| `has(array_col, 'value')` | Test array membership |
| `split_part(col, ',', 1)` | Nth part after split — for FCT `os` column |
| `left(col, n)` | Truncate string to n chars |
| `JSONExtractString(col, key)` | Extract string from JSON column |
| `bitAnd(a, b)` / `bitOr(a, b)` | Bitwise operations for logflag |

---

## Common Query Patterns

### Pattern A: Simple Top-N
```sql
SELECT catdesc, count(*) AS hits
FROM $log-webfilter
WHERE $filter AND utmaction IN ('block','blocked','blk') AND catdesc IS NOT NULL
GROUP BY catdesc
ORDER BY hits DESC
```

### Pattern B: Top-N with HCache
```sql
SELECT user_src, sum(sessions) AS sessions
FROM ###(
    SELECT coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           count(*) AS sessions
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,1)>0)
    GROUP BY user_src
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
GROUP BY user_src
ORDER BY sessions DESC
```

### Pattern C: Bandwidth Top Users
```sql
SELECT user_src,
       sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
FROM ###(
    SELECT coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src,
           sum(coalesce(sentdelta,sentbyte,0)+coalesce(rcvddelta,rcvdbyte,0)) AS bandwidth
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY user_src
    /*SkipSTART*/ORDER BY bandwidth DESC/*SkipEND*/
)### t
GROUP BY user_src
ORDER BY bandwidth DESC
```

### Pattern D: Time Series
```sql
SELECT $flex_timescale(timestamp) AS hodex, sum(traffic_out) AS out, sum(traffic_in) AS in
FROM ###(
    SELECT $flex_timestamp AS timestamp,
           sum(coalesce(sentdelta,sentbyte,0)) AS traffic_out,
           sum(coalesce(rcvddelta,rcvdbyte,0)) AS traffic_in
    FROM $log-traffic
    WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)
    GROUP BY timestamp
)### t
GROUP BY hodex
HAVING sum(traffic_out+traffic_in) > 0
ORDER BY hodex
```

### Pattern E: IPS Attack with Block Rate
```sql
SELECT attack,
       sum(totalnum) AS totalnum,
       cast(100.0 * sum(blocked) / sum(totalnum) AS decimal(10,2)) AS block_pct
FROM ###(
    SELECT attack,
           count(*) AS totalnum,
           sum(CASE WHEN action NOT IN ('detected','pass_session') THEN 1 ELSE 0 END) AS blocked
    FROM $log-attack
    WHERE $filter AND nullifna(attack) IS NOT NULL
    GROUP BY attack
    /*SkipSTART*/ORDER BY totalnum DESC/*SkipEND*/
)### t
GROUP BY attack
ORDER BY totalnum DESC
```

### Pattern F: Direction-based attacker/victim (IPS)
```sql
SELECT
    CASE WHEN direction='incoming' THEN ipstr(srcip) ELSE ipstr(dstip) END AS attacker,
    CASE WHEN direction='incoming' THEN ipstr(dstip) ELSE ipstr(srcip) END AS victim,
    count(*) AS hits
FROM $log-attack
WHERE $filter
GROUP BY attacker, victim
ORDER BY hits DESC
```

---

## Common Mistakes

1. **Missing `$filter`** — always include on raw log queries
2. **Filter on computed column without hcache** — `WHERE user_src IS NOT NULL` requires hcache
3. **Raw IP display** — always use `ipstr(srcip)`, not raw `srcip`
4. **N/A strings** — use `nullifna(user)` not `user IS NOT NULL`
5. **logflag missing** — traffic queries without `bitAnd(logflag,1)>0` inflate counts
6. **Bandwidth without logflag=32** — use `bitOr(1,32)` to include long-lived sessions
7. **Hardcoded table names** — use `$log-traffic` not `siem.sp1_FGT_tlog`
8. **HAVING vs WHERE** — can't `WHERE sum(x) > 0`, use `HAVING sum(x) > 0`
9. **epid/euid < 1024** — system IDs, null out before joining
10. **`$filter-drilldown` inside hcache** — must go on outer query only

---

## Key Enum Values

### `action` (traffic): `accept`, `deny`, `close`, `drop`, `server-rst`, `client-rst`, `timeout`, `ip-conn`
### `action` (UTM): `passthrough`, `blocked`, `detected`, `block`, `pass`, `reset`, `dropped`
### `utmaction`: `allow`, `block`, `passthrough`
### `utmevent`: `webfilter`, `app-ctrl`, `ips`, `av`, `dns`, `emailfilter`, `dlp`, `file-filter`, `ssh`, `ssl`
### `apprisk`: `critical`, `high`, `medium`, `low`, `elevated`
### `direction`: `incoming`, `outgoing`
### `level`: `emergency`, `alert`, `critical`, `error`, `warning`, `notice`, `information`, `debug`
### `subtype` (traffic): `forward`, `local`, `multicast`, `sniffer`, `ztna`
### `subtype` (event): `system`, `router`, `vpn`, `user`, `endpoint`, `ha`, `compliance`, `connector`, `wad`, `wanopt`, `wireless`, `netscan`, `security-rating`
### `proto` (UInt8): `1`=ICMP, `6`=TCP, `17`=UDP, `47`=GRE, `50`=ESP, `89`=OSPF

---

## Column Type Gotchas

- **IP columns** (`srcip`, `dstip`): `Nullable(IPv6)` — IPv4 stored as `::ffff:192.168.1.1`. Always `ipstr()`.
- **`sentbyte` vs `sentdelta`**: use `coalesce(sentdelta, sentbyte, 0)` — delta for long-lived, byte for closed sessions.
- **`itime` vs `dtime`**: `$filter` filters on `itime`; use `from_dtime(dtime)` for device-local time display.
- **`logid`**: `LowCardinality(String)` — use `logid_to_int(logid)` for numeric compare.
- **`N/A` sentinels**: `user`, `unauthuser`, `app` columns use `"N/A"` instead of NULL — always `nullifna()`.
- **`epid`/`euid` < 1024**: system-reserved, meaningless for joins — guard with `CASE WHEN epid < 1024 THEN NULL`.
- **`fct-event` logid**: `UInt64` not String — do NOT use `logid_to_int()`.

---

## logid Reference (FortiGate Events)

| logid | Category | Description |
|---|---|---|
| `32001` | Auth | Admin login success |
| `32002` | Auth | Admin login failed |
| `32003` | Auth | Admin logout |
| `44547` | Config | FortiManager config change |
| `26001` | DHCP | DHCP lease assignment (MAC, IP, interface) |
| `26003` | DHCP | DHCP release/expiry |
| `20099` | Interface | Interface up/down |
| `22105`–`22109` | Hardware | PSU/fan/temperature faults |
| `35011`–`35013` | HA | HA failover / split-brain |
| `37892`–`37908` | HA | HA member join/leave/sync |
| `22925`/`22933`/`22936`/`22938` | SD-WAN | SLA events, link degraded/restored |
| `43521`–`43585` | WiFi | Rogue AP / managed AP join/leave |
| `9233` | Sandbox | FortiSandbox file scan result |

Config change filter: `WHERE $filter AND cfgtid > 0`

---

## Quick Reference Card

```
Log sources:     $log-traffic  $log-webfilter  $log-app-ctrl  $log-attack
                 $log-virus  $log-event  $log-dns  $log-dlp
                 $log-emailfilter  $log-fct-traffic  $log-fct-event  $log-file-filter

Filters:         $filter                        (always required on raw logs)
                 $dev_filter                    (device only, no time)
                 $last3day_period $filter        (3-day lookback)
                 $pre_period                    (previous period comparison)
                 $cust_time_filter(alerttime)   (SOC tables)

Time:            $flex_timestamp               (inner GROUP BY — integer bucket)
                 $flex_timescale(col)          (outer SELECT — formatted)
                 $hour_of_day                  (hour 0–23)
                 $day_of_week / $DAY_OF_MONTH

HCache:          ###(inner)### t               (anonymous)
                 ###base(/*tag:lbl*/...)base### (named/shared)
                 /*SkipSTART*/ORDER BY.../*SkipEND*/

User identity:   coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`))
Bytes:           coalesce(sentdelta,sentbyte,0)  /  coalesce(rcvddelta,rcvdbyte,0)
IP display:      ipstr(`srcip`)
logflag:         bitAnd(logflag,1)>0   /   bitAnd(logflag,bitOr(1,32))>0

ADOM tables:     $ADOM_ENDPOINT  $ADOM_ENDUSER  $ADOM_EPEU_DEVMAP
                 $ADOMTBL_PLHD_POLINFO
SOC tables:      $event (alerttime)  $incident (createtime)
                 $event_history  $incident_history

Fabric hint:     /*fabricStart*/ (per-ADOM subquery) /*fabricEnd*/
Avoid:           ebtr_agg_flat()  ebtr_value()  — NOT installed
```
