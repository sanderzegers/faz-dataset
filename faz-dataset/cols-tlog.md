# `$log-traffic` — Traffic/Firewall Sessions

Richest log type. Represents completed or sampled firewall sessions. All common columns apply (see cols-common.md).

## Session & Bytes

| Column | Type | Description |
|---|---|---|
| `subtype` | String | `forward`, `local`, `multicast`, `sniffer`, `ztna` |
| **`sentbyte`** | Nullable(UInt64) | Bytes sent (client→server) — closed sessions |
| **`rcvdbyte`** | Nullable(UInt64) | Bytes received (server→client) — closed sessions |
| **`sentdelta`** | Nullable(UInt64) | Delta bytes sent — long-lived sessions (prefer over `sentbyte`) |
| **`rcvddelta`** | Nullable(UInt64) | Delta bytes received — long-lived sessions (prefer over `rcvdbyte`) |
| `sentpkt` / `rcvdpkt` | Nullable(Int64) | Packets sent/received |
| `sentpktdelta` / `rcvdpktdelta` | Nullable(UInt32) | Delta packets |
| **`duration`** | Nullable(UInt32) | Session duration in seconds |
| `durationdelta` | Nullable(UInt32) | Delta duration |
| `wanin` / `wanout` | Nullable(UInt64) | WAN bytes in/out |
| `lanin` / `lanout` | Nullable(UInt64) | LAN bytes in/out |

> **Bytes pattern:** `coalesce(sentdelta, sentbyte, 0)` — delta exists for long-lived sessions, byte for closed. Always use this form for bandwidth queries.
> **logflag for bandwidth:** use `bitAnd(logflag,bitOr(1,32))>0` to include long-lived sessions.

## NAT

| Column | Type | Description |
|---|---|---|
| `tranip` / `transip` | Nullable(IPv6) | NAT translated destination/source IP |
| `tranport` / `transport` | Nullable(UInt16) | NAT translated port |
| `trandisp` | LowCardinality(String) | NAT type: `snat`, `dnat`, `noop` |
| `vip` | Nullable(String) | VIP name |

## Application

| Column | Type | Description |
|---|---|---|
| **`app`** | LowCardinality(String) | Application name — may be `"N/A"`, use `nullifna()` |
| **`appcat`** | LowCardinality(String) | Application category |
| `appid` | Nullable(UInt32) | Application ID |
| **`apprisk`** | LowCardinality(String) | Risk: `critical`, `high`, `medium`, `low`, `elevated` |
| `appact` | LowCardinality(String) | App control action |
| `applist` | LowCardinality(String) | App control profile name |
| `apps` | Array(String) | Array of app names — use `arrayJoin()` or `has()` |
| `countapp` | Nullable(UInt32) | App-ctrl UTM event count |

## UTM / Security Summary (on traffic rows)

| Column | Type | Description |
|---|---|---|
| **`utmaction`** | LowCardinality(String) | UTM action: `allow`, `block`, `passthrough` |
| **`utmevent`** | LowCardinality(String) | UTM event type: `webfilter`, `app-ctrl`, `ips`, `av`, `dns` |
| `utmsubtype` | Nullable(String) | UTM sub-event |
| **`attack`** | LowCardinality(String) | IPS attack name (summary) |
| **`virus`** | LowCardinality(String) | AV virus name (summary) |
| **`catdesc`** | LowCardinality(String) | Web category description |
| `dlpsensor` | Nullable(String) | DLP sensor triggered |
| `countav` / `countdlp` / `countemail` / `countips` / `countweb` | Nullable(UInt32) | UTM event counts per type |
| `countff` / `countssh` / `countssl` / `countdns` / `countwaf` | Nullable(UInt32) | UTM event counts per type |
| `threats` | Array(String) | Threat names |
| `threattyps` | Array(String) | Threat types |
| `threatwgts` | Array(Int32) | Threat weights |
| `threatcnts` | Array(Int16) | Threat counts |
| `threatlvls` | Array(Int8) | Threat levels |

## User Identity

| Column | Type | Description |
|---|---|---|
| **`user`** | LowCardinality(String) | Authenticated user — may be `"N/A"` |
| **`unauthuser`** | LowCardinality(String) | Unauthenticated user — may be `"N/A"` |
| `dstunauthuser` | Nullable(String) | Destination unauthenticated user |
| `dstuser` | Nullable(String) | Destination user |
| `clouduser` | Nullable(String) | Cloud user identity |
| `emstag` / `emstag2` | Nullable(String) | EMS tags from FortiClient |

## Device Fingerprinting

| Column | Type | Description |
|---|---|---|
| `devtype` | LowCardinality(String) | Source device type |
| `devcategory` | LowCardinality(String) | Source device category |
| `dstdevtype` | LowCardinality(String) | Destination device type |
| `osname` / `osversion` | LowCardinality/Nullable(String) | Source OS name/version |
| `dstosname` | LowCardinality(String) | Destination OS name |
| `srcmac` | Nullable(String) | Source MAC address |
| `srcmacvendor` | Nullable(String) | Source MAC vendor |

## HTTP-specific

| Column | Type | Description |
|---|---|---|
| `httpmethod` | Nullable(String) | `GET`, `POST`, etc. |
| `statuscode` | Nullable(String) | HTTP status code |
| `scheme` | Nullable(String) | `http`, `https` |
| `referralurl` | Nullable(String) | HTTP referral URL |
| `reqlength` / `resplength` | Nullable(UInt64) | Request/response length |
| `reqtime` / `resptime` | Nullable(UInt64) | Request/response time (μs) |

## Networking

| Column | Type | Description |
|---|---|---|
| `accessproxy` | Nullable(String) | Access proxy name |
| `tunnelid` | Nullable(UInt32) | VPN tunnel ID |
| `vwlid` | Nullable(UInt32) | SD-WAN rule ID |
| `vwlservice` / `vwlname` | Nullable(String) | SD-WAN service/policy name |

## Standard logflag Filters

```sql
-- Sessions (most queries)
WHERE $filter AND (bitAnd(logflag,1)>0)

-- Bandwidth (include long-lived)
WHERE $filter AND (bitAnd(logflag,bitOr(1,32))>0)

-- Blocked only
WHERE $filter AND (bitAnd(logflag,2)>0)

-- End users only (exclude FCT system user)
WHERE $filter AND (bitAnd(logflag,1)>0) AND (bitAnd(logflag,8)=0)
```

## Canonical User Identity Pattern

```sql
coalesce(nullifna(`user`), nullifna(`unauthuser`), ipstr(`srcip`)) AS user_src
```
