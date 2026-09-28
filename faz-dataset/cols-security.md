# `$log-security` — Security Event

Security event logs covering intrusion prevention, malware detection, policy violations, and unauthorized access events. All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`securityaction`** | LowCardinality(String) | Action taken: `allow`, `block` |
| **`securitytype`** | LowCardinality(String) | Event type: `intrusion`, `malware`, `policy`, `unauthorized` |
| **`securityseverity`** | LowCardinality(String) | Severity: `critical`, `high`, `medium`, `low` |
| **`securitycategory`** | LowCardinality(String) | Category: `network`, `endpoint`, `application`, `data` |
| `attacker` / `victim` | — | Source / destination IP pair |
| `attackerport` / `victimport` | — | Source / destination port |
| `attacktype` | Nullable(String) | Specific attack type |
| `attackeros` / `victimos` | Nullable(String) | OS fingerprint |
| `attackname` | Nullable(String) | Attack name |
| `devname` / `devvdom` | — | Device name / VDOM |
| `poluuid` | Nullable(String) | Policy UUID that matched |
| `policyid` | Nullable(UInt32) | Policy ID |
| `sentpkt` / `rcvdpkt` | Nullable(UInt64) | Packets sent / received |
| `sentbyte` / `rcvdbyte` | — | Bytes sent / received |
| `service` | Nullable(String) | Service name |
| `srcintf` / `dstintf` | — | Source / destination interface |
| `srcintfrole` / `dstintfrole` | — | Source / destination interface role |
| `tzsrc` / `tzdst` | Nullable(String) | Timezone |
| `utmmode` | LowCardinality(String) | UTM mode: `proxy`, `flow` |

## Key Pattern

```sql
-- Security events by type and severity
SELECT securitytype, securityseverity, count(*) AS events
FROM $log-security
WHERE $filter
GROUP BY securitytype, securityseverity
ORDER BY events DESC
```

## Real Values Discovered from FAZ Instance

### `securityaction` (Security Action)

Observed from FAZ security logs:

| Value | Notes |
|---|---|
| `allow` | Allowed through |
| `block` | Blocked |

### `securitytype` (Security Event Type)

| Value | Notes |
|---|---|
| `intrusion` | Intrusion prevention event |
| `malware` | Malware detection event |
| `policy` | Policy violation event |
| `unauthorized` | Unauthorized access event |

### `securityseverity` (Security Severity)

| Value | Notes |
|---|---|
| `critical` | Critical severity |
| `high` | High severity |
| `medium` | Medium severity |
| `low` | Low severity |

### `securitycategory` (Security Category)

| Value | Notes |
|---|---|
| `network` | Network-level security event |
| `endpoint` | Endpoint security event |
| `application` | Application-layer security event |
| `data` | Data security event |

### `action` (Security Action — common column)

| Value | Notes |
|---|---|
| `allow` | Allowed |
| `block` | Blocked |

### `level` (Security Level)

| Value | Notes |
|---|---|
| `notice` | Notice-level event |
| `information` | Informational event |
| `warning` | Warning-level event |
