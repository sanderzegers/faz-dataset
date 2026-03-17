# `$log-attack` — IPS / Intrusion Prevention

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`attack`** | LowCardinality(String) | Attack/signature name — use `nullifna()` |
| **`attackid`** | Nullable(UInt32) | Numeric attack ID |
| **`severity`** | LowCardinality(String) | `critical`, `high`, `medium`, `low`, `info`, `debug` |
| **`direction`** | LowCardinality(String) | `incoming`, `outgoing` |
| `ref` | Nullable(String) | External reference URL |
| `attackcontext` | Nullable(String) | Attack context data |
| `attackcontextid` | Nullable(String) | Attack context ID |
| `count` | Nullable(UInt32) | Hit count (aggregated events) |
| `threat` | LowCardinality(String) | Threat name |
| `threattype` | LowCardinality(String) | Threat type |
| `threatlevel` | Nullable(Int8) | Numeric threat level |
| `icmpid` / `icmptype` / `icmpcode` | Nullable(String) | ICMP fields for ICMP-based attacks |
| **`action`** | LowCardinality(String) | `detected`, `blocked`, `dropped`, `reset`, `pass_session` |

## Key Patterns

```sql
-- Blocked = action NOT IN ('detected','pass_session')
sum(CASE WHEN action NOT IN ('detected','pass_session') THEN 1 ELSE 0 END) AS blocked

-- Victim/attacker based on direction
CASE WHEN direction='incoming' THEN ipstr(srcip) ELSE ipstr(dstip) END AS victim
CASE WHEN direction='incoming' THEN ipstr(dstip) ELSE ipstr(srcip) END AS attacker

-- Top attacks with block rate
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
