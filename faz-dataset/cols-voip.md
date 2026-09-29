# `$log-voip` — VoIP Call Signaling Logs

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| `voip_proto` | LowCardinality(String) | VoIP protocol used — use `nullifna()` |
| `kind` | LowCardinality(String) | VoIP call event type — SIP method or call state |
| `status` | LowCardinality(String) | Call/event status |
| `dir` | LowCardinality(String) | Call direction relative to the device |
| `vd` | LowCardinality(String) | VDOM name — use `nullifna()` |

## Key Patterns

```sql
-- Failed call attempts
SELECT kind, status, count(*) AS cnt
FROM $log-voip
WHERE $filter AND status != 'succeeded'
GROUP BY kind, status
ORDER BY cnt DESC

-- Registration activity by VDOM
SELECT vd, count(*) AS registrations
FROM $log-voip
WHERE $filter AND kind = 'register'
GROUP BY vd
ORDER BY registrations DESC

-- Call setup success rate
SELECT
    count(*) AS total_calls,
    sum(status = 'succeeded') AS successful,
    cast(100.0 * sum(status = 'succeeded') / count(*) AS decimal(10,2)) AS success_pct
FROM $log-voip
WHERE $filter AND kind = 'call'
```

## Real Values Discovered from FAZ Instance

### `voip_proto` (VoIP Protocol)

Observed from FAZ VoIP logs:

| Value | Notes |
|---|---|
| `sip` | Session Initiation Protocol |

### `kind` (VoIP Event Kind)

Observed from FAZ VoIP logs:

| Value | Notes |
|---|---|
| `register` | SIP registration event |
| `call` | SIP call establishment |
| `bye` | SIP hangup/teardown |
| `ack` | SIP acknowledgment |
| `invite` | SIP INVITE request |
| `cancel` | SIP cancel request |

### `status` (VoIP Status)

Observed from FAZ VoIP logs:

| Value | Notes |
|---|---|
| `succeeded` | Event completed successfully |
| `start` | Call started / in progress |
| `authentication-required` | Auth challenge issued |

### `dir` (VoIP Direction)

Observed from FAZ VoIP logs:

| Value | Notes |
|---|---|
| `session_origin` | Session originated from local endpoint |

### `vd` (VDOM)

Observed from FAZ VoIP logs:

| Value | Notes |
|---|---|
| `root` | Default VDOM |
| `ROUTING` | Routing VDOM |
