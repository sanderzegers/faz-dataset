# `$log-ssh` — SSH Log

SSH logs record SSH session activity including authentication events and connections. All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`sshaction`** | LowCardinality(String) | SSH action taken: `success`, `fail` |
| **`sshversion`** | Nullable(String) | SSH protocol version: `SSH-2.0`, `OpenSSH` |
| **`sshauthmethod`** | Nullable(String) | Authentication method used: `publickey`, `password` |
| **`sshauthstatus`** | Nullable(String) | Authentication result: `success`, `fail` |
| **`sshserver`** | Nullable(String) | SSH server identifier |
| **`action`** | LowCardinality(String) | Overall action: `allow`, `deny` |
| **`level`** | LowCardinality(String) | Log severity: `information`, `warning` |
| **`user`** | Nullable(String) | Username involved in session |
| **`srcip`** | Nullable(IPv6) | Source IP address |
| **`dstip`** | Nullable(IPv6) | Destination IP address |

## Key Patterns

```sql
-- Failed SSH authentications
SELECT from_dtime(dtime) AS ts, srcip, dstip, user, sshauthmethod, sshauthstatus
FROM $log-ssh
WHERE $filter AND sshauthstatus = 'fail'
ORDER BY dtime DESC

-- Successful SSH sessions by method
SELECT sshauthmethod, count() AS session_count
FROM $log-ssh
WHERE $filter AND sshauthstatus = 'success'
GROUP BY sshauthmethod
ORDER BY session_count DESC
```

## Real Values Discovered from FAZ Instance

### `sshaction` (SSH Action)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `success` | SSH session established successfully |
| `fail` | SSH session failed |

### `sshversion` (SSH Version)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `SSH-2.0` | SSH Protocol Version 2.0 |
| `OpenSSH` | OpenSSH implementation |

### `sshauthmethod` (SSH Authentication Method)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `publickey` | Public key authentication |
| `password` | Password authentication |

### `sshauthstatus` (SSH Authentication Status)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `success` | Authentication succeeded |
| `fail` | Authentication failed |

### `action` (SSH Action)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `allow` | Session allowed through |
| `deny` | Session denied |

### `level` (SSH Level)

Observed from FAZ SSH logs:

| Value | Notes |
|---|---|
| `information` | Routine SSH activity |
| `warning` | SSH warnings or failures |

### `user` (SSH User)

Observed usernames from FAZ SSH logs:

| Pattern | Notes |
|---|---|
| `{CORP}` | Corporate usernames |
