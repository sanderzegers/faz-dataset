# `$log-event` — System/Device Events

Event logs cover many subtypes with ~200 columns. All common columns apply (see cols-common.md).

## Universal Event Columns

| Column | Type | Description |
|---|---|---|
| **`subtype`** | String | `system`, `router`, `vpn`, `user`, `endpoint`, `ha`, `compliance`, `connector`, `wad`, `wanopt`, `wireless`, `netscan`, `security-rating` |
| **`logid`** | String | Specific event ID — use `logid_to_int(logid)` for numeric compare |
| **`logdesc`** | LowCardinality(String) | Log description |
| **`msg`** | Nullable(String) | Human-readable event message |
| **`user`** | LowCardinality(String) | User who triggered event |
| **`ui`** | Nullable(String) | UI method: `ssh`, `https`, `console`, `jsconsole` |
| **`action`** | LowCardinality(String) | `login`, `logout`, `set`, `add`, `delete`, `edit`, `clear` |
| `status` | Nullable(String) | Event status: `success`, `failed` |
| `result` | LowCardinality(String) | Operation result |
| `reason` | LowCardinality(String) | Reason for event |
| `error` | Nullable(String) | Error message |

## Config Change (logid 26001 family)

| Column | Type | Description |
|---|---|---|
| **`cfgtid`** | Nullable(UInt32) | Config transaction ID — `cfgtid > 0` filters config change events |
| `cfgpath` | Nullable(String) | Config object path (e.g. `firewall policy`) |
| `cfgobj` | Nullable(String) | Config object name |
| `cfgattr` | Nullable(String) | Attribute changed |
| `cfgcomment` | Nullable(String) | Change comment |
| `old_value` / `new_value` | Nullable(String) | Before/after values |

```sql
-- All config changes
SELECT from_dtime(dtime) AS ts, `user`, ui, cfgpath, cfgobj, cfgattr, old_value, new_value
FROM $log-event
WHERE $filter AND cfgtid > 0
ORDER BY dtime DESC
```

## Authentication Events

| Column | Type | Description |
|---|---|---|
| **`user`** | LowCardinality(String) | Username |
| **`srcip`** | Nullable(IPv6) | Client IP |
| `method` | LowCardinality(String) | Auth method |
| `authserver` | Nullable(String) | Auth server |
| `adgroup` | Nullable(String) | AD group |
| `reason` | LowCardinality(String) | Failure reason |

## VPN Events

| Column | Type | Description |
|---|---|---|
| **`vpntunnel`** | LowCardinality(String) | VPN tunnel name |
| `tunneltype` | Nullable(String) | `ipsec`, `ssl`, `pptp` |
| `tunnelid` | Nullable(UInt32) | Tunnel ID |
| `remip` | Nullable(IPv6) | Remote IP |
| `locip` | Nullable(IPv6) | Local IP |
| `tunnelip` | Nullable(IPv6) | Tunnel IP (assigned) |
| `assignip` | Nullable(IPv6) | Assigned IP |
| `sentbyte` / `rcvdbyte` | — | Tunnel bytes |
| `duration` | Nullable(UInt32) | Session duration |
| `init` | Nullable(String) | IKE initiator |
| `mode` / `exch` | Nullable(String) | IKE mode / exchange type |

## System Health

| Column | Type | Description |
|---|---|---|
| `cpu` | Nullable(UInt8) | CPU usage % |
| `mem` | Nullable(UInt8) | Memory usage % |
| `disk` | Nullable(UInt8) | Disk usage % |
| `totalsession` | Nullable(UInt32) | Total active sessions |
| `setuprate` | Nullable(UInt64) | Session setup rate |

## WiFi Events

| Column | Type | Description |
|---|---|---|
| `ap` | Nullable(String) | Access point name |
| `ssid` | Nullable(String) | SSID |
| `bssid` | Nullable(String) | BSSID |
| `mac` | Nullable(String) | Client MAC address |
| `stamac` | Nullable(String) | Station MAC |
| `channel` | Nullable(UInt8) | Radio channel |
| `rssi` / `signal` / `noise` | Nullable | RSSI / signal / noise |
| `radioband` | Nullable(String) | `2.4GHz`, `5GHz` |
| `security` | Nullable(String) | Security mode |
| `vap` | Nullable(String) | Virtual AP |

## SD-WAN Health Events

| Column | Type | Description |
|---|---|---|
| `healthcheck` | Nullable(String) | Health check name |
| `slamap` | Nullable(String) | SLA map |
| `latency` / `jitter` / `packetloss` | Nullable(String) | Performance metrics |
| `inbandwidthavailable` / `outbandwidthavailable` | Nullable(String) | Bandwidth available |
| `serviceid` / `slatargetid` | Nullable(UInt32) | SD-WAN service / SLA target ID |

## HA Events

| Column | Type | Description |
|---|---|---|
| `ha_role` | Nullable(String) | `master`, `slave` |
| `ha_group` | Nullable(Int16) | HA group |
| `vcluster` | Nullable(UInt32) | Virtual cluster ID |

## DHCP Events (logid 26001)

| Column | Type | Description |
|---|---|---|
| `mac` | Nullable(String) | Client MAC address |
| `interface` | Nullable(String) | Interface name |
| `devid` | String | Device ID |

```sql
-- DHCP MAC tracking pattern
concat(interface, '.', devid) AS devintf   -- unique interface key
WHERE logid_to_int(logid) = 26001
```

## logid Reference

| logid | Description |
|---|---|
| `32001` / `32002` / `32003` | Admin login success / failed / logout |
| `44547` | FortiManager config change |
| `26001` | DHCP lease assignment |
| `26003` | DHCP release/expiry |
| `20099` | Interface up/down |
| `35011`–`35013` | HA failover / split-brain |
| `22925` / `22933` / `22936` / `22938` | SD-WAN SLA events / link degraded / restored |
| `43522` / `43551` | WiFi managed AP joined / left |
