# FGT Event Log (`elog`) Columns

| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `devid` | String | Device ID |
| `vd` | String | VDOM |
| `logid` | String | Log ID |
| `type` | String | `event` |
| `subtype` | String | `system`, `user`, `router`, `vpn`, `ha`, `endpoint`, `compliance`, `security-rating` |
| `level` | String | Severity |
| `msg` | String | Human-readable log message |
| `action` | String | Action taken |
| `status` | String | `success`, `failed`, `timeout` |
| `user` | String | User |
| `ui` | String | User interface (`ssh`, `web`, `console`) |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` |
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `logdesc` | String | Log description |
| `reason` | String | Reason/detail |
