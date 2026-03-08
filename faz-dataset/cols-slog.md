# FGT IPS/Security Log (`slog`) Columns

| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` |
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `attack` | String | Attack/signature name |
| `attackid` | Int32 | Signature ID |
| `severity` | String | `critical`, `high`, `medium`, `low`, `info` |
| `action` | String | `detected`, `dropped`, `reset`, `pass` |
| `profile` | String | IPS profile name |
| `ref` | String | Reference URL |
| `policyid` | Int32 | Policy ID |
| `utmevent` | String | `ips` — filter with `${ATTACK_UTM_EVENT}` |
