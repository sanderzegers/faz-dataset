# FGT App Control Log (`alog`) Columns

| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` |
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `user` | String | User |
| `app` | String | Application name |
| `appcat` | String | Application category |
| `appid` | Int32 | Application ID |
| `apprisk` | String | Risk: `critical`, `high`, `medium`, `low`, `elevated` |
| `action` | String | Action |
| `utmevent` | String | `app-ctrl` — filter with `${APPCTRL_UTM_EVENT}` |
| `policyid` | Int32 | Policy ID |
| `profile` | String | App control profile name |
