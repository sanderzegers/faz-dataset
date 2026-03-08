# FGT Web Filter Log (`wlog`) Columns

| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` |
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `user` | String | User |
| `url` | String | Full URL |
| `hostname` | String | Hostname |
| `referralurl` | String | Referrer URL |
| `catdesc` | String | Web category description |
| `cat` | Int32 | Web category ID |
| `action` | String | `passthrough`, `blocked`, `warning` |
| `utmevent` | String | UTM event type — filter with `${WEB_UTM_EVENT}` |
| `policyid` | Int32 | Policy ID |
| `profile` | String | Web filter profile name |
| `sentbyte` | Int64 | Bytes sent |
| `rcvdbyte` | Int64 | Bytes received |
