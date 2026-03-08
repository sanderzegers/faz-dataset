# FGT Antivirus Log (`vlog`) Columns

| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` |
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `user` | String | User |
| `virus` | String | Virus/malware name |
| `virusid` | Int32 | Virus ID |
| `filename` | String | File name |
| `url` | String | URL (if web-based) |
| `profile` | String | AV profile name |
| `action` | String | `blocked`, `passthrough`, `quarantine` |
| `analyticssubmit` | String | Submitted to FortiSandbox |
| `utmevent` | String | AV event type — filter with `${AV_UTM_EVENT}` |
