# FGT Traffic Log (`tlog`) Columns

### Identification
| Column | Type | Description |
|---|---|---|
| `itime` | Int32 | Log receive time (Unix epoch) |
| `devid` | String | Device ID |
| `vd` | String | Virtual domain (VDOM) name |
| `logid` | String | Log ID |
| `type` | String | `traffic` |
| `subtype` | String | `forward`, `local`, `multicast`, `sniffer` |
| `level` | String | Severity |
| `sessionid` | UInt32 | Firewall session ID |

### Source
| Column | Type | Description |
|---|---|---|
| `srcip` | Nullable(IPv6) | Source IP — use `ipstr(srcip)` to display |
| `srcport` | Int32 | Source port |
| `srcintf` | String | Source interface |
| `srcintfrole` | String | Interface role (lan/wan/dmz) |
| `srcmac` | String | Source MAC |
| `srccountry` | String | Source country |
| `srcuuid` | String | Source address object UUID |
| `srcserver` | Int32 | Source is a server (1/0) |

### Destination
| Column | Type | Description |
|---|---|---|
| `dstip` | Nullable(IPv6) | Destination IP — use `ipstr(dstip)` |
| `dstport` | Int32 | Destination port |
| `dstintf` | String | Destination interface |
| `dstintfrole` | String | Interface role |
| `dstcountry` | String | Destination country |
| `dstuuid` | String | Destination address object UUID |

### NAT
| Column | Type | Description |
|---|---|---|
| `tranip` | Nullable(IPv6) | Translated (NAT) destination IP |
| `tranport` | Int32 | Translated destination port |
| `transip` | Nullable(IPv6) | Translated source IP |
| `transport` | Int32 | Translated source port |

### Protocol / Service / Policy
| Column | Type | Description |
|---|---|---|
| `proto` | Int32 | IP protocol (6=TCP, 17=UDP, 1=ICMP) |
| `service` | String | Service name (e.g. `HTTPS`, `DNS`) |
| `policyid` | Int32 | Policy ID (0 = implicit deny) |
| `policyname` | String | Policy name |
| `policytype` | String | Policy type |
| `poluuid` | String | Policy UUID |

### Action / Bytes / Duration
| Column | Type | Description |
|---|---|---|
| `action` | String | `accept`, `deny`, `close`, `ip-conn`, `timeout` |
| `logflag` | Nullable(Int32) | Bitmask flags — use `${MACRO}` or `bitAnd()` |
| `sentbyte` | Int64 | Bytes sent (client→server) |
| `rcvdbyte` | Int64 | Bytes received (server→client) |
| `sentpkt` | Int64 | Packets sent |
| `rcvdpkt` | Int64 | Packets received |
| `duration` | Int32 | Session duration (seconds) |

### User
| Column | Type | Description |
|---|---|---|
| `user` | String | Authenticated username |
| `srcuser` | String | Source user |
| `group` | String | User group |
| `authserver` | String | Authentication server |

### Application (UTM)
| Column | Type | Description |
|---|---|---|
| `app` | String | Application name |
| `appcat` | String | Application category |
| `applist` | String | App control profile |
| `appid` | Int32 | Application ID |
| `apprisk` | String | Risk level |
| `utmaction` | String | UTM action |
| `utmevent` | String | UTM event type |
| `countapp` | Int32 | App ctrl event count |
| `countweb` | Int32 | Web filter event count |
| `countav` | Int32 | AV event count |
| `countips` | Int32 | IPS event count |

### Array columns (use `arrayJoin()` or `has()`)
| Column | Type | Description |
|---|---|---|
| `threats` | Array(String) | Threat names |
| `threattyps` | Array(String) | Threat types |
| `apps` | Array(String) | All application names in session |
| `threatwgts` | Array(Int32) | Threat weights |
| `threatcnts` | Array(Int16) | Threat counts |
| `threatlvls` | Array(Int8) | Threat severity levels |
