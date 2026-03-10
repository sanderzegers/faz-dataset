# `$log-dns` — DNS Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`qname`** | LowCardinality(String) | DNS query name (domain queried) |
| **`qtype`** | Nullable(String) | Query type: `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`, `SRV` |
| `qtypeval` | Nullable(UInt16) | Numeric query type |
| `qclass` | LowCardinality(String) | Query class (`IN`) |
| `exchange` | Nullable(String) | MX exchange value |
| `ipaddr` | Array(IPv6) | Resolved IP addresses — use `arrayJoin(ipaddr)` + `ipstr()` |
| **`botnetdomain`** | Nullable(String) | Botnet domain if matched |
| **`botnetip`** | Nullable(IPv6) | Botnet IP if matched — use `ipstr()` |
| `cat` | Nullable(UInt8) | Web category for domain |
| **`catdesc`** | LowCardinality(String) | Category description |
| `domainfilteridx` | Nullable(UInt8) | Domain filter entry index |
| `domainfilterlist` | Nullable(String) | Domain filter list name |
| `xid` | Nullable(UInt16) | DNS transaction ID |
| `rcode` | Nullable(UInt32) | DNS response code (0=NOERROR, 3=NXDOMAIN) |
| `sscname` | Nullable(String) | Safe Search enforced CNAME |
| `eventtype` | LowCardinality(String) | `dns-query`, `domain`, `botnet` |
| `error` | Nullable(String) | DNS error |

## Key Patterns

```sql
-- Resolved IPs from DNS queries
SELECT qname, ipstr(arrayJoin(ipaddr)) AS resolved_ip
FROM $log-dns
WHERE $filter AND length(ipaddr) > 0

-- Botnet domain queries
SELECT botnet, count(DISTINCT nullifna(`qname`)) AS qname_cnt,
       count(DISTINCT ipstr(`srcip`)) AS src_cnt, sum(total_num) AS total_num
FROM ###(
    SELECT coalesce(nullifna(`botnetdomain`), ipstr(`botnetip`)) AS botnet,
           nullifna(`qname`) AS qname, srcip,
           count(*) AS total_num
    FROM $log-dns
    WHERE $filter AND (nullifna(`botnetdomain`) IS NOT NULL OR `botnetip` IS NOT NULL)
    GROUP BY botnet, qname, srcip
    /*SkipSTART*/ORDER BY total_num DESC/*SkipEND*/
)### t
GROUP BY botnet
ORDER BY total_num DESC
```
