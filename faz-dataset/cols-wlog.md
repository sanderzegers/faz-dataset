# `$log-webfilter` — Web Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`hostname`** | LowCardinality(String) | Request hostname (e.g. `www.google.com`) |
| **`url`** | Nullable(String) | Full URL path |
| **`cat`** | Nullable(UInt8) | Numeric web category ID |
| **`catdesc`** | LowCardinality(String) | Category description (e.g. `"Search Engines"`) |
| **`action`** | LowCardinality(String) | `passthrough`, `blocked`, `warning`, `authenticate`, `override` |
| **`utmaction`** | LowCardinality(String) | `allow`, `block` |
| **`utmevent`** | LowCardinality(String) | `webfilter`, `banned-word`, `web-content`, `command-block`, `script-filter` |
| **`filtertype`** | LowCardinality(String) | What matched: `category`, `urlfilter`, `keyword`, `ftgd` |
| `ruletype` | LowCardinality(String) | Rule type |
| `reqtype` | LowCardinality(String) | `direct`, `referral` |
| **`keyword`** | Nullable(String) | Matched keyword (banned-word events) |
| `banword` | LowCardinality(String) | Banned word matched |
| `urlfilterlist` | Nullable(String) | URL filter list name |
| `urlfilteridx` | Nullable(UInt32) | URL filter entry index |
| `ovrdid` / `ovrdtbl` | Nullable | Override ID / table |
| `quotaused` / `quotamax` | Nullable(UInt64) | Quota bytes used/max |
| `quotatype` / `quotaexceeded` | LowCardinality | Quota type / exceeded flag |
| `contenttype` | Nullable(String) | HTTP content type |
| `referralurl` | Nullable(String) | Referral URL |
| `antiphishdc` / `antiphishrule` | Nullable(String) | Anti-phishing fields |
| `urlrisk` | Nullable(UInt8) | URL risk score |
| `risklevel` | LowCardinality(String) | URL risk level |
| `videoid` / `videocategoryid` / `videotitle` | — | YouTube/video fields |
| `sentbyte` / `rcvdbyte` | Nullable | Session bytes |
| `eventtype` | LowCardinality(String) | `ftgd-cat`, `ftgd-err`, `ftgd-block`, `urlfilter`, `override` |
| `from` / `to` | LowCardinality(String) | Email from/to (webmail) |

## Key Patterns

```sql
-- Blocked categories
SELECT catdesc, count(*) AS hits
FROM $log-webfilter
WHERE $filter
  AND utmevent IN ('webfilter','banned-word','web-content','command-block','script-filter')
  AND utmaction IN ('block','blocked','blk')
  AND catdesc IS NOT NULL
GROUP BY catdesc
ORDER BY hits DESC

-- Top sites with category
SELECT website, catdesc, sum(sessions) AS hits
FROM ###(
    SELECT hostname AS website, catdesc, count(*) AS sessions
    FROM $log-webfilter
    WHERE $filter AND hostname IS NOT NULL
    GROUP BY hostname, catdesc
    /*SkipSTART*/ORDER BY sessions DESC/*SkipEND*/
)### t
GROUP BY website, catdesc
ORDER BY hits DESC

-- ${WEB_UTM_EVENT} macro = utmevent IN ('webfilter','banned-word','web-content','command-block','script-filter')
```
