# `$log-dlp` — Data Loss Prevention

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`severity`** | LowCardinality(String) | `critical`, `high`, `medium`, `low`, `info` |
| **`direction`** | LowCardinality(String) | `incoming`, `outgoing` |
| **`filtertype`** | LowCardinality(String) | DLP filter type |
| `filtercat` | LowCardinality(String) | DLP filter category |
| `ruleid` | Nullable(UInt32) | DLP rule ID |
| **`rulename`** | Nullable(String) | DLP rule name |
| **`filename`** | Nullable(String) | Intercepted filename |
| **`filetype`** | LowCardinality(String) | File type |
| **`filesize`** | Nullable(UInt64) | File size in bytes |
| `sensitivity` | Nullable(String) | Sensitivity classification |
| `docsource` | Nullable(String) | Document source |
| `dlpextra` | Nullable(String) | Extra DLP data |
| **`from`** | LowCardinality(String) | Email from |
| **`to`** | LowCardinality(String) | Email to |
| `sender` / `recipient` | LowCardinality(String) | Sender/recipient |
| **`subject`** | LowCardinality(String) | Email subject |
| `cc` | Nullable(String) | CC recipients |
| `attachment` | Nullable(String) | Attachment info |
| `eventtype` | LowCardinality(String) | DLP event type |
| `subservice` | Nullable(String) | Sub-service |
| `sentbyte` / `rcvdbyte` | — | Bytes |
| `infectedfilename` / `infectedfiletype` / `infectedfilesize` / `infectedfilelevel` | — | Inner file that matched (e.g. inside an archive) — seen on FAZ 7.6 |

## Real Values Discovered from FAZ Instance

> No DLP logs were found in the queried time window (2026-09-21 to 2026-09-28).
> Values below are from the FAZ 7.6.6 reference.

### `action` (DLP Action)

| Value | Notes |
|---|---|
| `allow` | Allowed |
| `block` | Blocked |
| `monitor` | Monitored |
| `exempt` | Exempted |

### `category` (DLP Category)

| Value | Notes |
|---|---|
| `credit-card` | Credit card numbers |
| `ssn` | Social Security Numbers |
| `confidential` | Confidential content |
| `pii` | Personally identifiable information |
| `custom` | Custom patterns |

### `subtype` (DLP Subtype)

| Value | Notes |
|---|---|
| `email` | Email DLP |
| `web` | Web DLP |
| `file-transfer` | File transfer DLP |
| `application` | Application DLP |
