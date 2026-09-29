# `$log-file-filter` — File Filter

All common columns apply (see cols-common.md).

> **Version differences.** The first table is tested live on **FAZ 7.6** (header dump). The second table comes from sample data collected on **FAZ 8.0**, and its columns fail with "Missing columns" on 7.6. On 7.6, use `action` for the action and `$log-virus` (`filehash`) for file hashes.

## FAZ 7.6 columns (tested)

| Column | Type | Description |
|---|---|---|
| **`filetype`** | LowCardinality(String) | File type detected |
| **`filename`** | Nullable(String) | Original filename — use `nullifna()` |
| `matchfiletype` / `matchfilename` | — | File type / filename pattern the rule matched |
| **`rulename`** | — | File filter rule that matched |
| `filtertype` | — | Filter type |
| **`action`** | LowCardinality(String) | File filter action |
| `direction` | — | `incoming` / `outgoing` |
| `level` | LowCardinality(String) | Log level: `notice`, `information`, `warning` |
| `filesize` | Nullable(UInt64) | File size in bytes |
| `hostname` / `url` | — | Web transfer host / URL |
| `from` / `to` / `sender` / `recipient` / `subject` / `attachment` | — | Email transfer fields |
| `sharename` / `pathname` | — | SMB share / path |

## FAZ 8.0 columns (from sample data, not present on 7.6)

| Column | Type | Description |
|---|---|---|
| **`fileaction`** | LowCardinality(String) | File filter action: `allow`, `block`, `quarantine` |
| **`filehash`** | Nullable(String) | Generic file hash — use `nullifna()` |
| **`filehashsha256`** | Nullable(String) | SHA-256 hash (64-char hex) — use `nullifna()` |
| `filehashsha1` | Nullable(String) | SHA-1 hash (40-char hex) |
| `filehashmd5` | Nullable(String) | MD5 hash (32-char hex) |
| `filecategory` | Nullable(String) | File category description |
| `sentbyte` | Nullable(UInt64) | Bytes sent (upload) |
| `rcvdbyte` | Nullable(Int64) | Bytes received (download) |

## Key Pattern

FAZ 7.6: column names tested, `action` values unverified. Check with `GROUP BY action` first. On 8.0, `fileaction` may replace `action`, but that's untested.

```sql
-- Blocked file transfers by rule and type
SELECT rulename, filetype, count(*) AS cnt
FROM $log-file-filter
WHERE $filter AND action = 'block'
GROUP BY rulename, filetype
ORDER BY cnt DESC

-- Large transfers by filetype
SELECT filetype, nullifna(filename) AS fname, direction, filesize
FROM $log-file-filter
WHERE $filter AND nullifna(filename) IS NOT NULL AND filesize > 1000000
ORDER BY filesize DESC
```

## Real Values Discovered from FAZ Instance (FAZ 8.0)

### `fileaction` (File Filter Action)

Observed from FAZ file-filter logs:

| Value | Notes |
|---|---|
| `allow` | File allowed through |
| `block` | File blocked by policy |
| `quarantine` | File quarantined |

### `action` (File Filter Action)

Observed from FAZ file-filter logs:

| Value | Notes |
|---|---|
| `allow` | Allowed |
| `block` | Blocked |
| `quarantine` | Quarantined |

### `level` (File Filter Level)

| Value | Notes |
|---|---|
| `notice` | Notice |
| `warning` | Warning |
| `information` | Informational |

### `filetype` (Detected File Type)

Observed file types from FAZ file-filter logs:

| Value | Notes |
|---|---|
| `PDF` | Portable Document Format |
| `ZIP` | ZIP archive |
| `EXE` | Windows executable |
| `DOCX` | Microsoft Word document |
| `XLSX` | Microsoft Excel spreadsheet |
| `PPTX` | Microsoft PowerPoint presentation |
| `JPG` | JPEG image |
| `PNG` | PNG image |
| `RAR` | RAR archive |
| `7Z` | 7-Zip archive |
| `ISO` | ISO disk image |
| `VHD` | Virtual hard disk |
| `BAT` | Batch script |
| `CMD` | Command script |
| `JS` | JavaScript |
| `VBS` | VBScript |
| `HTA` | HTML Application |
| `REG` | Windows registry |
| `MSI` | Windows installer |
| `CAB` | Cabinet archive |
| `DLL` | Dynamic link library |
| `SYS` | System file |

### `filehashsha256` / `filehashsha1` / `filehashmd5`

| Pattern | Notes |
|---|---|
| 64 / 40 / 32-char hex | SHA-256 / SHA-1 / MD5 hash of file content |

### `filename` (Original Filename)

Observed filenames from FAZ file-filter logs:

| Pattern | Notes |
|---|---|
| Office documents | `report.pdf`, `document.docx`, `spreadsheet.xlsx` |
| Archives | `backup.zip`, `data.rar`, `install.7z` |
| Executables | `setup.exe`, `installer.msi` |
| Scripts | `run.bat`, `deploy.cmd`, `script.js` |
