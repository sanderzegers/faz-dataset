# `$log-file-filter` — File Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`filetype`** | LowCardinality(String) | File type / extension detected: `PDF`, `ZIP`, `EXE`, `DOCX`, `XLSX`, `PPTX`, `JPG`, `PNG`, `RAR`, `7Z`, `ISO`, `VHD`, `BAT`, `CMD`, `JS`, `VBS`, `HTA`, `REG`, `MSI`, `CAB`, `DLL`, `SYS` |
| **`filename`** | Nullable(String) | Original filename — use `nullifna()` |
| **`fileaction`** | LowCardinality(String) | File filter action: `allow`, `block`, `quarantine` |
| **`filehash`** | Nullable(String) | Generic file hash — use `nullifna()` |
| **`filehashsha256`** | Nullable(String) | SHA-256 hash (64-char hex) — use `nullifna()` |
| `filehashsha1` | Nullable(String) | SHA-1 hash (40-char hex) |
| `filehashmd5` | Nullable(String) | MD5 hash (32-char hex) |
| `filecategory` | Nullable(String) | File category description |
| **`action`** | LowCardinality(String) | Overall action: `allow`, `block`, `quarantine` |
| `level` | LowCardinality(String) | Log level: `notice`, `information`, `warning` |
| `filesize` | Nullable(UInt64) | File size in bytes |
| `sentbyte` | Nullable(UInt64) | Bytes sent (upload) |
| `rcvdbyte` | Nullable(Int64) | Bytes received (download) |

## Key Pattern

```sql
-- Blocked/quarantined file transfers
SELECT filetype, fileaction, count(*) AS cnt
FROM $log-file-filter
WHERE $filter AND fileaction IN ('block', 'quarantine')
GROUP BY filetype, fileaction
/*SkipSTART*/ORDER BY cnt DESC/*SkipEND*/

-- Large uploads by filetype
SELECT filetype, nullifna(filename) AS fname, filesize, sentbyte
FROM $log-file-filter
WHERE $filter AND nullifna(filename) IS NOT NULL AND filesize > 1000000
/*SkipSTART*/ORDER BY filesize DESC/*SkipEND*/
```

## Real Values Discovered from FAZ Instance

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

### `filehashsha256` (SHA-256 Hash)

Observed file hashes from FAZ file-filter logs:

| Pattern | Notes |
|---|---|
| 64-char hex | SHA-256 hash of file content, e.g. `{FLOAT}` |

### `filehashsha1` (SHA-1 Hash)

| Pattern | Notes |
|---|---|
| 40-char hex | SHA-1 hash of file content |

### `filehashmd5` (MD5 Hash)

| Pattern | Notes |
|---|---|
| 32-char hex | MD5 hash of file content |

### `filename` (Original Filename)

Observed filenames from FAZ file-filter logs:

| Pattern | Notes |
|---|---|
| Office documents | `report.pdf`, `document.docx`, `spreadsheet.xlsx` |
| Archives | `backup.zip`, `data.rar`, `install.7z` |
| Executables | `setup.exe`, `installer.msi` |
| Scripts | `run.bat`, `deploy.cmd`, `script.js` |

### `filecategory` (File Category)

| Pattern | Notes |
|---|---|
| Various categories | File categorization used by FortiGuard file filter — category names vary |
