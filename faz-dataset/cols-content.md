# `$log-content` — Content Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`subtype`** | LowCardinality(String) | Protocol subtype: `smtp`, `http`, `ftp`, `imap`, `pop3` |
| **`level`** | LowCardinality(String) | Log level: `notice`, `information`, `warning` |
| **`action`** | LowCardinality(String) | Content filter action: `allow`, `block`, `quarantine`, `exempt` |
| `content` | LowCardinality(String) | Content type: `HTML`, `plain text`, `multipart`, `binary` |
| `ftpcmd` | Nullable(String) | FTP command: `RETR`, `STOR`, `LIST`, `NLST`, `CWD`, `PWD`, `TYPE`, `PASV`, `PORT`, `MKD`, `RMD`, `RNFR`, `RNTO` |
| **`status`** | LowCardinality(String) | Transfer status: `success`, `fail` |
| `direction` | LowCardinality(String) | `incoming`, `outgoing` |
| `infection` | Nullable(String) | Detected virus/malware name |
| `kind` | LowCardinality(String) | Content category: `mail`, `web`, `file` |

## Key Patterns

```sql
-- Content actions by subtype
SELECT subtype,
       sum(CASE WHEN action = 'block' THEN 1 ELSE 0 END) AS blocked,
       sum(CASE WHEN action = 'quarantine' THEN 1 ELSE 0 END) AS quarantined,
       count(*) AS total
FROM $log-content
WHERE $filter AND nullifna(subtype) IS NOT NULL
GROUP BY subtype
/*SkipSTART*/ORDER BY total DESC/*SkipEND*/

-- FTP command distribution (STOR = upload, RETR = download)
SELECT ftpcmd, count(*) AS cnt
FROM $log-content
WHERE $filter AND nullifna(ftpcmd) IS NOT NULL
GROUP BY ftpcmd
/*SkipSTART*/ORDER BY cnt DESC/*SkipEND*/

-- Infection detection by kind
SELECT kind, infection, count(*) AS cnt
FROM $log-content
WHERE $filter AND nullifna(infection) IS NOT NULL
GROUP BY kind, infection
/*SkipSTART*/ORDER BY cnt DESC/*SkipEND*/
```

## Real Values Discovered from FAZ Instance

### `subtype` (Protocol Subtype)

Observed from FAZ content logs:

| Value | Notes |
|---|---|
| `smtp` | SMTP email traffic |
| `http` | HTTP web traffic |
| `ftp` | FTP file transfers |
| `imap` | IMAP email access |
| `pop3` | POP3 email access |

### `level` (Log Level)

| Value | Notes |
|---|---|
| `notice` | Informational notice |
| `information` | Informational |
| `warning` | Warning-level event |

### `action` (Content Filter Action)

Observed from FAZ content logs:

| Value | Notes |
|---|---|
| `allow` | Allowed through |
| `block` | Blocked by filter |
| `quarantine` | Quarantined for review |
| `exempt` | Exempted from filtering |

### `content` (Content Type)

| Value | Notes |
|---|---|
| `HTML` | HyperText Markup Language |
| `plain text` | Plain text content |
| `multipart` | Multipart/mixed content |
| `binary` | Binary file content |

### `ftpcmd` (FTP Command)

Observed from FAZ FTP content logs:

| Value | Notes |
|---|---|
| `RETR` | Retrieve/download file |
| `STOR` | Store/upload file |
| `LIST` | List directory contents |
| `NLST` | List directory names only |
| `CWD` | Change working directory |
| `PWD` | Print working directory |
| `TYPE` | Set transfer type |
| `PASV` | Passive mode |
| `PORT` | Active mode |
| `MKD` | Make directory |
| `RMD` | Remove directory |
| `RNFR` | Rename from |
| `RNTO` | Rename to |

### `status` (Transfer Status)

| Value | Notes |
|---|---|
| `success` | Transfer completed |
| `fail` | Transfer failed |

### `direction` (Traffic Direction)

| Value | Notes |
|---|---|
| `incoming` | Inbound traffic |
| `outgoing` | Outbound traffic |

### `infection` (Detected Virus/Malware)

Detected infections from FAZ content logs:

| Pattern | Notes |
|---|---|
| `Win.Trojan.{NAME}-{HASH}` | Windows trojan variants |
| `Win.Malware.{NAME}` | Windows malware variants |
| `HTML/Phish.{NAME}` | Phishing HTML detection |
| `Java.Banned.{NAME}` | Banned Java applets |
| `Generic.{NAME}` | Generic malware detection |

### `kind` (Content Category)

| Value | Notes |
|---|---|
| `mail` | Email content (SMTP/IMAP/POP3) |
| `web` | Web content (HTTP) |
| `file` | File transfer content (FTP) |
