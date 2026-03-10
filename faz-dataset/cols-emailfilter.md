# `$log-emailfilter` — Email Filter

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`from`** | LowCardinality(String) | Sender email address |
| **`to`** | LowCardinality(String) | Recipient email address |
| `sender` / `recipient` | LowCardinality(String) | Alternate sender/recipient fields |
| **`subject`** | LowCardinality(String) | Email subject |
| `cc` | Nullable(String) | CC list |
| **`action`** | LowCardinality(String) | `pass`, `block`, `clear` |
| **`eventtype`** | LowCardinality(String) | `spam`, `bannedword`, `mheader`, `mime`, `other` |
| `banword` | LowCardinality(String) | Matched banned word |
| `attachment` | LowCardinality(String) | Has attachment? `yes`/`no` |
| `size` | Nullable(String) | Message size |
| `filetype` | LowCardinality(String) | Attachment file type |
| `filename` | Nullable(String) | Attachment filename |
| `filtername` | Nullable(String) | Email filter profile name |
| `matchfilename` / `matchfiletype` | Nullable/LowCardinality | Matched filename/type pattern |
| `fortiguardresp` | Nullable(String) | FortiGuard spam response |
| `webmailprovider` | Nullable(String) | Webmail provider: `gmail`, `outlook`, etc. |
| `direction` | LowCardinality(String) | `incoming`, `outgoing` |
| `sentbyte` / `rcvdbyte` | — | Bytes |

> **Email send service filter** (`${EMAIL_SEND_SERVICE}` macro):
> `service IN ('smtp','SMTP','25/tcp','587/tcp','smtps','SMTPS','465/tcp')`
