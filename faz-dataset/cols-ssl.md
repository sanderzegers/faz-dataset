# `$log-ssl` — SSL/SSH Inspection Logs

All common columns apply (see cols-common.md).

| Column | Type | Description |
|---|---|---|
| **`hostname`** | LowCardinality(String) | Server hostname (CN/SAN from certificate) |
| **`url`** | LowCardinality(String) | Requested URL |
| **`sslaction`** | LowCardinality(String) | SSL inspection action: `allow`, `block`, `sslexempt` |
| **`sslversion`** | LowCardinality(String) | TLS version: `TLSv1.0`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3` |
| **`sslcipher`** | LowCardinality(String) | Cipher suite name |
| **`sslserver`** | Nullable(String) | SSL server information |
| **`sslprotocol`** | Nullable(String) | SSL protocol |
| **`sslrootcacert`** | Nullable(String) | Root CA certificate name |
| **`sslexpiredcert`** | Nullable(String) | Whether certificate is expired: `Yes`, `No` |
| **`sslcipherid`** | Nullable(UInt16) | Numeric cipher suite identifier |
| **`catdesc`** | LowCardinality(String) | Application category description |
| **`action`** | LowCardinality(String) | Firewall action: `allow`, `block` |
| **`level`** | LowCardinality(String) | Severity level: `notice`, `information` |

## Key Patterns

```sql
-- Deprecated TLS versions (pre-TLS 1.2)
SELECT * FROM $log-ssl
WHERE $filter AND sslversion IN ('TLSv1.0', 'TLSv1.1')

-- Expired certificates
SELECT * FROM $log-ssl
WHERE $filter AND sslexpiredcert = 'Yes'

-- SSL inspection exemptions
SELECT * FROM $log-ssl
WHERE $filter AND sslaction = 'sslexempt'

-- Cipher strength analysis
SELECT sslcipher, count(*) AS cnt
FROM $log-ssl
WHERE $filter
GROUP BY sslcipher
ORDER BY cnt DESC
```

## Real Values Discovered from FAZ Instance

### `sslaction` (SSL Inspection Action)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `allow` | SSL traffic allowed through inspection |
| `block` | SSL traffic blocked by policy |
| `sslexempt` | SSL traffic exempted from inspection |

### `sslversion` (SSL/TLS Version)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `TLSv1.0` | Deprecated, insecure |
| `TLSv1.1` | Deprecated, insecure |
| `TLSv1.2` | Current standard |
| `TLSv1.3` | Latest TLS version |

### `sslcipher` (Cipher Suite)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `DHE-RSA-AES256-GCM-SHA384` | Strong cipher |
| `ECDHE-RSA-AES128-GCM-SHA256` | Strong cipher |
| `ECDHE-RSA-AES256-GCM-SHA384` | Strong cipher |
| `DHE-RSA-AES128-GCM-SHA256` | Strong cipher |
| `AES128-SHA` | Weaker cipher |
| `AES256-SHA` | Weaker cipher |
| `RC4-SHA` | Insecure cipher |
| `DES-CBC3-SHA` | Insecure cipher (3DES) |
| `ECDHE-RSA-AES128-SHA` | Moderate cipher |
| `DHE-RSA-AES128-SHA` | Moderate cipher |
| `ECDHE-RSA-DES-CBC3-SHA` | Insecure cipher (3DES) |

### `sslrootcacert` (Root CA Certificate)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `Symantec Class 3` | Symantec root CA |
| `DigiCert Global` | DigiCert root CA |
| `Let's Encrypt Authority X3` | Let's Encrypt root CA |
| `GlobalSign Root CA` | GlobalSign root CA |
| `Sectigo RSA` | Sectigo/Comodo root CA |

### `sslexpiredcert` (Expired Certificate Flag)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `Yes` | Certificate has expired |
| `No` | Certificate is valid |

### `action` (Firewall Action)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `allow` | Connection allowed |
| `block` | Connection blocked |

### `level` (Severity)

Observed from FAZ SSL logs:

| Value | Notes |
|---|---|
| `notice` | Routine |
| `information` | Informational |

### `catdesc` (Category Description)

Observed application categories from FAZ SSL logs:

| Value | Notes |
|---|---|
| `sslexempt` | SSL exemption category |
| `Social Networking` | Social media sites |
| `Streaming Media` | Video/audio streaming services |
| `Business` | Business applications |
| `Communication` | Communication tools |

### `hostname` (Server Hostname)

Observed hostname patterns from FAZ SSL logs:

| Pattern | Examples |
|---|---|
| Cloud services | `api.cloud-storage.example.com`, `client.cloud-storage.example.com`, `d.cloud-storage.example.com`, `bolt.cloud-storage.example.com`, `t8.cloud-storage.example.com` |
| Media streaming | `www.media-stream.example.com`, `accounts.media-stream.example.com`, `spclient.wg.media-stream.example.com`, `gew4-spclient.media-stream.example.com` |
| Communication | `edge.voice-call.example.com`, `eu-api.asm.voice-call.example.com`, `grpc.chat.secure-messaging.example.com` |
| Proxy/CDN | `mask.proxy.example.com`, `gateway.proxy.example.com`, `p139-contacts.proxy.example.com` |
| Software/updates | `play.store.example.com`, `cmux.example.com`, `apt.archive.example.com` |
| Randomized/CDN | `1807754d-9d3a-559c-be7f-21ed41449439.prd.edge-inf.example.com`, `1a1inqjh.p.qrcdn.example.com` |

### `url` (Requested URL)

Observed URL patterns from FAZ SSL logs:

| Pattern | Examples |
|---|---|
| API endpoints | `https://api.cloud-storage.example.com/v1/...`, `https://api.ai-assistant.example.com/...` |
| Media streams | `https://www.media-stream.example.com/watch`, `https://gew4-spclient.media-stream.example.com/...` |
| Communication | `https://grpc.chat.secure-messaging.example.com/...`, `https://edge.voice-call.example.com/...` |
| Software updates | `https://play.store.example.com/...`, `https://apt.archive.example.com/...` |
| Proxy services | `https://mask.proxy.example.com/...`, `https://gateway.proxy.example.com/...` |
