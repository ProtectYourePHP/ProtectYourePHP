# License endpoint protocol (v1)

Every encoded file that uses the *server layer* asks one URL (the `--server` you gave the
encoder) for permission and for part of its decryption key. You can host this endpoint
yourself in any language; `server/index.php` is the reference implementation.

## Request

`POST <url>` with `Content-Type: application/json`

```json
{
  "v": 1,
  "project": "prj_1a2b3c4d5e6f",
  "license": "PYP-ABCDE-FGHJK-MNPQR-STVWX-YZ012",
  "nonce": "base64, 16 random bytes",
  "epk": "base64 X25519 public key (libsodium crypto_box), ephemeral per request",
  "host": {
    "domain": "shop.example.com",
    "hostname": "web01",
    "ips": ["203.0.113.5"],
    "macs": ["aa:bb:cc:dd:ee:ff"]
  },
  "php": "8.4.1",
  "loader": "1.0.0"
}
```

## Response

HTTP 200, `application/json`:

```json
{
  "v": 1,
  "status": "ok",
  "nonce": "<echo of the request nonce>",
  "issued_at": "2026-11-12T10:00:00+00:00",
  "ttl": 3600,
  "message": null,
  "license": {
    "id": "lic_ab12cd34",
    "expires_at": "2027-01-01T00:00:00+00:00",
    "domains": ["*.example.com"],
    "ips": ["10.0.0.0/8"],
    "macs": []
  },
  "key": "base64( crypto_box_seal(keyShare, epk) )",
  "signature": "base64( Ed25519 detached signature over canonical(response without 'signature') )"
}
```

| field | meaning |
|---|---|
| `status` | `ok`, `expired`, `not_authorized`, `revoked`, `invalid` |
| `message` | optional text shown to the end user instead of the encoder's default message |
| `ttl` | seconds the loader may cache the key share (max 7 days) |
| `license.*` | restrictions. The loader re-checks them locally (empty list = unrestricted); `domains` supports `*.example.com`, `ips` supports CIDR |
| `key` | 32 byte key share, sealed to the request's `epk`. Must be `null` unless `status` is `ok` |
| `signature` | verified with the project's public key that is embedded in the encoded files |

`keyShare = HMAC-SHA256(key = projectSecret, data = "pyp-share-v1")`. The encoder knows the
project secret and mixes the share into each file key
(`HKDF-SHA256(len‖embedded ‖ len‖external ‖ len‖share, salt, "pyp1|<fileId>")`), so a file can only be
decrypted while the license server says yes (or while a cached share is still within its TTL + grace).

### Canonical JSON (for signing)

Recursively sort object keys (byte order), keep list order, encode with
`JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` (no whitespace). Empty objects and
empty arrays are both `[]`. Signed values must be strings, ints, bools, null, lists or objects.

### Caching on the client

The loader stores the complete signed response (plus the ephemeral secret key needed to
open `key`). On every use it re-verifies the signature, so `ttl`, `issued_at` and the
restrictions cannot be changed in the cache. The lifetime starts at
`min(issued_at, local fetch time)`. Non-`ok` answers are cached for 60 s, network
failures for 30 s; a still valid cached grant (within `ttl` + `grace`) is used while the
server is unreachable.

### HTTP status

The reference server answers `405` for non-POST requests, `400` for invalid JSON, `429`
when the per-IP rate limit is exceeded and `500` on internal errors. The loader treats any
non-JSON answer or 5xx status as `unreachable`.

### Security notes

* The nonce is echoed and signed, so responses cannot be replayed for other requests.
* License keys are `PYP-` + 5 groups of 5 Crockford base32 characters (125 random bits).
  The loader accepts keys matching `^[A-Z0-9][A-Z0-9-]{7,79}$` (after upper-casing and
  removing whitespace), so custom key formats work as long as they fit that pattern.
* `host` data is reported by the client. It stops honest-but-careless copying, not an attacker
  who patches the loader. Real protection comes from the server-issued key (the key is not
  on disk) and, optionally, the external key.
* Use HTTPS. Unsigned or wrongly signed answers are rejected as `invalid`.
