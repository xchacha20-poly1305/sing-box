---
icon: material/new-box
---

# DNS over HTTP(S)

The DoH service answers DNS queries through the internal DNS router. It supports
GET with an unpadded base64url `dns` query parameter and POST with a binary DNS
message and `Content-Type: application/dns-message`.

### Structure

```json
{
  "type": "doh",
  "tag": "doh-in",
  "listen": "127.0.0.1",
  "listen_port": 8443,
  "path": "/dns-query",
  "users": [
    {
      "username": "alice",
      "password": "alice-password"
    },
    {
      "username": "bob",
      "password": "bob-password"
    }
  ],
  "tls": {
    "enabled": true,
    "certificate_path": "cert.pem",
    "key_path": "key.pem"
  }
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### path

The exact URL path to serve. Defaults to `/dns-query`. Use a canonical absolute
path. The root path, trailing slashes, empty or dot segments, percent escapes,
queries, fragments, and router wildcards are invalid.

#### users

Users accepted by HTTP Basic authentication. Each entry requires a unique,
non-empty username and a non-empty password. A username cannot contain a colon.
An empty list allows anonymous queries.

DNS rules can match the service tag using `inbound` and the authenticated
username using `auth_user`.

#### tls

Enable HTTPS on the listener. See [TLS](/configuration/shared/tls/) for details.
When TLS is disabled, the listener uses plain HTTP, including for Basic
authentication headers.
