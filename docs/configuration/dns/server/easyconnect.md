---
icon: material/new-box
---

# EasyConnect

### Structure

```json
{
  "dns": {
    "servers": [
      {
        "type": "easyconnect",
        "tag": "",

        "endpoint": "ec-client",
        "accept_default_resolvers": false,
        "accept_search_domain": false
      }
    ]
  }
}
```

### Fields

#### endpoint

==Required==

The tag of the [EasyConnect Endpoint](/configuration/endpoint/easyconnect).

DNS queries are sent through the endpoint to resolvers published by the VPN server. Resource-list domains are used as search-domain suffixes. The most specific matching suffix takes precedence.

Pushed DNS settings are not installed into the operating system.

#### accept_default_resolvers

Use published resolvers for queries that do not match a resource-list domain suffix.

When disabled, unmatched queries return `NXDOMAIN`.

#### accept_search_domain

When enabled and published search domains are available, single-label queries (for example, `intranet`) are retried with each search domain until one resolves.

If every search-domain expansion returns `NXDOMAIN`, the original unqualified name follows normal default-resolver behavior.

### Example

```json
{
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      },
      {
        "type": "easyconnect",
        "tag": "ec",
        "endpoint": "ec-client"
      }
    ],
    "rules": [
      {
        "preferred_by": "ec",
        "action": "route",
        "server": "ec"
      }
    ],
    "final": "local"
  }
}
```
