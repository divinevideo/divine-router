# Divine Router

Fastly Compute@Edge router for wildcard subdomain routing on Divine Video.

## Overview

This edge router handles incoming requests to `*.divine.video`, `*.dvine.video`, and `*.dvines.org`, routing them based on the subdomain:

- **Apex domains** (divine.video, dvines.org) → passthrough to origin
- **System subdomains** (www, api, cdn, admin, etc.) → passthrough to origin
- **Username subdomains** (alice.divine.video) → profile lookup and redirect

## Features

- **Username routing**: Routes `username.divine.video` to user profiles
- **NIP-05 support**: Serves `/.well-known/nostr.json` for Nostr identity verification
- **KV-backed lookups**: Username data stored in Fastly KV Store
- **System subdomain passthrough**: Reserves common subdomains for services

## NIP-05 Verification

Requests to `username.divine.video/.well-known/nostr.json` return NIP-05 responses:

```json
{
  "names": {
    "username": "pubkey-hex"
  },
  "relays": {
    "pubkey-hex": ["wss://relay.example.com"]
  }
}
```

## Development

### Prerequisites

- Rust with `wasm32-wasip1` target
- [Fastly CLI](https://developer.fastly.com/reference/cli/)

### Local Development

```bash
fastly compute serve
```

### Deploy

```bash
fastly compute publish --non-interactive && fastly purge --all
```

## Configuration

Username data is stored in the `usernames` KV store with this structure:

```json
{
  "pubkey": "hex-encoded-pubkey",
  "relays": ["wss://relay1.example.com"],
  "status": "active"
}
```

## System Subdomains

Reserved subdomains that passthrough to origin:
- www, api, cdn, admin, support, relay
- analytics, blossom, funnel, stream, media, gateway

## License

MIT
