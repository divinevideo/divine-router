# Divine Router

A Fastly Compute edge router that fronts every `*.divine.video` and `*.dvines.org`
request. It inspects the host and path at the edge, decides whether the request is
for the main site, a platform service, or a user's subdomain, and either serves a
small response itself (WebFinger, NIP-05, ATProto DID) or forwards to the right
backend.

This is the public edge tier, separate from the GitOps-managed GKE stack. It is
published on its own as a Fastly Compute service, independent of
`divine-iac-coreconfig`.

## What it does

- **Subdomain routing** — classifies each host as an apex domain, a reserved system
  subdomain, a username subdomain, or a deeper multi-level host, and routes
  accordingly.
- **Per-service backends** — sends media, invite, and API traffic to dedicated
  backends while everything else falls through to the main site.
- **WebFinger** — serves `/.well-known/webfinger` for `acct:user@divine.video`
  directly from the username KV store (RFC 7033 JRD), with proper 404s for unknown
  or inactive users.
- **NIP-05** — serves `/.well-known/nostr.json` on username subdomains for Nostr
  identity verification, reading pubkeys and relays from KV.
- **ATProto handle resolution** — serves `/.well-known/atproto-did` on username
  subdomains for users whose ATProto state is ready.
- **ActivityPub passthrough** — forwards `/ap`, `/ap/*`, and nodeinfo paths on the
  apex to the ActivityPub gateway.
- **Edge caching** — bypasses cache for `/.well-known/*`, ActivityPub, and WebSocket
  traffic, and applies a short cacheable TTL to public API GET requests.

## Routing

Host classification happens in `classify_host`. Requests are handled in this order:

### Apex domains (`divine.video`, `dvines.org`)

- `GET /.well-known/webfinger` — answered at the edge from the username KV.
- `/ap`, `/ap/*`, `/.well-known/nodeinfo`, `/nodeinfo`, `/nodeinfo/*` — forwarded to
  the ActivityPub gateway backend.
- Everything else — passthrough to the main site backend.

### System subdomains (`sub.divine.video`, `sub.dvines.org`)

Reserved single-level subdomains are routed by name:

| Subdomain | Backend |
| --- | --- |
| `media`, `blossom` | Blossom / media server |
| `invite` | Invite faucet service |
| `api` | Funnelcake API (`relay.divine.video`) |
| `www`, `cdn`, `admin`, `support`, `relay`, `analytics`, `funnel`, `stream`, `gateway`, `names`, `login`, `pds`, `feed`, `labeler` | Main site |

### Username subdomains (`alice.divine.video`, `alice.dvines.org`)

Any single-level subdomain that is not reserved is treated as a username:

- `/.well-known/atproto-did` — returns the user's DID if their ATProto state is
  `ready`, otherwise 404.
- `/.well-known/nostr.json` — returns the user's NIP-05 record.
- Any other path — looks the username up in KV. Active users are forwarded to the
  main site backend with an `X-Original-Host` header so the web app can render the
  subdomain profile; unknown or inactive users get a 404 page.

### Multi-level and unknown hosts

Deeper hosts (`a.b.divine.video`) and hosts outside the owned domains fall through to
the main site backend.

## NIP-05 verification

Requests to `username.divine.video/.well-known/nostr.json` return a standard NIP-05
document. The subdomain name is looked up in KV, and the response echoes the queried
`?name=` parameter (defaulting to the subdomain), which supports the
`_@username.divine.video` form:

```json
{
  "names": {
    "_": "hex-encoded-pubkey"
  },
  "relays": {
    "hex-encoded-pubkey": ["wss://relay.example.com"]
  }
}
```

## Architecture

The service is a single Rust binary (`src/main.rs`) compiled to WebAssembly and run
on Fastly Compute. It reads the request `Host` and path, classifies the host, and
then either builds a response in-process (WebFinger, NIP-05, ATProto DID, 404s) or
rewrites headers and forwards to a backend.

On passthrough it sets `Host` to the backend's expected hostname and adds
`X-Forwarded-Host` and `X-Forwarded-Proto`. Caching is decided per request:

- `/.well-known/*` and ActivityPub paths on public Divine hosts, plus WebSocket
  upgrades, are passed uncached.
- Public API GET requests on `api.divine.video` (excluding `/api/docs`,
  authenticated, and WebSocket requests) are cacheable with a 30-second fallback TTL.
- Other passthrough responses are cacheable; the Fastly 0.13 `stale-if-error`
  default is disabled so origin 5xx responses keep surfacing.

Username, NIP-05, WebFinger, and ATProto lookups all read the same Fastly KV store.
Backends are defined in `fastly.toml`.

## Getting started

### Prerequisites

- Rust `1.88.0` with the `wasm32-wasip1` target (pinned in `rust-toolchain.toml`).
- The [Fastly CLI](https://developer.fastly.com/reference/cli/).

### Build and test

```bash
cargo build --profile release --target wasm32-wasip1
cargo test
```

### Run locally

```bash
fastly compute serve
```

The local server uses the KV fixture bound in `fastly.toml` (`kv_usernames.json`) and
the local backend definitions.

## Configuration

Backends are declared in `fastly.toml` for both the local server and Fastly setup:

| Backend | Purpose |
| --- | --- |
| `main_site` | Main Divine web app |
| `username_handler` | Username / profile origin |
| `blossom` | Blossom media server |
| `invite_service` | Invite faucet |
| `funnelcake_api` | API origin (`relay.divine.video`) |
| `activitypub_gateway` | ActivityPub gateway worker |

Username records are read from KV under the key `user:<username>` with this shape:

```json
{
  "pubkey": "hex-encoded-pubkey",
  "relays": ["wss://relay.example.com"],
  "status": "active",
  "atproto_did": "did:plc:...",
  "atproto_state": "ready"
}
```

Only records with `status` `active` are served. ATProto DID resolution additionally
requires `atproto_state` to be `ready` and `atproto_did` to be present.

## Deployment

Deploy with the Fastly CLI:

```bash
fastly compute publish --non-interactive && fastly purge --all
```

Because username, WebFinger, and ATProto responses come from KV, publish this service
after the handle and ATProto state have been written by `divine-name-server`.

## License

MIT

---

Part of [Divine](https://divine.video) — your playground for human creativity · [Brand guidelines](https://github.com/divinevideo/brand-guidelines)
