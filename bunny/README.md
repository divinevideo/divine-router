# Divine Router — Bunny Edge Scripting Port (Evaluation)

Deno/TypeScript port of `divine-router` (`src/main.rs`) for evaluating **Bunny Edge Scripting** as a lower-cost replacement for Fastly Compute.

> **Production isolation:** This directory is additive and does not modify the live Fastly Compute build (`src/main.rs`, `fastly.toml`, `scripts/deploy.py`).

## Entrypoints

| File | Mode | When to use |
| --- | --- | --- |
| `src/main.ts` | **Standalone Edge Script** (`BunnySDK.net.http.serve`) | Full multi-backend router (`api.divine.video`, `divine.video`, `*.divine.video`, `*.dvines.org`) with WebFinger, NIP-05, ATProto DID, and profile routing. |
| `src/middleware.ts` | **Pull Zone Middleware** (`BunnySDK.net.http.servePullZone`) | Lowest-cost option for `api.divine.video`: cache HITs are served directly by Bunny's 119-PoP CDN with **$0 script compute**; the script only runs on cache MISSes (`onOriginRequest` / `onOriginResponse`). |
| `src/dev_server.ts` | Local Deno HTTP server | Local verification using `../kv_usernames.json`. |

## Local Verification

```bash
cd bunny
deno task check
deno task test
```

Run locally against live upstreams with the local username fixture:

```bash
# Test exact api.divine.video routing locally:
PUBLIC_HOST_OVERRIDE=api.divine.video deno task dev

# Or test full host routing by passing explicit Host headers:
deno task dev
curl -H 'Host: rabble.divine.video' http://127.0.0.1:8787/.well-known/nostr.json?name=_
curl -H 'Host: api.divine.video' http://127.0.0.1:8787/api/videos
```

## Phase 1 Staging Setup (`api.divine.video` on Bunny)

`api.divine.video` is the cleanest first cutover target because it has **zero Fastly backend or KV dependencies** (it only routes to GKE `relay.divine.video`, `relay2.divine.video`, `api-relay-prod.divine.video`, and Cloudflare `sounds.divine.video`).

1. **Create a Bunny Edge Script** (test both **Standalone** `src/main.ts` and **Pull Zone Middleware** `src/middleware.ts` with default origin `https://relay.divine.video`).
2. **Set staging environment variable** (staging only — remove before production cutover if sharing the Pull Zone across multiple hosts):
   - `PUBLIC_HOST_OVERRIDE=api.divine.video` so requests arriving on `*.bunny.run` or `*.b-cdn.net` execute the exact `api.divine.video` routing rules (`mobile_api`, `sound_proxy`, `funnelcake_api`).
3. **Configure the fronting Bunny Pull Zone** to match Fastly's cache contract:
   - **Network Tier:** Standard (global PoPs covering North America, Europe, Asia-Pacific, and Oceania).
   - **Serve Stale:** Enable `UseStaleWhileUpdating` (`stale-while-revalidate`) and `UseStaleWhileOffline` (`stale-if-error`).
   - **Request Coalescing:** Enable to collapse concurrent cache misses against ClickHouse.
   - **Cache-Control / Smart Cache:** Honor origin `Cache-Control` / `CDN-Cache-Control` for `application/json` (do not restrict caching to static extensions).
   - **Edge Rules (pre-cache bypasses, essential for Middleware mode):** `bunny/deploy_bunny.py` creates and reconciles these (rules prefixed `divine-router:`); the script is the source of truth.
     - Bypass cache when the `Authorization` request header is present, and mark those responses `Cache-Control: private, no-store`.
     - Bypass cache for candidate hosts (`api2.divine.video`, `relay2.divine.video`).
     - Bypass cache for `/.well-known/*`, `/ap`, `/ap/*`, `/nodeinfo`, `/nodeinfo/*`, `/api/docs*`.
     - Bypass cache for the exact mobile API routes (`/v1/account/moderation-status`, `/v1/minor-review-cases/greenlight`, `/v1/minor-review-cases/*/parent-contact`, `/v1/minor-review-cases/*/parent-consent`, `/api/zendesk/pre-auth`).
     - Bypass cache for the sound proxy routes (`/api/sounds/providers`, `/api/sounds/trending`, `/api/sounds/*/videos`).
     - Bypass cache for short links (`/l`, `/l/*`, `/api/links`, `/api/links/*` on `divine.video` and `www.divine.video`).
     - Bypass cache for non-`GET` methods (`POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`) and `HEAD`.
4. **Before production without `PUBLIC_HOST_OVERRIDE`:** confirm on the real Bunny runtime that `onOriginRequest` sees the client's `Host` header and that `onOriginResponse` receives the rewritten origin request (the one carrying the router-set `X-Original-Host`). The SDK's local emulation behaves this way, but the hosted runtime has not been checked.
5. **Optional Phase 2 (`divine.video` + `*.divine.video`):**
   - Provision a replicated **Bunny Database** (`usernames` table) and set `BUNNY_DB_URL` + `BUNNY_DB_TOKEN`.
   - Sync writes from `divine-name-server` into Bunny Database alongside Fastly KV during migration.
   - For wildcard `*.divine.video` TLS while DNS remains on Cloudflare, automate ACME DNS-01 cert upload via the Bunny Pull Zone API (or move DNS to Bunny DNS for native wildcard Let's Encrypt).

### Deploying

Bundle, then deploy with `bunny/deploy_bunny.py` (reads `BUNNY_API_KEY` or `~/.config/divine-cdn/bunny-api-key`; never prints it):

```bash
cd bunny && deno task bundle && deno task bundle:middleware && cd ..
python3 bunny/deploy_bunny.py --name divine-router-api-middleware --mode middleware \
  --bundle bunny/dist/middleware.js --origin https://relay.divine.video \
  --env PUBLIC_HOST_OVERRIDE=api.divine.video
```

The script upserts the Edge Script, its variables and code, publishes it, then applies the Pull Zone settings and Edge Rules above.

## A/B Benchmarking Against Fastly

From any host or regional GCE VM (`us-central1`, `asia-northeast1` Tokyo, `europe-west2` London, `australia-southeast1` Sydney):

```bash
python3 scripts/probe_router_edge.py \
  --edge fastly=https://api.divine.video \
  --edge bunny=https://api-bunny-test.divine.video \
  --path /api/videos \
  --path "/api/videos?limit=20" \
  --baseline fastly \
  --region us-central1 \
  --iterations 20 \
  --json /tmp/router-probe-us-central1.json
```

The probe measures and verifies:
- Separate DNS+TCP+TLS connect time vs. established-connection p50/p95/p99 TTFB.
- `Accept-Encoding` cache fragmentation across `br`, Chrome (`gzip, deflate, br, zstd`), Dart (`gzip`), and `gzip, deflate`.
- `Authorization` header cache bypass (`BYPASS` / `MISS`, never `HIT`; a missing cache-status header fails).
- The probe exits non-zero when a non-baseline edge fails the latency verdict, the `Authorization` check, or the `Accept-Encoding` dedup check (every variant must be a cache `HIT`).
- Cold cache miss latency and JSON payload shape parity against Fastly.
