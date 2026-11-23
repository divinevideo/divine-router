// ABOUTME: Bunny Edge Scripting Pull Zone Middleware entrypoint for divine-router.
// ABOUTME: Runs only on cache misses (onOriginRequest / onOriginResponse) so CDN cache hits pay $0 script compute.

import * as BunnySDK from "@bunny.net/edgescript-sdk";
import { createPullZoneMiddleware } from "./handler.ts";
import { createUsernameStoreFromEnv } from "./username_store.ts";

const middleware = createPullZoneMiddleware({
  publicHostOverride: Deno.env.get("PUBLIC_HOST_OVERRIDE") || undefined,
  usernameStore: createUsernameStoreFromEnv(),
  hopToken: Deno.env.get("ROUTER_HOP_TOKEN") || undefined,
});

const defaultOrigin = Deno.env.get("PULL_ZONE_ORIGIN_URL") || "https://relay.divine.video";

BunnySDK.net.http
  .servePullZone({ url: defaultOrigin })
  // @bunny.net/edgescript-sdk types the return as `Promise<Request> | Promise<Response>`
  // rather than `Promise<Request | Response>`; coerce at the SDK boundary.
  .onOriginRequest((ctx) =>
    middleware.onOriginRequest(ctx) as Promise<Request> | Promise<Response>
  )
  .onOriginResponse(middleware.onOriginResponse);
