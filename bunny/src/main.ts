// ABOUTME: Bunny Edge Scripting Standalone entrypoint for divine-router.
// ABOUTME: Deploy this file as a Bunny Standalone Edge Script behind a Pull Zone.

import * as BunnySDK from "@bunny.net/edgescript-sdk";
import { createRouterHandler } from "./handler.ts";
import { createUsernameStoreFromEnv } from "./username_store.ts";

const handler = createRouterHandler({
  publicHostOverride: Deno.env.get("PUBLIC_HOST_OVERRIDE") || undefined,
  usernameStore: createUsernameStoreFromEnv(),
});

BunnySDK.net.http.serve(handler);
