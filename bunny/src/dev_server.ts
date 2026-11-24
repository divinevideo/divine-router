// ABOUTME: Local Deno dev server for divine-router Bunny Edge Script evaluation.
// ABOUTME: Loads ../kv_usernames.json so WebFinger, NIP-05, ATProto, and API routes can be tested locally.

import { createRouterHandler } from "./handler.ts";
import { MemoryUsernameStore } from "./username_store.ts";

const port = Number.parseInt(Deno.env.get("PORT") ?? "8787", 10);
const publicHostOverride = Deno.env.get("PUBLIC_HOST_OVERRIDE") || undefined;

let fixtureEntries: Record<string, { data: string }> = {};
try {
  const fixturePath = new URL("../../kv_usernames.json", import.meta.url);
  fixtureEntries = JSON.parse(await Deno.readTextFile(fixturePath));
} catch {
  console.warn("Could not load ../kv_usernames.json; starting with empty username fixture.");
}

const handler = createRouterHandler({
  publicHostOverride,
  usernameStore: new MemoryUsernameStore(fixtureEntries),
});

console.log(
  `divine-router (Bunny Edge Script dev) listening on http://127.0.0.1:${port}` +
    (publicHostOverride ? ` (PUBLIC_HOST_OVERRIDE=${publicHostOverride})` : ""),
);

Deno.serve({ hostname: "127.0.0.1", port }, handler);
