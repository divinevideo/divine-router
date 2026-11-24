// ABOUTME: Comprehensive unit and integration test suite for the Bunny Edge Scripting router port.
// ABOUTME: Mirrors every routing, header, caching, Accept-Encoding, and identity test in src/main.rs.

import { assertEquals, assertMatch } from "@std/assert";
import {
  ACTIVITYPUB_BACKEND,
  ACTIVITYPUB_BACKEND_HOST,
  apiBackendFor,
  apiCachePolicy,
  applyPassthroughHeaders,
  backendHostFor,
  BLOSSOM_BACKEND,
  buildAtprotoDidResponse,
  buildNip05Response,
  buildUsernameNotFoundResponse,
  buildWebFingerJrd,
  webFingerNotFoundResponse,
  CANDIDATE_API_BACKEND,
  CANDIDATE_BACKEND_HOST,
  candidateCacheAction,
  CANONICAL_API_HOST,
  classifyHost,
  EDGE_STALE_IF_ERROR_SECS,
  FUNNELCAKE_API_BACKEND,
  FUNNELCAKE_BACKEND_HOST,
  honorsOriginStaleIfError,
  INVITE_BACKEND,
  isCandidateHost,
  isPublicDivineHost,
  isRetiredSystemSubdomain,
  isRssFeedPath,
  isShortLinkRoute,
  MAIN_BACKEND,
  MAIN_BACKEND_HOST,
  MOBILE_API_BACKEND,
  MOBILE_API_BACKEND_HOST,
  normalizedAcceptEncoding,
  parseStrictTvAgeSecs,
  parseStrictTvCdnTags,
  parseWebFingerResource,
  passthroughCacheMode,
  passthroughHeaders,
  RETIRED_SYSTEM_SUBDOMAINS,
  retiredSystemResponse,
  routeDecisionFor,
  SHORTENER_BACKEND,
  SHORTENER_BACKEND_HOST,
  shouldBypassCache,
  shouldNormalizeAcceptEncoding,
  SOUND_PROXY_BACKEND,
  SOUND_PROXY_BACKEND_HOST,
  staleIfErrorOverrideSecs,
  STRICT_TV_POLICY,
  STRICT_TV_POLICY_HEADER,
  strictTvCacheLeaseSecs,
  strictTvLeaseExpired,
  strictTvPassAgeAllowed,
  strictTvResponseAllowed,
  strictTvUsesCallerContext,
  SYSTEM_SUBDOMAINS,
  tvRequest,
  type UsernameData,
} from "./router.ts";
import { createPullZoneMiddleware, createRouterHandler } from "./handler.ts";
import {
  BunnyDatabaseUsernameStore,
  lookupUsernameWithFallback,
  MemoryUsernameStore,
} from "./username_store.ts";

function makeActiveUser(pubkey: string, relays: string[] = []): UsernameData {
  return { pubkey, relays, status: "active", atproto_did: null, atproto_state: null };
}

function makeInactiveUser(pubkey: string): UsernameData {
  return { pubkey, relays: [], status: "inactive", atproto_did: null, atproto_state: null };
}

function makeAtprotoUser(pubkey: string, did: string, state: string): UsernameData {
  return { pubkey, relays: [], status: "active", atproto_did: did, atproto_state: state };
}

Deno.test("short links match only public hosts and exact namespaces", () => {
  for (const host of ["divine.video", "www.divine.video", "DIVINE.VIDEO", "divine.video:443"]) {
    for (const path of ["/l", "/l/Abc12345", "/api/links", "/api/links/Abc12345"]) {
      assertEquals(isShortLinkRoute(host, path), true, `${host} ${path}`);
    }
    for (
      const path of [
        "/login",
        "/lists",
        "/l-other",
        "/api/linkstuff",
        "/video/test",
        "/.well-known/nostr.json",
        "/ap/actor",
      ]
    ) {
      assertEquals(isShortLinkRoute(host, path), false, `${host} ${path}`);
    }
  }
  for (
    const host of [
      "api.divine.video",
      "alice.divine.video",
      "dvines.org",
      "example.com",
      "divine.video.example.com",
    ]
  ) {
    assertEquals(isShortLinkRoute(host, "/l/Abc12345"), false, host);
  }
});

Deno.test("short link backend uses assigned origin and passes", () => {
  assertEquals(backendHostFor(SHORTENER_BACKEND), SHORTENER_BACKEND_HOST);
  for (const method of ["GET", "HEAD", "POST", "OPTIONS"]) {
    for (const path of ["/l/Abc12345", "/api/links", "/api/links/Abc12345"]) {
      assertEquals(
        passthroughCacheMode("divine.video", method, path, false, false, SHORTENER_BACKEND),
        { kind: "Pass" },
      );
    }
  }
  const headers = passthroughHeaders(SHORTENER_BACKEND, "www.divine.video", "https");
  assertEquals(headers.backendHost, SHORTENER_BACKEND_HOST);
  assertEquals(headers.forwardedHost, "www.divine.video");
  assertEquals(headers.forwardedProto, "https");
});

Deno.test("NIP-05 response builder covers subdomain, relays, inactive, not found, case", () => {
  const user = makeActiveUser("abc123pubkey");
  assertEquals(buildNip05Response("_", user), { names: { _: "abc123pubkey" } });
  assertEquals(buildNip05Response("DANIEL", user), { names: { daniel: "abc123pubkey" } });

  const relays = ["wss://relay.divine.video", "wss://relay.damus.io"];
  const userWithRelays = makeActiveUser("abc123pubkey", relays);
  assertEquals(buildNip05Response("_", userWithRelays), {
    names: { _: "abc123pubkey" },
    relays: { abc123pubkey: relays },
  });

  assertEquals(buildNip05Response("_", null), { names: {} });
  assertEquals(buildNip05Response("_", makeInactiveUser("abc123pubkey")), { names: {} });
});

Deno.test("WebFinger parsing and JRD generation", () => {
  assertEquals(parseWebFingerResource("acct:alice@divine.video"), {
    kind: "Lookup",
    user: "alice",
  });
  assertEquals(parseWebFingerResource("acct:alice@dvines.org"), {
    kind: "Lookup",
    user: "alice",
  });
  assertEquals(parseWebFingerResource("alice"), { kind: "Lookup", user: "alice" });
  assertEquals(parseWebFingerResource("acct:alice"), { kind: "Lookup", user: "alice" });
  assertEquals(parseWebFingerResource("acct:ALICE@DIVINE.VIDEO"), {
    kind: "Lookup",
    user: "alice",
  });
  assertEquals(parseWebFingerResource("acct:alice@evil.com"), { kind: "NotFound" });
  assertEquals(parseWebFingerResource("acct:alice@divine.video.evil.com"), { kind: "NotFound" });
  assertEquals(parseWebFingerResource(""), { kind: "BadRequest" });
  assertEquals(parseWebFingerResource("acct:@divine.video"), { kind: "BadRequest" });

  const jrd = buildWebFingerJrd("alice");
  assertEquals(jrd.subject, "acct:alice@divine.video");
  assertEquals((jrd.aliases as string[])[0], "https://alice.divine.video");
  assertEquals((jrd.aliases as string[])[1], "https://divine.video/ap/users/alice");
});

Deno.test("host classification: apex, ports, system, retired, usernames, multi-level, unknown", () => {
  assertEquals(classifyHost("divine.video"), { kind: "Apex" });
  assertEquals(classifyHost("dvines.org"), { kind: "Apex" });
  assertEquals(classifyHost("divine.video:443"), { kind: "Apex" });
  assertEquals(classifyHost("daniel.divine.video:8080"), {
    kind: "Username",
    username: "daniel",
  });
  assertEquals(classifyHost("DANIEL.divine.video"), { kind: "Username", username: "daniel" });
  assertEquals(classifyHost("bob.dvines.org"), { kind: "Username", username: "bob" });
  assertEquals(classifyHost("foo.bar.divine.video"), { kind: "MultiLevel" });
  assertEquals(classifyHost("example.com"), { kind: "Apex" });

  for (
    const sub of [
      "www",
      "api",
      "api2",
      "relay2",
      "relay",
      "media",
      "stream",
      "names",
      "login",
      "pds",
      "feed",
      "labeler",
      "invite",
    ]
  ) {
    assertEquals(classifyHost(`${sub}.divine.video`), { kind: "System", subdomain: sub });
  }

  for (const retired of RETIRED_SYSTEM_SUBDOMAINS) {
    assertEquals(SYSTEM_SUBDOMAINS.has(retired), true);
  }
  assertEquals(isRetiredSystemSubdomain("stream"), true);
  assertEquals(isRetiredSystemSubdomain("STREAM"), true);
  assertEquals(isRetiredSystemSubdomain("media"), false);
});

Deno.test("retired system response returns 410 Gone", async () => {
  const resp = retiredSystemResponse();
  assertEquals(resp.status, 410);
  assertEquals(resp.headers.get("content-type"), "text/plain; charset=utf-8");
  assertEquals(await resp.text(), "Gone\n");
});

Deno.test("candidate hosts use isolated origin and bypass cache", () => {
  for (const host of ["api2.divine.video", "relay2.divine.video", "API2.DIVINE.VIDEO:443"]) {
    assertEquals(isCandidateHost(host), true);
    const headers = passthroughHeaders(CANDIDATE_API_BACKEND, host, "https");
    assertEquals(headers.backendHost, CANDIDATE_BACKEND_HOST);
    assertEquals(headers.originalHost, host);
    assertEquals(
      passthroughCacheMode(host, "GET", "/api/videos", false, false, CANDIDATE_API_BACKEND),
      { kind: "Pass" },
    );
  }
  for (
    const host of [
      "api.divine.video",
      "relay.divine.video",
      "api2.dvines.org",
      "api2.divine.video.example.com",
      "evilapi2.divine.video",
    ]
  ) {
    assertEquals(isCandidateHost(host), false);
  }
});

Deno.test("API backend routing: mobile_api, sound_proxy, and Funnelcake fallback", () => {
  for (
    const [method, path] of [
      ["GET", "/v1/account/moderation-status"],
      ["POST", "/v1/minor-review-cases/greenlight"],
      ["POST", "/v1/minor-review-cases/case-123/parent-contact"],
      ["POST", "/v1/minor-review-cases/case-123/parent-consent"],
      ["POST", "/api/zendesk/pre-auth"],
      ["OPTIONS", "/v1/account/moderation-status"],
      ["OPTIONS", "/api/zendesk/pre-auth"],
    ]
  ) {
    assertEquals(apiBackendFor(CANONICAL_API_HOST, method, path), MOBILE_API_BACKEND);
  }

  for (
    const [method, path] of [
      ["GET", "/v1/minor-review-cases/greenlight"],
      ["POST", "/v1/minor-review-cases/greenlight/extra"],
      ["POST", "/v1/account/moderation-status"],
      ["POST", "/v1/minor-review-cases//parent-consent"],
      ["POST", "/v1/minor-review-cases/case/extra/parent-contact"],
      ["GET", "/api/zendesk/pre-auth"],
      ["GET", "/api/search"],
    ]
  ) {
    assertEquals(apiBackendFor(CANONICAL_API_HOST, method, path), FUNNELCAKE_API_BACKEND);
  }

  assertEquals(apiBackendFor("api.dvines.org", "GET", "/v1/account/moderation-status"), FUNNELCAKE_API_BACKEND);
  assertEquals(apiBackendFor("API.divine.video", "GET", "/v1/account/moderation-status"), MOBILE_API_BACKEND);
  assertEquals(apiBackendFor("api.divine.video:443", "GET", "/v1/account/moderation-status"), MOBILE_API_BACKEND);

  for (const method of ["GET", "OPTIONS"]) {
    for (
      const path of [
        "/api/sounds/providers",
        "/api/sounds/trending",
        "/api/sounds/evt123/videos",
      ]
    ) {
      assertEquals(apiBackendFor(CANONICAL_API_HOST, method, path), SOUND_PROXY_BACKEND);
    }
  }
  for (const method of ["POST", "PUT", "DELETE", "HEAD"]) {
    assertEquals(apiBackendFor(CANONICAL_API_HOST, method, "/api/sounds/trending"), FUNNELCAKE_API_BACKEND);
  }
  for (
    const path of [
      "/api/sounds",
      "/api/sounds/",
      "/api/sounds/evt123",
      "/api/sounds/evt123/stats",
      "/api/sounds/evt123/videos/extra",
      "/api/sounds//videos",
      "/api/sounds/search",
      "/api/sounds/trending/weekly",
    ]
  ) {
    assertEquals(apiBackendFor(CANONICAL_API_HOST, "GET", path), FUNNELCAKE_API_BACKEND);
  }
  assertEquals(apiBackendFor("api.dvines.org", "GET", "/api/sounds/trending"), FUNNELCAKE_API_BACKEND);
  assertEquals(backendHostFor(SOUND_PROXY_BACKEND), SOUND_PROXY_BACKEND_HOST);
});

Deno.test("cache policy, stale-if-error, and well-known bypass rules", () => {
  assertEquals(apiCachePolicy("api.divine.video", "GET", "/api/search", false, false), {
    cacheable: true,
    fallbackTtlSecs: 30,
  });
  assertEquals(apiCachePolicy("api.divine.video", "POST", "/api/events", false, false).cacheable, false);
  assertEquals(apiCachePolicy("api.divine.video", "GET", "/api/search", true, false).cacheable, false);
  assertEquals(apiCachePolicy("api.divine.video", "GET", "/api/docs", false, false).cacheable, false);
  assertEquals(apiCachePolicy("api.divine.video", "GET", "/api/search", false, true).cacheable, false);
  assertEquals(apiCachePolicy("relay.divine.video", "GET", "/api/search", false, false).cacheable, false);

  assertEquals(
    passthroughCacheMode("api.divine.video", "GET", "/api/search", false, false, FUNNELCAKE_API_BACKEND),
    { kind: "Cacheable", fallbackTtlSecs: 30, honorsOriginStaleIfError: true },
  );
  assertEquals(
    passthroughCacheMode("api.divine.video", "GET", "/feed/global.xml", false, false, FUNNELCAKE_API_BACKEND),
    { kind: "Cacheable", fallbackTtlSecs: null, honorsOriginStaleIfError: true },
  );
  assertEquals(
    passthroughCacheMode("api.divine.video", "GET", "/feed/global.xml", true, false, FUNNELCAKE_API_BACKEND),
    { kind: "Pass" },
  );
  assertEquals(
    passthroughCacheMode("api.divine.video", "GET", "/api/sounds/trending", false, false, SOUND_PROXY_BACKEND),
    { kind: "Pass" },
  );
  assertEquals(
    passthroughCacheMode("api.divine.video", "GET", "/v1/account/moderation-status", false, false, MOBILE_API_BACKEND),
    { kind: "Pass" },
  );
  assertEquals(
    passthroughCacheMode("divine.video", "GET", "/.well-known/webfinger", false, false, MAIN_BACKEND),
    { kind: "Pass" },
  );

  assertEquals(
    staleIfErrorOverrideSecs({
      kind: "Cacheable",
      fallbackTtlSecs: null,
      honorsOriginStaleIfError: true,
    }),
    EDGE_STALE_IF_ERROR_SECS,
  );
  assertEquals(
    staleIfErrorOverrideSecs({
      kind: "Cacheable",
      fallbackTtlSecs: null,
      honorsOriginStaleIfError: false,
    }),
    0,
  );
  assertEquals(staleIfErrorOverrideSecs({ kind: "Pass" }), null);

  assertEquals(candidateCacheAction(true, true, true, false, 0, null), { kind: "ServeStale" });
  assertEquals(candidateCacheAction(true, true, false, false, 0, 30), { kind: "PreserveOrigin" });
  assertEquals(candidateCacheAction(true, false, false, true, 0, 30), { kind: "PreserveOrigin" });
  assertEquals(candidateCacheAction(false, false, false, false, 0, 30), {
    kind: "SetFallbackTtl",
    ttlSecs: 30,
  });
  assertEquals(candidateCacheAction(false, false, false, false, 120, 30), {
    kind: "PreserveOrigin",
  });

  assertEquals(isRssFeedPath("/feed/global.xml"), true);
  assertEquals(isRssFeedPath("/feed"), false);
  assertEquals(isRssFeedPath("/feedback"), false);
  assertEquals(honorsOriginStaleIfError("api.divine.video", "GET", "/feed/global.xml", false, false, { cacheable: false, fallbackTtlSecs: null }), true);
  assertEquals(shouldBypassCache("divine.video", "/.well-known/apple-app-site-association"), true);
  assertEquals(shouldBypassCache("alice.divine.video", "/.well-known/nostr.json"), false);
  assertEquals(isPublicDivineHost("divine.video"), true);
  assertEquals(isPublicDivineHost("example.com"), false);
});

Deno.test("Accept-Encoding normalization matches RFC 9110 q=0 and wildcard rules", () => {
  assertEquals(normalizedAcceptEncoding("gzip, deflate, br, zstd"), "br");
  assertEquals(normalizedAcceptEncoding("br"), "br");
  assertEquals(normalizedAcceptEncoding("gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("gzip, deflate"), "gzip");
  assertEquals(normalizedAcceptEncoding("deflate, gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("gzip;q=1.0"), "gzip");
  assertEquals(normalizedAcceptEncoding("identity"), null);
  assertEquals(normalizedAcceptEncoding("deflate"), null);
  assertEquals(normalizedAcceptEncoding(""), null);
  assertEquals(normalizedAcceptEncoding("zstd"), null);
  assertEquals(normalizedAcceptEncoding("br;q=0, gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("br;Q=0, gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("br ; q = 0 , gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("br;q=0.0, gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("gzip;q=0, br"), "br");
  assertEquals(normalizedAcceptEncoding("br;q=0, gzip;q=0"), null);
  assertEquals(normalizedAcceptEncoding("*"), "br");
  assertEquals(normalizedAcceptEncoding("gzip;q=0, *"), "br");
  assertEquals(normalizedAcceptEncoding("br;q=0, *"), "gzip");
  assertEquals(normalizedAcceptEncoding("br;q=0, gzip;q=0, *"), null);
  assertEquals(normalizedAcceptEncoding("*;q=0, gzip"), "gzip");
  assertEquals(normalizedAcceptEncoding("  GZIP , Deflate "), "gzip");

  assertEquals(
    shouldNormalizeAcceptEncoding(
      { kind: "Cacheable", fallbackTtlSecs: 30, honorsOriginStaleIfError: true },
      FUNNELCAKE_API_BACKEND,
      "api.divine.video",
      "/api/videos",
    ),
    true,
  );
  assertEquals(
    shouldNormalizeAcceptEncoding(
      { kind: "Pass" },
      FUNNELCAKE_API_BACKEND,
      "api.divine.video",
      "/api/videos",
    ),
    false,
  );
});

Deno.test("ATProto DID response requires active + ready + did", async () => {
  const ready = buildAtprotoDidResponse(makeAtprotoUser("pk", "did:plc:abc123", "ready"));
  assertEquals(ready.status, 200);
  assertEquals(await ready.text(), "did:plc:abc123");

  assertEquals(buildAtprotoDidResponse(makeAtprotoUser("pk", "did:plc:abc123", "pending")).status, 404);
  assertEquals(buildAtprotoDidResponse(makeActiveUser("pk")).status, 404);
  assertEquals(
    buildAtprotoDidResponse({
      pubkey: "pk",
      status: "revoked",
      atproto_did: "did:plc:abc123",
      atproto_state: "ready",
    }).status,
    404,
  );
});

Deno.test("applyPassthroughHeaders overwrites spoofed X-Original-Host", () => {
  const headers = new Headers();
  headers.append("x-original-host", "spoofed.example");
  headers.append("x-original-host", "another-spoofed.example");
  applyPassthroughHeaders(headers, passthroughHeaders(FUNNELCAKE_API_BACKEND, "api.divine.video", "https"));

  assertEquals(headers.get("host"), FUNNELCAKE_BACKEND_HOST);
  assertEquals(headers.get("x-original-host"), "api.divine.video");
  assertEquals(headers.get("x-forwarded-host"), "api.divine.video");
  assertEquals(headers.get("x-forwarded-proto"), "https");
});

Deno.test("routeDecisionFor maps apex, ActivityPub, system, and username routes", () => {
  assertEquals(routeDecisionFor("divine.video", "GET", "/.well-known/webfinger"), { kind: "WebFinger" });
  assertEquals(routeDecisionFor("divine.video", "GET", "/ap/users/alice"), {
    kind: "Passthrough",
    backend: ACTIVITYPUB_BACKEND,
  });
  assertEquals(routeDecisionFor("media.divine.video", "GET", "/abc"), {
    kind: "Passthrough",
    backend: BLOSSOM_BACKEND,
  });
  assertEquals(routeDecisionFor("invite.divine.video", "GET", "/"), {
    kind: "Passthrough",
    backend: INVITE_BACKEND,
  });
  assertEquals(routeDecisionFor("stream.divine.video", "GET", "/"), { kind: "RetiredSystem" });
  assertEquals(routeDecisionFor("alice.divine.video", "GET", "/"), {
    kind: "Username",
    username: "alice",
  });
});

Deno.test("end-to-end standalone handler: API proxy, Accept-Encoding, fallback TTL, spoofed header overwrite", async () => {
  let capturedUrl = "";
  let capturedHeaders: Headers | null = null;

  const mockFetch: typeof fetch = (input, init) => {
    capturedUrl = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    capturedHeaders = new Headers(init?.headers);
    return Promise.resolve(
      new Response(JSON.stringify({ videos: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  };

  const handler = createRouterHandler({ fetcher: mockFetch });
  const req = new Request("https://api.divine.video/api/videos?limit=10", {
    headers: {
      host: "api.divine.video",
      "accept-encoding": "gzip, deflate, br, zstd",
      "x-original-host": "evil.example",
    },
  });

  const resp = await handler(req);
  assertEquals(resp.status, 200);
  assertEquals(capturedUrl, "https://relay.divine.video/api/videos?limit=10");
  assertEquals(capturedHeaders!.get("host"), FUNNELCAKE_BACKEND_HOST);
  assertEquals(capturedHeaders!.get("x-original-host"), "api.divine.video");
  assertEquals(capturedHeaders!.get("accept-encoding"), "br");
  // Fastly's fallback only sets the edge TTL. Clients must not be told to cache:
  // the fallback goes to CDN-Cache-Control plus a shared-cache-only s-maxage.
  assertEquals(resp.headers.get("cache-control"), "s-maxage=30");
  assertEquals(
    resp.headers.get("cdn-cache-control"),
    `public, max-age=30, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );
});

Deno.test("fallback TTL preserves origin browser Cache-Control (max-age=0 stays max-age=0)", async () => {
  const handler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: { "cache-control": "max-age=0, must-revalidate" },
        }),
      ),
  });
  const resp = await handler(
    new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video" },
    }),
  );
  assertEquals(resp.headers.get("cache-control"), "max-age=0, must-revalidate, s-maxage=30");
  assertEquals(
    resp.headers.get("cdn-cache-control"),
    `public, max-age=30, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );

  // An origin s-maxage=0 is replaced, not duplicated.
  const sZeroHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", { status: 404, headers: { "cache-control": "max-age=5, s-maxage=0" } }),
      ),
  });
  const sZeroResp = await sZeroHandler(
    new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video" },
    }),
  );
  assertEquals(sZeroResp.headers.get("cache-control"), "max-age=5, s-maxage=30");
});

Deno.test("end-to-end standalone handler: authenticated API request bypasses cache and keeps Accept-Encoding", async () => {
  let capturedHeaders: Headers | null = null;
  const mockFetch: typeof fetch = (_input, init) => {
    capturedHeaders = new Headers(init?.headers);
    return Promise.resolve(new Response("{}", { status: 200 }));
  };

  const handler = createRouterHandler({ fetcher: mockFetch });
  const req = new Request("https://api.divine.video/api/videos", {
    headers: {
      host: "api.divine.video",
      authorization: "Nostr test-token",
      "accept-encoding": "gzip, deflate, br",
    },
  });

  const resp = await handler(req);
  assertEquals(capturedHeaders!.get("accept-encoding"), "gzip, deflate, br");
  assertEquals(resp.headers.get("cdn-cache-control"), "no-store");
});

Deno.test("end-to-end standalone handler: publicHostOverride enables staging hostname testing", async () => {
  let capturedUrl = "";
  let capturedHeaders: Headers | null = null;
  const mockFetch: typeof fetch = (input, init) => {
    capturedUrl = String(input);
    capturedHeaders = new Headers(init?.headers);
    return Promise.resolve(new Response("{}", { status: 200 }));
  };

  const handler = createRouterHandler({
    publicHostOverride: "api.divine.video",
    fetcher: mockFetch,
  });

  const req = new Request("https://divine-api-test.bunny.run/v1/account/moderation-status", {
    headers: { host: "divine-api-test.bunny.run" },
  });

  await handler(req);
  assertEquals(capturedUrl, `https://${MOBILE_API_BACKEND_HOST}/v1/account/moderation-status`);
  assertEquals(capturedHeaders!.get("x-original-host"), "api.divine.video");
});

Deno.test("end-to-end standalone handler: username NIP-05, WebFinger, ATProto, dotless fallback, and 404", async () => {
  const fixtureRaw = JSON.parse(
    await Deno.readTextFile(new URL("../../kv_usernames.json", import.meta.url)),
  );
  const store = new MemoryUsernameStore({
    ...fixtureRaw,
    lelepons: makeActiveUser("deadbeef", []),
  });

  let proxiedHost = "";
  const mockFetch: typeof fetch = (_input, init) => {
    proxiedHost = new Headers(init?.headers).get("x-original-host") ?? "";
    return Promise.resolve(new Response("profile-html", { status: 200 }));
  };

  const handler = createRouterHandler({ usernameStore: store, fetcher: mockFetch });

  // WebFinger on apex
  const wf = await handler(
    new Request("https://divine.video/.well-known/webfinger?resource=acct:alice@divine.video", {
      headers: { host: "divine.video" },
    }),
  );
  assertEquals(wf.status, 200);
  assertEquals(wf.headers.get("content-type"), "application/jrd+json");
  assertEquals((await wf.json()).subject, "acct:alice@divine.video");

  // NIP-05 on subdomain
  const nip05 = await handler(
    new Request("https://rabble.divine.video/.well-known/nostr.json?name=_", {
      headers: { host: "rabble.divine.video" },
    }),
  );
  assertEquals(nip05.status, 200);
  const nip05Body = await nip05.json();
  assertEquals(
    nip05Body.names._,
    "76c71aae3a491f1d9eec47cba17e229cda4113a0bbb6e6ae1776d7643e29cafa",
  );

  // ATProto DID on ready user
  const did = await handler(
    new Request("https://rabble.divine.video/.well-known/atproto-did", {
      headers: { host: "rabble.divine.video" },
    }),
  );
  assertEquals(did.status, 200);
  assertEquals(await did.text(), "did:plc:raaaaab1e000000000000000");

  // Pending user returns 404
  const pending = await handler(
    new Request("https://testuser.divine.video/", {
      headers: { host: "testuser.divine.video" },
    }),
  );
  assertEquals(pending.status, 404);
  assertMatch(await pending.text(), /@testuser not found/);

  // Active user proxies to MAIN_BACKEND with X-Original-Host
  const profile = await handler(
    new Request("https://alice.divine.video/", {
      headers: { host: "alice.divine.video" },
    }),
  );
  assertEquals(profile.status, 200);
  assertEquals(proxiedHost, "alice.divine.video");

  // Dotless lookup fallback
  const dotless = await lookupUsernameWithFallback(store, "lele.pons");
  assertEquals(dotless?.pubkey, "deadbeef");
});

Deno.test("Pull Zone middleware rewrites origin URL and applies cache policy on origin response", async () => {
  const { onOriginRequest, onOriginResponse } = createPullZoneMiddleware();

  const req = new Request("https://api.divine.video/api/sounds/trending", {
    headers: { host: "api.divine.video" },
  });
  const rewritten = await onOriginRequest({ request: req });
  assertEquals(rewritten instanceof Request, true);
  const rewrittenReq = rewritten as Request;
  assertEquals(rewrittenReq.url, `https://${SOUND_PROXY_BACKEND_HOST}/api/sounds/trending`);
  assertEquals(rewrittenReq.headers.get("host"), SOUND_PROXY_BACKEND_HOST);
  assertEquals(rewrittenReq.headers.get("x-original-host"), "api.divine.video");

  const finalResp = await onOriginResponse({
    request: rewrittenReq,
    response: new Response("[]", { status: 200 }),
  });
  assertEquals(finalResp.headers.get("cdn-cache-control"), "no-store");

  // ActivityPub apex rewrite
  const apReq = await onOriginRequest({
    request: new Request("https://divine.video/ap/users/alice", {
      headers: { host: "divine.video" },
    }),
  });
  assertEquals((apReq as Request).url, `https://${ACTIVITYPUB_BACKEND_HOST}/ap/users/alice`);

  // Surrogate-Control is mirrored to CDN-Cache-Control for Bunny Pull Zones
  const apiReq = new Request("https://api.divine.video/api/videos", {
    headers: { host: "api.divine.video", "x-original-host": "api.divine.video" },
  });
  const apiResp = await onOriginResponse({
    request: apiReq,
    response: new Response("[]", {
      status: 200,
      headers: {
        "cache-control": "public, max-age=10",
        "surrogate-control": "max-age=30, stale-while-revalidate=600, stale-if-error=86400",
      },
    }),
  });
  assertEquals(
    apiResp.headers.get("cdn-cache-control"),
    "max-age=30, stale-while-revalidate=600, stale-if-error=86400",
  );
  assertEquals(
    apiResp.headers.get("cache-control"),
    "public, max-age=10, s-maxage=30",
  );
});

Deno.test("security & cache-policy regression tests: private/no-store, Pass override, X-Forwarded-Proto spoofing, stale-if-error=0", async () => {
  // 1. Origin Cache-Control: private or no-store must NEVER be upgraded to public, max-age=30
  for (const cc of ["private, max-age=0", "no-store", "no-cache"]) {
    const handler = createRouterHandler({
      fetcher: () =>
        Promise.resolve(
          new Response("{}", {
            status: 200,
            headers: { "cache-control": cc },
          }),
        ),
    });
    const resp = await handler(
      new Request("https://api.divine.video/api/videos", {
        headers: { host: "api.divine.video" },
      }),
    );
    assertEquals(resp.headers.get("cache-control"), cc);
    assertEquals(resp.headers.get("cdn-cache-control"), "no-store");
  }

  // 2. Pass mode (Authorization) unconditionally forces cdn-cache-control: no-store and private, no-store
  //    even if origin sends Cache-Control: public, max-age=30
  const authHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: {
            "cache-control": "public, max-age=30",
            "cdn-cache-control": "max-age=30",
          },
        }),
      ),
  });
  const authResp = await authHandler(
    new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video", authorization: "Nostr secret" },
    }),
  );
  assertEquals(authResp.headers.get("cdn-cache-control"), "no-store");
  assertEquals(authResp.headers.get("cache-control"), "private, no-store");

  // 3. Client-supplied X-Forwarded-Proto: http on an HTTPS request must NOT be trusted
  let seenProto = "";
  const protoHandler = createRouterHandler({
    fetcher: (_input, init) => {
      seenProto = new Headers(init?.headers).get("x-forwarded-proto") ?? "";
      return Promise.resolve(new Response("ok", { status: 200 }));
    },
  });
  await protoHandler(
    new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video", "x-forwarded-proto": "http" },
    }),
  );
  assertEquals(seenProto, "https");

  // 4. Non-API/non-RSS cacheable route emits stale-if-error=0 opt-out
  const webHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("<html></html>", {
          status: 200,
          headers: { "cache-control": "public, max-age=60" },
        }),
      ),
  });
  const webResp = await webHandler(
    new Request("https://www.divine.video/", {
      headers: { host: "www.divine.video" },
    }),
  );
  assertEquals(webResp.headers.get("cache-control"), "public, max-age=60");
  assertEquals(webResp.headers.get("cdn-cache-control"), "public, max-age=60, stale-if-error=0");

  // 5. ATProto DID and dynamic 404 responses carry cache-control: no-store
  const didResp = buildAtprotoDidResponse(makeAtprotoUser("pk", "did:plc:abc123", "ready"));
  assertEquals(didResp.headers.get("cache-control"), "no-store");
  assertEquals(webFingerNotFoundResponse().headers.get("cache-control"), "no-store");
  assertEquals(buildUsernameNotFoundResponse("missing").headers.get("cache-control"), "no-store");

  // 6. Non-Authorization Pass route (e.g. api2.divine.video) overwrites origin Cache-Control: public
  const passPublicHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: { "cache-control": "public, max-age=10" },
        }),
      ),
  });
  const passPublicResp = await passPublicHandler(
    new Request("https://api2.divine.video/api/videos", {
      headers: { host: "api2.divine.video" },
    }),
  );
  assertEquals(passPublicResp.headers.get("cache-control"), "no-store");
  assertEquals(passPublicResp.headers.get("cdn-cache-control"), "no-store");

  // 7. Surrogate-Control: no-store paired with Cache-Control: public forces uncacheable Cache-Control too
  const surrogateNoStoreHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: {
            "cache-control": "public, max-age=10",
            "surrogate-control": "no-store",
          },
        }),
      ),
  });
  const surrogateNoStoreResp = await surrogateNoStoreHandler(
    new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video" },
    }),
  );
  assertEquals(surrogateNoStoreResp.headers.get("cache-control"), "no-store");
  assertEquals(surrogateNoStoreResp.headers.get("cdn-cache-control"), "no-store");

  // 8. Uncacheable 4xx/3xx responses (429, 401, 403, 302) must NOT receive fallback public max-age=30
  for (const status of [302, 400, 401, 403, 429]) {
    const statusHandler = createRouterHandler({
      fetcher: () => Promise.resolve(new Response("", { status })),
    });
    const statusResp = await statusHandler(
      new Request("https://api.divine.video/api/videos", {
        headers: { host: "api.divine.video" },
      }),
    );
    assertEquals(statusResp.headers.get("cache-control"), null);
    assertEquals(statusResp.headers.get("cdn-cache-control"), null);
  }

  // 9. Non-API cacheable route overrides origin stale-if-error=3600 down to stale-if-error=0
  const overrideSieHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("<html></html>", {
          status: 200,
          headers: { "cache-control": "public, max-age=60, stale-if-error=3600" },
        }),
      ),
  });
  const overrideSieResp = await overrideSieHandler(
    new Request("https://www.divine.video/", {
      headers: { host: "www.divine.video" },
    }),
  );
  assertEquals(overrideSieResp.headers.get("cache-control"), "public, max-age=60, stale-if-error=3600");
  assertEquals(overrideSieResp.headers.get("cdn-cache-control"), "public, max-age=60, stale-if-error=0");
});

Deno.test("BunnyDatabaseUsernameStore does not negative-cache HTTP 200 libSQL statement errors", async () => {
  let calls = 0;
  const mockFetch: typeof fetch = () => {
    calls += 1;
    if (calls === 1) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            results: [{ type: "error", error: { message: "SQLITE_BUSY" } }],
          }),
          { status: 200 },
        ),
      );
    }
    return Promise.resolve(
      new Response(
        JSON.stringify({
          results: [
            {
              type: "ok",
              response: {
                result: {
                  rows: [[{ value: "pk1" }, { value: "[]" }, { value: "active" }, { value: null }, { value: null }]],
                },
              },
            },
          ],
        }),
        { status: 200 },
      ),
    );
  };

  const store = new BunnyDatabaseUsernameStore("https://db.bunny.net", "tok", 60_000, mockFetch);
  assertEquals(await store.lookup("alice"), null);
  const recovered = await store.lookup("alice");
  assertEquals(calls, 2);
  assertEquals(recovered?.pubkey, "pk1");
});

Deno.test("BunnyDatabaseUsernameStore parses libSQL pipeline rows and caches hits", async () => {
  let calls = 0;
  const mockFetch: typeof fetch = () => {
    calls += 1;
    return Promise.resolve(
      new Response(
        JSON.stringify({
          results: [
            {
              response: {
                result: {
                  rows: [
                    [
                      { value: "pubkeyhex123" },
                      { value: '["wss://relay.divine.video"]' },
                      { value: "active" },
                      { value: "did:plc:test123" },
                      { value: "ready" },
                    ],
                  ],
                },
              },
            },
          ],
        }),
        { status: 200 },
      ),
    );
  };

  const store = new BunnyDatabaseUsernameStore("https://db.bunny.net", "tok", 60_000, mockFetch);
  const first = await store.lookup("Alice");
  const second = await store.lookup("alice");
  assertEquals(calls, 1);
  assertEquals(first, {
    pubkey: "pubkeyhex123",
    relays: ["wss://relay.divine.video"],
    status: "active",
    atproto_did: "did:plc:test123",
    atproto_state: "ready",
  });
  assertEquals(second, first);
  assertEquals(MAIN_BACKEND_HOST, "inherently-ethical-gelding.edgecompute.app");
});

Deno.test("stale-if-error and Surrogate-Control stay at the edge; clients see origin Cache-Control", async () => {
  for (const status of [200, 404, 429]) {
    const handler = createRouterHandler({
      fetcher: () =>
        Promise.resolve(
          new Response("{}", { status, headers: { "cache-control": "public, max-age=60" } }),
        ),
    });
    const resp = await handler(
      new Request("https://api.divine.video/api/videos", { headers: { host: "api.divine.video" } }),
    );
    assertEquals(resp.headers.get("cache-control"), "public, max-age=60");
    assertEquals(
      resp.headers.get("cdn-cache-control"),
      `public, max-age=60, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
    );
  }

  const surrogateHandler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: { "cache-control": "public, max-age=10", "surrogate-control": "max-age=30" },
        }),
      ),
  });
  const surrogateResp = await surrogateHandler(
    new Request("https://api.divine.video/api/videos", { headers: { host: "api.divine.video" } }),
  );
  assertEquals(surrogateResp.headers.get("surrogate-control"), null);
  assertEquals(surrogateResp.headers.get("cache-control"), "public, max-age=10, s-maxage=30");
  assertEquals(
    surrogateResp.headers.get("cdn-cache-control"),
    `max-age=30, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );
});

Deno.test("Set-Cookie responses get no-store for edge and downstream caches", async () => {
  for (const cc of [null, "public, max-age=60"]) {
    const headers: Record<string, string> = { "set-cookie": "sid=abc; Path=/" };
    if (cc) headers["cache-control"] = cc;
    const handler = createRouterHandler({
      fetcher: () => Promise.resolve(new Response("{}", { status: 200, headers })),
    });
    const resp = await handler(
      new Request("https://api.divine.video/api/videos", { headers: { host: "api.divine.video" } }),
    );
    assertEquals(resp.headers.get("cdn-cache-control"), "no-store");
    assertEquals(resp.headers.get("cache-control"), "no-store");
    assertEquals(resp.headers.get("set-cookie"), "sid=abc; Path=/");
  }
});

Deno.test("An origin CDN policy suppresses the fallback and retains its edge TTL", async () => {
  for (const edgeControl of ["no-store", "max-age=90, stale-if-error=5"]) {
    const handler = createRouterHandler({
      fetcher: () => Promise.resolve(new Response("{}", {
        headers: { "cache-control": "max-age=0", "cdn-cache-control": edgeControl },
      })),
    });
    const response = await handler(new Request("https://api.divine.video/api/videos"));
    assertEquals(response.headers.get("cache-control"), "max-age=0");
    assertEquals(
      response.headers.get("cdn-cache-control"),
      `${edgeControl.split(",")[0]}, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
    );
  }
});

Deno.test("Pull Zone onOriginResponse ignores client-supplied X-Original-Host and stamps Authorization responses", async () => {
  const { onOriginRequest, onOriginResponse } = createPullZoneMiddleware();

  // A client-shaped request (public host in the URL) claiming a non-API host must
  // still be classified by its real Host: the mobile API route stays Pass.
  const spoofed = await onOriginResponse({
    request: new Request("https://api.divine.video/v1/account/moderation-status", {
      headers: { host: "api.divine.video", "x-original-host": "divine.video" },
    }),
    response: new Response("{}", { status: 200, headers: { "cache-control": "public, max-age=60" } }),
  });
  assertEquals(spoofed.headers.get("cdn-cache-control"), "no-store");

  // Authorization responses are private even when the route is not a passthrough.
  const authProfile = await onOriginResponse({
    request: new Request(`https://${MAIN_BACKEND_HOST}/`, {
      headers: {
        host: MAIN_BACKEND_HOST,
        "x-original-host": "bob.divine.video",
        authorization: "Nostr abc",
      },
    }),
    response: new Response("<html></html>", {
      status: 200,
      headers: { "cache-control": "public, max-age=60" },
    }),
  });
  assertEquals(authProfile.headers.get("cdn-cache-control"), "no-store");
  assertEquals(authProfile.headers.get("cache-control"), "private, no-store");

  // A forged rewritten-looking request (backend host, X-Original-Host) without the
  // router's per-isolate marker is not trusted either.
  const forged = await onOriginResponse({
    request: new Request(`https://${FUNNELCAKE_BACKEND_HOST}/api/videos`, {
      headers: {
        host: "api.divine.video",
        "x-original-host": "bob.divine.video",
        "x-divine-router-hop": "guess",
        authorization: "Nostr abc",
      },
    }),
    response: new Response("{}", { status: 200, headers: { "cache-control": "public, max-age=10" } }),
  });
  assertEquals(forged.headers.get("cache-control"), "private, no-store");

  // The request onOriginRequest actually built is trusted.
  const built = await onOriginRequest({
    request: new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video", "x-original-host": "evil.example" },
    }),
  }) as Request;
  assertEquals(built.headers.get("x-original-host"), "api.divine.video");
  const rewritten = await onOriginResponse({
    request: built,
    response: new Response("{}", { status: 200, headers: { "cache-control": "public, max-age=10" } }),
  });
  assertEquals(
    rewritten.headers.get("cdn-cache-control"),
    `public, max-age=10, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );
});

Deno.test("standalone proxy keeps Content-Encoding consistent with what real fetch returns", async () => {
  const { brotliCompressSync, gzipSync } = await import("node:zlib");
  const raw = new TextEncoder().encode(JSON.stringify({ videos: ["a".repeat(512)] }));
  const origin = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, (req) => {
    const ae = req.headers.get("accept-encoding") ?? "";
    const coding = ae.includes("br") ? "br" : ae.includes("gzip") ? "gzip" : null;
    const body = new Uint8Array(
      coding === "br" ? brotliCompressSync(raw) : coding === "gzip" ? gzipSync(raw) : raw,
    );
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "content-length": String(body.length),
      "cache-control": "public, max-age=10",
    };
    if (coding) headers["content-encoding"] = coding;
    return new Response(body, { headers });
  });
  try {
    const handler = createRouterHandler({
      backendUrls: {
        funnelcake_api: `http://127.0.0.1:${origin.addr.port}`,
        main_site: `http://127.0.0.1:${origin.addr.port}`,
      },
      usernameStore: new MemoryUsernameStore({ alice: { pubkey: "pk", status: "active" } }),
    });
    const cases: Array<[string, string | null]> = [
      ["api.divine.video", "gzip"],
      ["api.divine.video", "br"],
      ["api.divine.video", "gzip, deflate, br, zstd"],
      ["api.divine.video", null],
      ["api.divine.video", "identity"],
      ["alice.divine.video", "gzip"],
      ["alice.divine.video", "br"],
    ];
    for (const [host, ae] of cases) {
      const headers: Record<string, string> = { host };
      if (ae) headers["accept-encoding"] = ae;
      const resp = await handler(new Request(`https://${host}/api/videos`, { headers }));
      const bytes = new Uint8Array(await resp.arrayBuffer());
      const ce = resp.headers.get("content-encoding");
      const decoded = ce === null || ce === "identity" ? bytes : null;
      assertEquals(ce, null, `${host} ${ae}: content-encoding must match the decoded body`);
      assertEquals(new TextDecoder().decode(decoded!), new TextDecoder().decode(raw), `${host} ${ae}`);
      const cl = resp.headers.get("content-length");
      if (cl !== null) assertEquals(Number(cl), bytes.length, `${host} ${ae}: content-length`);
    }
  } finally {
    await origin.shutdown();
  }
});

Deno.test("API stale-if-error pin overrides an origin-supplied stale-if-error at the edge", async () => {
  const handler = createRouterHandler({
    fetcher: () =>
      Promise.resolve(
        new Response("{}", {
          status: 200,
          headers: { "cache-control": "public, max-age=10, stale-if-error=60" },
        }),
      ),
  });
  const resp = await handler(
    new Request("https://api.divine.video/api/videos", { headers: { host: "api.divine.video" } }),
  );
  assertEquals(resp.headers.get("cache-control"), "public, max-age=10, stale-if-error=60");
  assertEquals(
    resp.headers.get("cdn-cache-control"),
    `public, max-age=10, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );
});

Deno.test("a configured hop token is honored across middleware instances (separate isolates)", async () => {
  const requestSide = createPullZoneMiddleware({ hopToken: "shared-secret" });
  const responseSide = createPullZoneMiddleware({ hopToken: "shared-secret" });
  const built = await requestSide.onOriginRequest({
    request: new Request("https://api.divine.video/api/videos", {
      headers: { host: "api.divine.video" },
    }),
  }) as Request;
  const resp = await responseSide.onOriginResponse({
    request: built,
    response: new Response("{}", { status: 200, headers: { "cache-control": "public, max-age=10" } }),
  });
  assertEquals(
    resp.headers.get("cdn-cache-control"),
    `public, max-age=10, stale-if-error=${EDGE_STALE_IF_ERROR_SECS}`,
  );
});

Deno.test("strict TV query parsing and route matrix match src/main.rs", () => {
  for (
    const [query, expected] of [
      ["", null],
      ["moderation_profile=default", null],
      ["moderation_profile=strict", "Strict"],
      ["view=tv", "Strict"],
      ["label=anything&%6doderation_profile=%73trict", "Strict"],
      ["search=moderation_profile%3Dstrict", null],
      ["view=tv+extra", null],
    ] as const
  ) {
    const url = new URL(`https://api.divine.video/api/v2/videos?${query}`);
    assertEquals(tvRequest(url.pathname, url), expected, query);
  }

  for (
    const path of [
      "/api/videos",
      "/api/v2/videos",
      "/api/search",
      "/api/v2/search",
      "/api/videos/event/comments",
      "/api/v2/videos/event/comments",
      "/api/users/author/feed",
      "/api/users/author/recommendations",
      "/api/v2/lists",
      "/api/lists/author/tag/items",
      "/api/v2/lists/author/tag/items",
      "/api/featured-tabs",
      "/api/featured-tabs/tab/videos",
    ]
  ) {
    const url = new URL(`https://api.divine.video${path}?view=tv&moderation_profile=strict`);
    assertEquals(tvRequest(path, url), "Strict", path);
  }

  for (
    const path of [
      "/api/categories",
      "/api/hashtags",
      "/api/users/author/events/3",
      "/api/v2/search/lists",
      "/api/v2/lists/discover",
      "/api/videos/event",
    ]
  ) {
    const url = new URL(`https://api.divine.video${path}?view=tv&moderation_profile=strict`);
    assertEquals(tvRequest(path, url), null, path);
  }

  for (
    const path of [
      "/api/search",
      "/api/v2/search",
      "/api/featured-tabs",
      "/api/v2/lists",
      "/api/videos/event/comments",
      "/api/v2/videos/event/comments",
    ]
  ) {
    const url = new URL(`https://api.divine.video${path}?view=tv`);
    assertEquals(tvRequest(path, url), "UnsupportedView", path);
  }
});

Deno.test("strict TV caller context, lease, age, policy, and CDN-Tag helpers match Fastly", () => {
  for (const input of ["followed_hashtags=dogs", "preferred_languages=en", "%73eed=1"]) {
    const url = new URL(
      `https://api.divine.video/api/users/author/recommendations?view=tv&${input}`,
    );
    assertEquals(strictTvUsesCallerContext(url.pathname, url, false), true, input);
  }
  for (
    const raw of [
      "https://api.divine.video/api/users/author/recommendations?view=tv&limit=20",
      "https://api.divine.video/api/v2/videos?view=tv&seed=1",
    ]
  ) {
    const url = new URL(raw);
    assertEquals(strictTvUsesCallerContext(url.pathname, url, false), false, raw);
  }
  const videosUrl = new URL("https://api.divine.video/api/v2/videos?view=tv");
  assertEquals(strictTvUsesCallerContext(videosUrl.pathname, videosUrl, true), true);

  assertEquals(strictTvResponseAllowed(200, null), false);
  assertEquals(strictTvResponseAllowed(200, "strict-v0"), false);
  assertEquals(strictTvResponseAllowed(200, STRICT_TV_POLICY), true);
  assertEquals(strictTvResponseAllowed(302, STRICT_TV_POLICY), false);
  assertEquals(strictTvResponseAllowed(404, null), true);
  assertEquals(strictTvResponseAllowed(503, null), true);

  assertEquals(strictTvCacheLeaseSecs(200, "max-age=15"), 15);
  assertEquals(strictTvCacheLeaseSecs(200, "max-age=120, stale-if-error=86400"), 30);
  assertEquals(strictTvCacheLeaseSecs(200, "max-age=30, max-age=10"), 10);
  assertEquals(strictTvCacheLeaseSecs(200, "max-age=99999999999999999999999"), 30);
  assertEquals(strictTvCacheLeaseSecs(200, "no-store, max-age=30"), null);
  assertEquals(strictTvCacheLeaseSecs(200, "max-age=30foo"), null);
  assertEquals(strictTvCacheLeaseSecs(200, null), null);
  assertEquals(strictTvCacheLeaseSecs(200, "max-age=0"), null);
  assertEquals(strictTvCacheLeaseSecs(503, "max-age=30"), null);

  assertEquals(parseStrictTvAgeSecs(null), 0);
  assertEquals(parseStrictTvAgeSecs("0"), 0);
  assertEquals(parseStrictTvAgeSecs("12"), 12);
  assertEquals(parseStrictTvAgeSecs("99999999999999999999999"), Number.MAX_SAFE_INTEGER);
  for (const invalid of ["", "5, 5", "invalid", "-1"]) {
    assertEquals(parseStrictTvAgeSecs(invalid), null, invalid);
  }

  assertEquals(strictTvLeaseExpired(10, 9), false);
  assertEquals(strictTvLeaseExpired(10, 10), true);
  assertEquals(strictTvLeaseExpired(10, 15), true);
  assertEquals(strictTvLeaseExpired(10, null), true);
  assertEquals(strictTvLeaseExpired(null, 15), false);

  for (const age of [null, "0", "00"]) {
    assertEquals(strictTvPassAgeAllowed(age), true, String(age));
  }
  for (const age of ["", "1", "0, 0", "invalid", "99999999999999999999"]) {
    assertEquals(strictTvPassAgeAllowed(age), false, age);
  }

  assertEquals(
    parseStrictTvCdnTags("videos strict-tv author-abc strict-tv event-def"),
    ["videos", "strict-tv", "author-abc", "event-def"],
  );
  assertEquals(parseStrictTvCdnTags(null), null);
  assertEquals(parseStrictTvCdnTags("videos author-abc"), null);
  // Fail closed on non-ASCII or comma tokens, matching Fastly's HeaderValue::to_str() check.
  assertEquals(parseStrictTvCdnTags("videos strict-tv list-abc-música"), null);
  assertEquals(parseStrictTvCdnTags("videos,strict-tv"), null);
});

Deno.test("Bunny strict TV caches attested 2xx up to 30s with CDN-Tag and zero stale", async () => {
  let forwardedPolicyHeader: string | null = "untouched";
  const handler = createRouterHandler({
    fetcher: (_input, init) => {
      forwardedPolicyHeader = new Headers(init?.headers).get(STRICT_TV_POLICY_HEADER);
      return Promise.resolve(
        new Response('{"videos":[]}', {
          status: 200,
          headers: {
            "content-type": "application/json",
            "cache-control": "public, max-age=0, must-revalidate",
            "surrogate-control": "max-age=120, stale-if-error=86400",
            "surrogate-key": "videos strict-tv author-abc event-def",
            [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
            age: "10",
          },
        }),
      );
    },
  });

  const resp = await handler(
    new Request("https://api.divine.video/api/v2/videos?view=tv&limit=10", {
      headers: {
        host: "api.divine.video",
        [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
      },
    }),
  );

  assertEquals(forwardedPolicyHeader, null, "spoofed request policy header must be stripped");
  assertEquals(resp.status, 200);
  assertEquals(resp.headers.get("surrogate-control"), null);
  assertEquals(resp.headers.get("surrogate-key"), null);
  assertEquals(resp.headers.get("cdn-tag"), "videos, strict-tv, author-abc, event-def");
  assertEquals(
    resp.headers.get("cdn-cache-control"),
    "public, max-age=20, must-revalidate, stale-if-error=0, stale-while-revalidate=0",
  );
  assertEquals(
    resp.headers.get("cache-control"),
    "public, max-age=0, must-revalidate, proxy-revalidate, s-maxage=20, stale-if-error=0, stale-while-revalidate=0",
  );
});

Deno.test("Bunny strict TV fails closed on unattested 200, 3xx, expired lease, upstream error, and bad view=tv", async () => {
  const middleware = createPullZoneMiddleware({ hopToken: "tok" });

  // Unsupported view=tv on strict-only route returns 400 without hitting origin.
  const badView = await middleware.onOriginRequest({
    request: new Request("https://api.divine.video/api/v2/lists?view=tv", {
      headers: { host: "api.divine.video" },
    }),
  });
  assertEquals(badView instanceof Response, true);
  if (badView instanceof Response) {
    assertEquals(badView.status, 400);
    assertEquals(badView.headers.get("access-control-allow-origin"), "*");
    assertEquals(badView.headers.get("cache-control"), "private, no-store");
    assertEquals(badView.headers.get("cdn-cache-control"), "no-store");
  }

  const strictReq = await middleware.onOriginRequest({
    request: new Request("https://api.divine.video/api/v2/videos?moderation_profile=strict", {
      headers: { host: "api.divine.video", [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY },
    }),
  }) as Request;
  assertEquals(strictReq.headers.get(STRICT_TV_POLICY_HEADER), null);

  // Unattested 200 -> 503 with CORS and no-store.
  const unattested = await middleware.onOriginResponse({
    request: strictReq,
    response: new Response('{"videos":[]}', {
      status: 200,
      headers: { "surrogate-control": "max-age=30", "surrogate-key": "videos strict-tv" },
    }),
  });
  assertEquals(unattested.status, 503);
  assertEquals(unattested.headers.get("access-control-allow-origin"), "*");
  assertEquals(unattested.headers.get("cache-control"), "private, no-store");
  assertEquals(unattested.headers.get("cdn-cache-control"), "no-store");

  // 302 redirect -> 503.
  const redirect = await middleware.onOriginResponse({
    request: strictReq,
    response: new Response(null, {
      status: 302,
      headers: { location: "https://example.com", [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY },
    }),
  });
  assertEquals(redirect.status, 503);

  // Exhausted lease (Age >= lease) -> 503.
  const expired = await middleware.onOriginResponse({
    request: strictReq,
    response: new Response('{"videos":[]}', {
      status: 200,
      headers: {
        [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
        "surrogate-control": "max-age=15",
        "surrogate-key": "videos strict-tv",
        age: "15",
      },
    }),
  });
  assertEquals(expired.status, 503);

  // Malformed Age on leased response -> 503.
  const badAge = await middleware.onOriginResponse({
    request: strictReq,
    response: new Response('{"videos":[]}', {
      status: 200,
      headers: {
        [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
        "surrogate-control": "max-age=15",
        "surrogate-key": "videos strict-tv",
        age: "5, 5",
      },
    }),
  });
  assertEquals(badAge.status, 503);

  // Non-ASCII Surrogate-Key fails closed to uncached 200 (never stored without purge tags).
  const badKey = await middleware.onOriginResponse({
    request: strictReq,
    response: new Response('{"videos":[]}', {
      status: 200,
      headers: {
        [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
        "surrogate-control": "max-age=30",
        "surrogate-key": "videos strict-tv list-abc-música",
      },
    }),
  });
  assertEquals(badKey.status, 200);
  assertEquals(badKey.headers.get("cdn-tag"), null);
  assertEquals(badKey.headers.get("cdn-cache-control"), "no-store");
  assertEquals(badKey.headers.get("cache-control"), "private, no-store");

  // Upstream fetch failure in standalone mode returns CORS-readable 503.
  const failingHandler = createRouterHandler({
    fetcher: () => Promise.reject(new Error("origin down")),
  });
  const failed = await failingHandler(
    new Request("https://api.divine.video/api/v2/videos?view=tv", {
      headers: { host: "api.divine.video" },
    }),
  );
  assertEquals(failed.status, 503);
  assertEquals(failed.headers.get("access-control-allow-origin"), "*");
  assertEquals(failed.headers.get("cache-control"), "private, no-store");
});

Deno.test("Bunny strict TV enforces policy and zero-Age on authenticated and caller-private pass reads", async () => {
  const middleware = createPullZoneMiddleware({ hopToken: "tok" });

  for (
    const req of [
      new Request("https://api.divine.video/api/v2/videos?moderation_profile=strict", {
        headers: { host: "api.divine.video", authorization: "Nostr abc" },
      }),
      new Request("https://api.divine.video/api/v2/videos?moderation_profile=strict", {
        headers: { host: "api.divine.video", "x-pubkey": "a".repeat(64) },
      }),
      new Request(
        "https://api.divine.video/api/users/author/recommendations?view=tv&seed=42",
        { headers: { host: "api.divine.video" } },
      ),
    ]
  ) {
    const built = await middleware.onOriginRequest({ request: req }) as Request;

    // Attested pass response with Age: 0 is served uncached (no CDN-Tag).
    const ok = await middleware.onOriginResponse({
      request: built,
      response: new Response('{"videos":[]}', {
        status: 200,
        headers: {
          [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY,
          "surrogate-control": "max-age=30",
          "surrogate-key": "videos strict-tv",
          age: "0",
        },
      }),
    });
    assertEquals(ok.status, 200);
    assertEquals(ok.headers.get("cdn-tag"), null);
    assertEquals(ok.headers.get("surrogate-control"), null);
    assertEquals(ok.headers.get("surrogate-key"), null);
    assertEquals(ok.headers.get("cdn-cache-control"), "no-store");
    assertEquals(ok.headers.get("cache-control"), "private, no-store");

    // Unattested pass response -> 503 even with Authorization header.
    const unattested = await middleware.onOriginResponse({
      request: built,
      response: new Response('{"videos":[]}', { status: 200 }),
    });
    assertEquals(unattested.status, 503);

    // Nonzero Age on pass response -> 503.
    const aged = await middleware.onOriginResponse({
      request: built,
      response: new Response('{"videos":[]}', {
        status: 200,
        headers: { [STRICT_TV_POLICY_HEADER]: STRICT_TV_POLICY, age: "1" },
      }),
    });
    assertEquals(aged.status, 503);
  }
});
