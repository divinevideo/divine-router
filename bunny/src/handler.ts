// ABOUTME: Request handler and Bunny Pull Zone middleware builders for divine-router on Deno/Bunny Edge Scripting.
// ABOUTME: Handles upstream proxying, cache-control/stale-if-error signaling, Accept-Encoding normalization, and identity endpoints.

import {
  applyPassthroughHeaders,
  backendHostFor,
  buildAtprotoDidResponse,
  buildNip05Response,
  buildUsernameNotFoundResponse,
  buildWebFingerJrd,
  candidateCacheAction,
  EDGE_STALE_IF_ERROR_SECS,
  MAIN_BACKEND,
  MAIN_BACKEND_HOST,
  normalizedAcceptEncoding,
  parseEffectiveCacheTtlSecs,
  parseWebFingerResource,
  passthroughCacheMode,
  passthroughHeaders,
  retiredSystemResponse,
  routeDecisionFor,
  shouldNormalizeAcceptEncoding,
  staleIfErrorOverrideSecs,
  webFingerNotFoundResponse,
  type BackendName,
  type PassthroughCacheMode,
} from "./router.ts";
import {
  lookupUsernameWithFallback,
  NullUsernameStore,
  type UsernameStore,
} from "./username_store.ts";

export interface RouterConfig {
  /**
   * Optional override for staging/testing on non-production hostnames (e.g.,
   * `api-bunny-test.divine.video` or `*.bunny.run`). Leave unset in production
   * so the incoming HTTP Host header is always authoritative.
   */
  publicHostOverride?: string;
  /**
   * Optional per-backend base URL overrides (useful for local tests or staging origins).
   */
  backendUrls?: Partial<Record<BackendName, string>>;
  usernameStore?: UsernameStore;
  fetcher?: typeof fetch;
}

const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
];

export function resolvePublicHost(request: Request, config?: RouterConfig): string {
  if (config?.publicHostOverride) {
    return config.publicHostOverride;
  }
  const hostHeader = request.headers.get("host");
  if (hostHeader) {
    return hostHeader;
  }
  try {
    return new URL(request.url).host;
  } catch {
    return "";
  }
}

export function resolveRequestProto(request: Request): "http" | "https" {
  // Derive strictly from the incoming request URL scheme (matching src/main.rs)
  // rather than trusting client-supplied X-Forwarded-Proto headers.
  try {
    return new URL(request.url).protocol === "http:" ? "http" : "https";
  } catch {
    return "https";
  }
}

export function upstreamUrlFor(
  backend: BackendName,
  incomingUrl: URL,
  config?: RouterConfig,
): string {
  const overrideBase = config?.backendUrls?.[backend];
  if (overrideBase) {
    return `${overrideBase.replace(/\/$/, "")}${incomingUrl.pathname}${incomingUrl.search}`;
  }
  const host = backendHostFor(backend);
  return `https://${host}${incomingUrl.pathname}${incomingUrl.search}`;
}

function buildUpstreamHeaders(
  incoming: Request,
  backend: BackendName,
  originalHost: string,
  originalProto: string,
  cacheMode: PassthroughCacheMode,
  path: string,
): Headers {
  const headers = new Headers(incoming.headers);
  const isWebsocketUpgrade =
    (incoming.headers.get("upgrade") ?? "").toLowerCase() === "websocket";

  if (!isWebsocketUpgrade) {
    for (const h of HOP_BY_HOP_HEADERS) {
      headers.delete(h);
    }
    headers.delete("upgrade");
  }

  if (shouldNormalizeAcceptEncoding(cacheMode, backend, originalHost, path)) {
    const rawAe = headers.get("accept-encoding");
    const normalized = rawAe ? normalizedAcceptEncoding(rawAe) : null;
    if (normalized) {
      headers.set("accept-encoding", normalized);
    } else {
      headers.delete("accept-encoding");
    }
  }

  applyPassthroughHeaders(headers, passthroughHeaders(backend, originalHost, originalProto));
  return headers;
}

/**
 * Applies divine-router's cache contract onto a proxied origin Response so a
 * fronting Bunny Pull Zone (or downstream cache) mirrors Fastly Compute's
 * cache/bypass/fallback-TTL/stale-if-error behavior.
 */
export function applyResponseCachePolicy(
  response: Response,
  cacheMode: PassthroughCacheMode,
  options: { hasAuthorization?: boolean } = {},
): Response {
  const headers = new Headers(response.headers);

  if (cacheMode.kind === "Pass") {
    // Unconditionally prevent fronting Bunny Pull Zones from caching pass routes,
    // even if the origin emitted Cache-Control: public.
    headers.set("cdn-cache-control", "no-store");
    if (options.hasAuthorization) {
      headers.set("cache-control", "private, no-store");
    } else if (!headers.has("cache-control")) {
      headers.set("cache-control", "no-store");
    }
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  const { hasSurrogateControl, ttlSecs, isExplicitlyUncacheable } =
    parseEffectiveCacheTtlSecs(headers);

  if (isExplicitlyUncacheable) {
    // Never upgrade an origin private/no-store/no-cache response to publicly cacheable.
    headers.set("cdn-cache-control", "no-store");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  const isServerError = response.status >= 500 && response.status <= 599;
  const action = candidateCacheAction(
    cacheMode.honorsOriginStaleIfError,
    isServerError,
    false,
    hasSurrogateControl,
    ttlSecs,
    cacheMode.fallbackTtlSecs,
  );

  const sieSecs = staleIfErrorOverrideSecs(cacheMode);

  // Funnelcake uses Fastly's Surrogate-Control (e.g. max-age=30) to set a
  // longer edge TTL than browser Cache-Control (max-age=10). Mirror it into
  // CDN-Cache-Control AND s-maxage on Cache-Control (when absent) so Bunny
  // honors the 30s edge TTL while browsers keep max-age=10.
  const surrogateControl = headers.get("surrogate-control");
  if (!isServerError && surrogateControl) {
    if (!headers.has("cdn-cache-control")) {
      let mirrored = surrogateControl;
      if (sieSecs !== null && !/stale-if-error/i.test(mirrored)) {
        mirrored = `${mirrored}, stale-if-error=${sieSecs}`;
      }
      headers.set("cdn-cache-control", mirrored);
    }
    const existingCc = headers.get("cache-control");
    const surrogateMaxAge = surrogateControl.match(/(?:^|,|\s)max-age\s*=\s*(\d+)/i);
    if (
      existingCc &&
      surrogateMaxAge &&
      !/s-maxage/i.test(existingCc)
    ) {
      headers.set("cache-control", `${existingCc}, s-maxage=${surrogateMaxAge[1]}`);
    }
  }

  if (action.kind === "SetFallbackTtl") {
    const directives = ["public", `max-age=${action.ttlSecs}`];
    if (sieSecs !== null) {
      directives.push(`stale-if-error=${sieSecs}`);
    }
    const ccValue = directives.join(", ");
    headers.set("cache-control", ccValue);
    if (!headers.has("cdn-cache-control")) {
      headers.set("cdn-cache-control", ccValue);
    }
  } else if (!isServerError && sieSecs !== null) {
    const existingCc = headers.get("cache-control");
    if (existingCc && !/stale-if-error/i.test(existingCc)) {
      headers.set("cache-control", `${existingCc}, stale-if-error=${sieSecs}`);
    }
    if (sieSecs === 0) {
      // Explicitly opt non-API/non-RSS cacheable routes out of Pull Zone stale-if-error.
      const existingCdnCc = headers.get("cdn-cache-control");
      if (existingCdnCc && !/stale-if-error/i.test(existingCdnCc)) {
        headers.set("cdn-cache-control", `${existingCdnCc}, stale-if-error=0`);
      } else if (!existingCdnCc && existingCc) {
        headers.set("cdn-cache-control", `${existingCc}, stale-if-error=0`);
      }
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function handleWebFinger(url: URL, store: UsernameStore): Promise<Response> {
  const resource = url.searchParams.get("resource") ?? "";
  const parsed = parseWebFingerResource(resource);
  if (parsed.kind === "BadRequest") {
    return new Response('{"error":"missing or malformed resource"}', {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  if (parsed.kind === "NotFound") {
    return webFingerNotFoundResponse();
  }

  const userData = await lookupUsernameWithFallback(store, parsed.user);
  if (userData && userData.status === "active") {
    return new Response(JSON.stringify(buildWebFingerJrd(parsed.user)), {
      status: 200,
      headers: {
        "content-type": "application/jrd+json",
        "access-control-allow-origin": "*",
        "cache-control": "no-store",
      },
    });
  }
  return webFingerNotFoundResponse();
}

async function handleUsernameRequest(
  username: string,
  url: URL,
  request: Request,
  originalHost: string,
  config: RouterConfig,
  store: UsernameStore,
  fetcher: typeof fetch,
): Promise<Response> {
  if (url.pathname === "/.well-known/atproto-did") {
    const userData = await lookupUsernameWithFallback(store, username);
    return buildAtprotoDidResponse(userData);
  }

  if (url.pathname === "/.well-known/nostr.json") {
    const queriedName = url.searchParams.get("name") ?? username;
    const userData = await lookupUsernameWithFallback(store, username);
    const body = JSON.stringify(buildNip05Response(queriedName, userData));
    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "cache-control": "no-store",
      },
    });
  }

  const userData = await lookupUsernameWithFallback(store, username);
  if (userData && userData.status === "active") {
    const headers = new Headers(request.headers);
    for (const h of HOP_BY_HOP_HEADERS) {
      headers.delete(h);
    }
    headers.set("host", MAIN_BACKEND_HOST);
    headers.set("x-original-host", originalHost);
    const targetUrl = upstreamUrlFor(MAIN_BACKEND, url, config);
    const method = request.method.toUpperCase();
    return await fetcher(targetUrl, {
      method,
      headers,
      body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });
  }

  return buildUsernameNotFoundResponse(username);
}

/**
 * Full standalone edge router handler matching src/main.rs.
 * Attach to `BunnySDK.net.http.serve(createRouterHandler(config))` or `Deno.serve(...)`.
 */
export function createRouterHandler(
  config: RouterConfig = {},
): (request: Request) => Promise<Response> {
  const store = config.usernameStore ?? new NullUsernameStore();
  const fetcher = config.fetcher ?? fetch;

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const originalHost = resolvePublicHost(request, config);
    const originalProto = resolveRequestProto(request);
    const method = request.method.toUpperCase();
    const path = url.pathname;

    const decision = routeDecisionFor(originalHost, method, path);
    switch (decision.kind) {
      case "RetiredSystem":
        return retiredSystemResponse();
      case "WebFinger":
        return await handleWebFinger(url, store);
      case "Username":
        return await handleUsernameRequest(
          decision.username,
          url,
          request,
          originalHost,
          config,
          store,
          fetcher,
        );
      case "Passthrough": {
        const hasAuthorization = request.headers.has("authorization");
        const isWebsocketUpgrade =
          (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
        const cacheMode = passthroughCacheMode(
          originalHost,
          method,
          path,
          hasAuthorization,
          isWebsocketUpgrade,
          decision.backend,
        );

        const upstreamHeaders = buildUpstreamHeaders(
          request,
          decision.backend,
          originalHost,
          originalProto,
          cacheMode,
          path,
        );
        const targetUrl = upstreamUrlFor(decision.backend, url, config);

        const originResponse = await fetcher(targetUrl, {
          method,
          headers: upstreamHeaders,
          body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
          redirect: "manual",
        });

        return applyResponseCachePolicy(originResponse, cacheMode, { hasAuthorization });
      }
    }
  };
}

/**
 * Pull Zone middleware hooks for running in Bunny Pull Zone Middleware mode
 * (cache HITs bypass Edge Scripting completely for $0 script compute).
 *
 * - `onOriginRequest`: handles synthetic responses (410/WebFinger/NIP-05/ATProto)
 *   and rewrites origin URL + trusted forwarding headers + Accept-Encoding.
 * - `onOriginResponse`: stamps fallback 30s TTL / pass no-store cache directives
 *   before Bunny stores the response in its edge cache.
 */
export function createPullZoneMiddleware(config: RouterConfig = {}) {
  const store = config.usernameStore ?? new NullUsernameStore();

  const onOriginRequest = async (ctx: { request: Request }): Promise<Request | Response> => {
    const request = ctx.request;
    const url = new URL(request.url);
    const originalHost = resolvePublicHost(request, config);
    const originalProto = resolveRequestProto(request);
    const method = request.method.toUpperCase();
    const path = url.pathname;

    const decision = routeDecisionFor(originalHost, method, path);
    if (decision.kind === "RetiredSystem") {
      return retiredSystemResponse();
    }
    if (decision.kind === "WebFinger") {
      return await handleWebFinger(url, store);
    }
    if (decision.kind === "Username") {
      if (path === "/.well-known/atproto-did") {
        return buildAtprotoDidResponse(await lookupUsernameWithFallback(store, decision.username));
      }
      if (path === "/.well-known/nostr.json") {
        const queriedName = url.searchParams.get("name") ?? decision.username;
        const userData = await lookupUsernameWithFallback(store, decision.username);
        return new Response(JSON.stringify(buildNip05Response(queriedName, userData)), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
            "cache-control": "no-store",
          },
        });
      }
      const userData = await lookupUsernameWithFallback(store, decision.username);
      if (!userData || userData.status !== "active") {
        return buildUsernameNotFoundResponse(decision.username);
      }
      const headers = new Headers(request.headers);
      for (const h of HOP_BY_HOP_HEADERS) {
        headers.delete(h);
      }
      headers.delete("upgrade");
      headers.set("host", MAIN_BACKEND_HOST);
      headers.set("x-original-host", originalHost);
      return new Request(upstreamUrlFor(MAIN_BACKEND, url, config), {
        method,
        headers,
        body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
        redirect: "manual",
      });
    }

    const hasAuthorization = request.headers.has("authorization");
    const isWebsocketUpgrade =
      (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
    const cacheMode = passthroughCacheMode(
      originalHost,
      method,
      path,
      hasAuthorization,
      isWebsocketUpgrade,
      decision.backend,
    );
    const upstreamHeaders = buildUpstreamHeaders(
      request,
      decision.backend,
      originalHost,
      originalProto,
      cacheMode,
      path,
    );
    return new Request(upstreamUrlFor(decision.backend, url, config), {
      method,
      headers: upstreamHeaders,
      body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });
  };

  const onOriginResponse = (ctx: {
    request: Request;
    response: Response;
  }): Promise<Response> => {
    const request = ctx.request;
    const url = new URL(request.url);
    const originalHost =
      config.publicHostOverride ??
      request.headers.get("x-original-host") ??
      resolvePublicHost(request, config);
    const method = request.method.toUpperCase();
    const path = url.pathname;
    const decision = routeDecisionFor(originalHost, method, path);
    if (decision.kind !== "Passthrough") {
      return Promise.resolve(ctx.response);
    }

    const hasAuthorization = request.headers.has("authorization");
    const isWebsocketUpgrade =
      (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
    const cacheMode = passthroughCacheMode(
      originalHost,
      method,
      path,
      hasAuthorization,
      isWebsocketUpgrade,
      decision.backend,
    );
    return Promise.resolve(
      applyResponseCachePolicy(ctx.response, cacheMode, { hasAuthorization }),
    );
  };

  return { onOriginRequest, onOriginResponse };
}
