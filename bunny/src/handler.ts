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
  isStrictTvApiRequest,
  MAIN_BACKEND,
  MAIN_BACKEND_HOST,
  normalizedAcceptEncoding,
  parseEffectiveCacheTtlSecs,
  parseStrictTvAgeSecs,
  parseWebFingerResource,
  passthroughCacheMode,
  passthroughHeaders,
  retiredSystemResponse,
  routeDecisionFor,
  shouldNormalizeAcceptEncoding,
  staleIfErrorOverrideSecs,
  STRICT_TV_MAX_AGE_SECS,
  STRICT_TV_POLICY_HEADER,
  strictTvBadRequestResponse,
  strictTvCacheLeaseSecs,
  strictTvCdnTag,
  strictTvLeaseExpired,
  strictTvPassAgeAllowed,
  strictTvResponseAllowed,
  strictTvUnavailableResponse,
  strictTvUsesCallerContext,
  tvRequest,
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
  /**
   * Whether `fetcher` transparently decodes gzip/br response bodies (Deno's
   * fetch does, and keeps Content-Encoding). Defaults to true. Standalone mode
   * only; Pull Zone origin fetches are made by Bunny, not by this script.
   */
  fetchDecodesBodies?: boolean;
  /**
   * Pull Zone Middleware only: value of the hop marker that lets
   * `onOriginResponse` trust the router-set X-Original-Host. Set it (via
   * `ROUTER_HOP_TOKEN`) so requests built in one isolate are recognised in
   * another; unset, each isolate uses its own random value, and a mismatch
   * fails closed (the response is treated as pass).
   */
  hopToken?: string;
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
  strictTv = false,
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

  if (strictTv) {
    headers.delete(STRICT_TV_POLICY_HEADER);
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
 * Deno's fetch transparently decodes gzip and br response bodies unless the
 * request's Accept-Encoding is exactly "identity" (with no Accept-Encoding it
 * sends its own "gzip, br"). It leaves Content-Encoding and the compressed
 * Content-Length on the Response, so proxying it as-is serves a plain body
 * labelled as compressed. Drop both headers when the body was decoded; the
 * serving layer may re-compress for the client.
 */
export function fetchDecodedBody(
  upstreamAcceptEncoding: string | null,
  contentEncoding: string | null,
): boolean {
  const coding = (contentEncoding ?? "").trim().toLowerCase();
  if (coding !== "gzip" && coding !== "br") {
    return false;
  }
  return (upstreamAcceptEncoding ?? "").trim().toLowerCase() !== "identity";
}

function withDecodedBodyHeaders(
  response: Response,
  upstreamAcceptEncoding: string | null,
  config: RouterConfig,
): Response {
  if (
    config.fetchDecodesBodies === false ||
    !fetchDecodedBody(upstreamAcceptEncoding, response.headers.get("content-encoding"))
  ) {
    return response;
  }
  const headers = new Headers(response.headers);
  headers.delete("content-encoding");
  headers.delete("content-length");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

const CACHEABLE_FALLBACK_STATUSES = new Set([200, 203, 204, 206, 300, 301, 404, 410]);

function replaceOrAppendDirective(headerValue: string, directive: string, seconds: number): string {
  const existing = new RegExp(`^${directive}(?:\\s*=|$)`, "i");
  const cleaned = headerValue
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && !existing.test(part));
  cleaned.push(`${directive}=${seconds}`);
  return cleaned.join(", ");
}

function replaceOrAppendStaleIfError(headerValue: string, seconds: number): string {
  return replaceOrAppendDirective(headerValue, "stale-if-error", seconds);
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
    // Unconditionally prevent fronting Bunny Pull Zones and downstream caches
    // from caching pass routes, even if the origin emitted Cache-Control: public.
    headers.set("cdn-cache-control", "no-store");
    headers.set("cache-control", options.hasAuthorization ? "private, no-store" : "no-store");
    headers.delete("surrogate-control");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  const { hasSurrogateControl, ttlSecs, isExplicitlyUncacheable } =
    parseEffectiveCacheTtlSecs(headers);
  const edgeControl = headers.get("cdn-cache-control");

  const setsCookie = headers.has("set-cookie");
  if (isExplicitlyUncacheable || setsCookie) {
    // Never upgrade an origin private/no-store/no-cache response to publicly cacheable,
    // and ensure Cache-Control itself is uncacheable even if only Surrogate-Control was.
    // Do not rely on a cache understanding CDN-Cache-Control to protect a cookie.
    headers.set("cdn-cache-control", "no-store");
    const existingCc = headers.get("cache-control") ?? "";
    const needsClientNoStore = setsCookie ||
      !/\b(?:private|no-store|no-cache)\b/i.test(existingCc);
    if (needsClientNoStore) {
      headers.set("cache-control", "no-store");
    }
    headers.delete("surrogate-control");
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
      if (sieSecs === 0) {
        mirrored = replaceOrAppendStaleIfError(mirrored, 0);
      } else if (sieSecs !== null) {
        // Fastly's set_stale_if_error pins the value regardless of the origin.
        mirrored = replaceOrAppendStaleIfError(mirrored, sieSecs);
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

  // An explicit CDN policy already governs the edge, even when the browser
  // max-age is zero. Do not inject a fallback for other shared caches either.
  if (
    action.kind === "SetFallbackTtl" && edgeControl === null &&
    CACHEABLE_FALLBACK_STATUSES.has(response.status)
  ) {
    // Fastly's fallback (`candidate.set_ttl` in src/main.rs) only changes the edge
    // TTL; clients keep the origin's Cache-Control. Put the fallback in
    // CDN-Cache-Control and a shared-cache-only s-maxage, never in max-age.
    const directives = ["public", `max-age=${action.ttlSecs}`];
    if (sieSecs !== null) {
      directives.push(`stale-if-error=${sieSecs}`);
    }
    headers.set("cdn-cache-control", directives.join(", "));
    const existingCc = headers.get("cache-control");
    headers.set(
      "cache-control",
      existingCc
        ? replaceOrAppendDirective(existingCc, "s-maxage", action.ttlSecs)
        : `s-maxage=${action.ttlSecs}`,
    );
  } else if (!isServerError && sieSecs !== null) {
    // Fastly's set_stale_if_error is edge-only, so the override goes into
    // CDN-Cache-Control (seeded from Cache-Control when absent) and the client's
    // Cache-Control stays exactly as the origin sent it.
    const edgeBase = headers.get("cdn-cache-control") ?? headers.get("cache-control");
    if (sieSecs === 0) {
      // Explicitly opt non-API/non-RSS cacheable routes out of Pull Zone stale-if-error,
      // overriding any origin-supplied stale-if-error directive.
      headers.set(
        "cdn-cache-control",
        edgeBase ? replaceOrAppendStaleIfError(edgeBase, 0) : "stale-if-error=0",
      );
    } else if (edgeBase) {
      // Pin the edge value, as Fastly's set_stale_if_error does, even when the
      // origin sent its own stale-if-error.
      headers.set("cdn-cache-control", replaceOrAppendStaleIfError(edgeBase, sieSecs));
    }
  }

  // Surrogate-Control is an edge-only header (mirrored into CDN-Cache-Control
  // above); Fastly never forwards it to clients.
  headers.delete("surrogate-control");

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
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
      },
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
    headers.delete("upgrade");
    headers.set("host", MAIN_BACKEND_HOST);
    headers.set("x-original-host", originalHost);
    const targetUrl = upstreamUrlFor(MAIN_BACKEND, url, config);
    const method = request.method.toUpperCase();
    const profileResponse = await fetcher(targetUrl, {
      method,
      headers,
      body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });
    return withDecodedBodyHeaders(profileResponse, headers.get("accept-encoding"), config);
  }

  return buildUsernameNotFoundResponse(username);
}

/**
 * Enforces the strict TV cache and attestation policy on a Bunny origin response.
 *
 * Mirrors `configure_strict_tv_cache` and post-send checks in `src/main.rs`:
 * - Rejects unattested 2xx and all 3xx responses with a CORS-readable 503.
 * - Rejects expired leases (or malformed Age headers on leased 2xx responses) with 503.
 * - Rejects nonzero or invalid Age on caller-private (Pass) 2xx reads with 503.
 * - Maps valid visible-ASCII `Surrogate-Key` tokens containing `strict-tv` into Bunny's
 *   `CDN-Tag` header and caps shared caching to `min(lease - age, 30)` seconds with
 *   `stale-if-error=0, stale-while-revalidate=0`.
 * - Refuses to cache non-2xx, unleased, untagged, `Set-Cookie`, or `private`/`no-store`
 *   responses (`CDN-Cache-Control: no-store`, `Cache-Control: private, no-store`).
 */
export function applyStrictTvResponsePolicy(
  response: Response,
  cacheMode: PassthroughCacheMode,
): Response {
  const status = response.status;
  if (!strictTvResponseAllowed(status, response.headers.get(STRICT_TV_POLICY_HEADER))) {
    console.error(`strict TV policy or status rejected: ${status}`);
    void response.body?.cancel();
    return strictTvUnavailableResponse();
  }

  const isSuccess = status >= 200 && status <= 299;
  if (cacheMode.kind === "Pass") {
    if (isSuccess && !strictTvPassAgeAllowed(response.headers.get("age"))) {
      console.error("strict TV pass rejected a nonzero or invalid Age");
      void response.body?.cancel();
      return strictTvUnavailableResponse();
    }
    const headers = new Headers(response.headers);
    headers.delete("surrogate-control");
    headers.delete("surrogate-key");
    headers.delete("cdn-tag");
    headers.set("cdn-cache-control", "no-store");
    headers.set("cache-control", "private, no-store");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  const leaseSecs = strictTvCacheLeaseSecs(status, response.headers.get("surrogate-control"));
  const ageSecs = parseStrictTvAgeSecs(response.headers.get("age"));
  if (strictTvLeaseExpired(leaseSecs, ageSecs)) {
    console.error("strict TV lease expired");
    void response.body?.cancel();
    return strictTvUnavailableResponse();
  }

  const headers = new Headers(response.headers);
  const cdnTag = strictTvCdnTag(headers.get("surrogate-key"));
  const setsCookie = headers.has("set-cookie");
  const originCc = headers.get("cache-control") ?? "";
  const originUncacheable = /(?:^|,|\s)(?:private|no-store|no-cache)(?:$|,|\s|=)/i.test(originCc);
  const remaining =
    leaseSecs !== null && ageSecs !== null
      ? Math.min(Math.max(0, leaseSecs - ageSecs), STRICT_TV_MAX_AGE_SECS)
      : 0;

  headers.delete("surrogate-control");
  headers.delete("surrogate-key");

  if (remaining > 0 && cdnTag !== null && !setsCookie && !originUncacheable) {
    headers.set("cdn-tag", cdnTag);
    headers.set(
      "cdn-cache-control",
      `public, max-age=${remaining}, must-revalidate, stale-if-error=0, stale-while-revalidate=0`,
    );
    headers.set(
      "cache-control",
      `public, max-age=0, must-revalidate, proxy-revalidate, s-maxage=${remaining}, stale-if-error=0, stale-while-revalidate=0`,
    );
  } else {
    headers.delete("cdn-tag");
    headers.set("cdn-cache-control", "no-store");
    headers.set("cache-control", "private, no-store");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
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
        const tvReq = isStrictTvApiRequest(originalHost, method, decision.backend)
          ? tvRequest(path, url)
          : null;
        if (tvReq === "UnsupportedView") {
          return strictTvBadRequestResponse();
        }
        const strictTv = tvReq === "Strict";
        const hasAuthorization = request.headers.has("authorization");
        const isWebsocketUpgrade =
          (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
        const cacheMode = passthroughCacheMode(
          originalHost,
          method,
          path,
          hasAuthorization ||
            (strictTv && strictTvUsesCallerContext(path, url, request.headers.has("x-pubkey"))),
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
          strictTv,
        );
        const targetUrl = upstreamUrlFor(decision.backend, url, config);

        let originResponse: Response;
        try {
          originResponse = await fetcher(targetUrl, {
            method,
            headers: upstreamHeaders,
            body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
            redirect: "manual",
          });
        } catch (error) {
          if (strictTv) {
            console.error("strict TV upstream response unavailable:", error);
            return strictTvUnavailableResponse();
          }
          throw error;
        }

        const decoded = withDecodedBodyHeaders(
          originResponse,
          upstreamHeaders.get("accept-encoding"),
          config,
        );
        if (strictTv) {
          return applyStrictTvResponsePolicy(decoded, cacheMode);
        }
        return applyResponseCachePolicy(decoded, cacheMode, { hasAuthorization });
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
/**
 * Marks origin requests this middleware built. `onOriginResponse` trusts the
 * router-set X-Original-Host only when the marker carries this isolate's
 * random token, so a client-supplied X-Original-Host is never trusted even if
 * the runtime hands `onOriginResponse` the client's own request.
 */
export const ROUTER_HOP_HEADER = "x-divine-router-hop";

export function createPullZoneMiddleware(config: RouterConfig = {}) {
  const store = config.usernameStore ?? new NullUsernameStore();
  const hopToken = config.hopToken || crypto.randomUUID();

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
      headers.set(ROUTER_HOP_HEADER, hopToken);
      return new Request(upstreamUrlFor(MAIN_BACKEND, url, config), {
        method,
        headers,
        body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
        redirect: "manual",
      });
    }

    const tvReq = isStrictTvApiRequest(originalHost, method, decision.backend)
      ? tvRequest(path, url)
      : null;
    if (tvReq === "UnsupportedView") {
      return strictTvBadRequestResponse();
    }
    const strictTv = tvReq === "Strict";
    const hasAuthorization = request.headers.has("authorization");
    const isWebsocketUpgrade =
      (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";
    const cacheMode = passthroughCacheMode(
      originalHost,
      method,
      path,
      hasAuthorization ||
        (strictTv && strictTvUsesCallerContext(path, url, request.headers.has("x-pubkey"))),
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
      strictTv,
    );
    upstreamHeaders.set(ROUTER_HOP_HEADER, hopToken);
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
    const builtByRouter = request.headers.get(ROUTER_HOP_HEADER) === hopToken;
    const routerOriginalHost = builtByRouter ? request.headers.get("x-original-host") : null;
    const originalHost =
      config.publicHostOverride ?? routerOriginalHost ?? resolvePublicHost(request, config);
    const method = request.method.toUpperCase();
    const path = url.pathname;
    const hasAuthorization = request.headers.has("authorization");
    const decision = routeDecisionFor(originalHost, method, path);
    const isWebsocketUpgrade =
      (request.headers.get("upgrade") ?? "").toLowerCase() === "websocket";

    if (
      !config.publicHostOverride &&
      !builtByRouter &&
      method === "GET" &&
      tvRequest(path, url) !== null
    ) {
      // Cross-isolate execution without PUBLIC_HOST_OVERRIDE or a shared
      // ROUTER_HOP_TOKEN cannot trust the rewritten Host header; fail closed
      // so strict TV responses are never served unverified.
      console.error("strict TV response rejected: missing or mismatched router hop token");
      void ctx.response.body?.cancel();
      return Promise.resolve(strictTvUnavailableResponse());
    }

    if (
      decision.kind === "Passthrough" &&
      isStrictTvApiRequest(originalHost, method, decision.backend) &&
      tvRequest(path, url) === "Strict"
    ) {
      const cacheMode = passthroughCacheMode(
        originalHost,
        method,
        path,
        hasAuthorization ||
          strictTvUsesCallerContext(path, url, request.headers.has("x-pubkey")),
        isWebsocketUpgrade,
        decision.backend,
      );
      return Promise.resolve(applyStrictTvResponsePolicy(ctx.response, cacheMode));
    }

    if (hasAuthorization) {
      // The Pull Zone cache key ignores Authorization, so a response to an
      // authenticated request is never stored, whatever the route. This matches
      // the "mark Authorization responses private no-store" Edge Rule.
      return Promise.resolve(
        applyResponseCachePolicy(ctx.response, { kind: "Pass" }, { hasAuthorization }),
      );
    }
    if (decision.kind !== "Passthrough") {
      return Promise.resolve(ctx.response);
    }

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
