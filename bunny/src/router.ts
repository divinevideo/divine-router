// ABOUTME: Pure routing, host classification, cache policy, and identity helpers for Bunny Edge Scripting.
// ABOUTME: Mirrors src/main.rs so Bunny evaluation runs with 1:1 behavioral parity against Fastly Compute.

export const MAIN_BACKEND = "main_site" as const;
export const BLOSSOM_BACKEND = "blossom" as const;
export const INVITE_BACKEND = "invite_service" as const;
export const FUNNELCAKE_API_BACKEND = "funnelcake_api" as const;
export const CANDIDATE_API_BACKEND = "funnelcake_candidate" as const;
export const MOBILE_API_BACKEND = "mobile_api" as const;
export const SOUND_PROXY_BACKEND = "sound_proxy" as const;
export const ACTIVITYPUB_BACKEND = "activitypub_gateway" as const;
export const SHORTENER_BACKEND = "link_shortener" as const;

export type BackendName =
  | typeof MAIN_BACKEND
  | typeof BLOSSOM_BACKEND
  | typeof INVITE_BACKEND
  | typeof FUNNELCAKE_API_BACKEND
  | typeof CANDIDATE_API_BACKEND
  | typeof MOBILE_API_BACKEND
  | typeof SOUND_PROXY_BACKEND
  | typeof ACTIVITYPUB_BACKEND
  | typeof SHORTENER_BACKEND;

export const MAIN_BACKEND_HOST = "inherently-ethical-gelding.edgecompute.app";
export const BLOSSOM_BACKEND_HOST = "separately-robust-roughy.edgecompute.app";
export const INVITE_BACKEND_HOST = "adversely-polished-yak.edgecompute.app";
export const FUNNELCAKE_BACKEND_HOST = "relay.divine.video";
export const CANDIDATE_BACKEND_HOST = "relay2.divine.video";
export const MOBILE_API_BACKEND_HOST = "api-relay-prod.divine.video";
export const SOUND_PROXY_BACKEND_HOST = "sounds.divine.video";
export const ACTIVITYPUB_BACKEND_HOST = "divine-activity-pub.protestnet.workers.dev";
export const SHORTENER_BACKEND_HOST = "vaguely-robust-ant.edgecompute.app";

export const CANONICAL_API_HOST = "api.divine.video";
export const CANONICAL_WEBFINGER_DOMAIN = "divine.video";
export const STRICT_TV_POLICY_HEADER = "x-divine-tv-policy";
export const STRICT_TV_POLICY = "strict-v1";
export const STRICT_TV_SURROGATE_KEY = "strict-tv";
export const STRICT_TV_MAX_AGE_SECS = 30;
export const OWNED_APEX_DOMAINS: readonly string[] = ["divine.video", "dvines.org"];
export const RETIRED_SYSTEM_CONTENT_TYPE = "text/plain; charset=utf-8";
export const RETIRED_SYSTEM_BODY = "Gone\n";

/**
 * Pins eligible API and RSS stale reuse at the edge for 24 hours.
 * Matches Funnelcake's intended cache contract and src/main.rs.
 */
export const EDGE_STALE_IF_ERROR_SECS = 24 * 60 * 60;
export const API_FALLBACK_TTL_SECS = 30;

export const BLOSSOM_SUBDOMAINS: ReadonlySet<string> = new Set(["media", "blossom"]);
export const INVITE_SUBDOMAINS: ReadonlySet<string> = new Set(["invite"]);
export const RETIRED_SYSTEM_SUBDOMAINS: readonly string[] = ["stream"];

export const SYSTEM_SUBDOMAINS: ReadonlySet<string> = new Set([
  "www",
  "api",
  "api2",
  "relay2",
  "cdn",
  "admin",
  "support",
  "relay",
  "analytics",
  "blossom",
  "funnel",
  "stream",
  "media",
  "gateway",
  "names",
  "login",
  "pds",
  "feed",
  "labeler",
  "invite",
]);

const SOUND_PROXY_API_PATHS: ReadonlySet<string> = new Set([
  "/api/sounds/providers",
  "/api/sounds/trending",
]);

export interface UsernameData {
  pubkey: string;
  relays?: string[];
  status?: string;
  atproto_did?: string | null;
  atproto_state?: string | null;
}

export interface Nip05Response {
  names: Record<string, string>;
  relays?: Record<string, string[]>;
}

export type HostType =
  | { kind: "Apex" }
  | { kind: "MultiLevel" }
  | { kind: "System"; subdomain: string }
  | { kind: "Username"; username: string };

export interface PassthroughHeaders {
  backendHost: string;
  originalHost: string;
  forwardedHost: string;
  forwardedProto: string;
}

export interface ApiCachePolicy {
  cacheable: boolean;
  fallbackTtlSecs: number | null;
}

export type PassthroughCacheMode =
  | { kind: "Pass" }
  | {
    kind: "Cacheable";
    fallbackTtlSecs: number | null;
    honorsOriginStaleIfError: boolean;
  };

export type CandidateCacheAction =
  | { kind: "ServeStale" }
  | { kind: "SetFallbackTtl"; ttlSecs: number }
  | { kind: "PreserveOrigin" };

export type WebFingerLookup =
  | { kind: "Lookup"; user: string }
  | { kind: "BadRequest" }
  | { kind: "NotFound" };

export type RouteDecision =
  | { kind: "Passthrough"; backend: BackendName }
  | { kind: "RetiredSystem" }
  | { kind: "WebFinger" }
  | { kind: "Username"; username: string };

function stripPort(host: string): string {
  const colonIdx = host.indexOf(":");
  return colonIdx === -1 ? host : host.slice(0, colonIdx);
}

export function isOwnedApexDomain(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return OWNED_APEX_DOMAINS.includes(lower);
}

export function isActivityPubPath(path: string): boolean {
  return (
    path === "/ap" ||
    path.startsWith("/ap/") ||
    path === "/.well-known/nodeinfo" ||
    path === "/nodeinfo" ||
    path.startsWith("/nodeinfo/")
  );
}

export function isCandidateHost(host: string): boolean {
  const hostname = stripPort(host).toLowerCase();
  return hostname === "api2.divine.video" || hostname === "relay2.divine.video";
}

export function isShortLinkRoute(host: string, path: string): boolean {
  const hostname = stripPort(host).toLowerCase();
  return (
    (hostname === "divine.video" || hostname === "www.divine.video") &&
    (path === "/l" ||
      path.startsWith("/l/") ||
      path === "/api/links" ||
      path.startsWith("/api/links/"))
  );
}

function isMinorReviewCaseActionPath(path: string, action: string): boolean {
  const prefix = "/v1/minor-review-cases/";
  if (!path.startsWith(prefix) || !path.endsWith(action)) {
    return false;
  }
  const caseId = path.slice(prefix.length, path.length - action.length);
  return caseId.length > 0 && !caseId.includes("/");
}

function isSoundProxyVideosPath(path: string): boolean {
  const prefix = "/api/sounds/";
  const suffix = "/videos";
  if (!path.startsWith(prefix) || !path.endsWith(suffix)) {
    return false;
  }
  const id = path.slice(prefix.length, path.length - suffix.length);
  return id.length > 0 && !id.includes("/");
}

export function isSoundProxyPath(path: string): boolean {
  return SOUND_PROXY_API_PATHS.has(path) || isSoundProxyVideosPath(path);
}

export function apiBackendFor(host: string, method: string, path: string): BackendName {
  const hostname = stripPort(host).toLowerCase();
  if (hostname !== CANONICAL_API_HOST) {
    return FUNNELCAKE_API_BACKEND;
  }

  const isGreenlightStartPath = path === "/v1/minor-review-cases/greenlight";
  const isParentContactPath = isMinorReviewCaseActionPath(path, "/parent-contact");
  const isParentConsentPath = isMinorReviewCaseActionPath(path, "/parent-consent");
  const isMobileApiPath =
    path === "/v1/account/moderation-status" ||
    isGreenlightStartPath ||
    isParentContactPath ||
    isParentConsentPath ||
    path === "/api/zendesk/pre-auth";

  const isSupportedMobileRequest =
    (method === "GET" && path === "/v1/account/moderation-status") ||
    (method === "POST" &&
      (isGreenlightStartPath || isParentContactPath || isParentConsentPath)) ||
    (method === "POST" && path === "/api/zendesk/pre-auth") ||
    (method === "OPTIONS" && isMobileApiPath);

  if (isSupportedMobileRequest) {
    return MOBILE_API_BACKEND;
  }

  if (isSoundProxyPath(path) && (method === "GET" || method === "OPTIONS")) {
    return SOUND_PROXY_BACKEND;
  }

  return FUNNELCAKE_API_BACKEND;
}

export function classifyHost(host: string): HostType {
  const hostname = stripPort(host);
  const parts = hostname.split(".");

  const isOurDomain =
    parts.length >= 2 &&
    (() => {
      const tld = parts[parts.length - 1];
      const sld = parts[parts.length - 2];
      return (sld === "dvines" && tld === "org") || (sld === "divine" && tld === "video");
    })();

  if (!isOurDomain) {
    return { kind: "Apex" };
  }

  if (parts.length === 2) {
    return { kind: "Apex" };
  }

  if (parts.length === 3) {
    const subdomain = parts[0].toLowerCase();
    if (SYSTEM_SUBDOMAINS.has(subdomain)) {
      return { kind: "System", subdomain };
    }
    return { kind: "Username", username: subdomain };
  }

  return { kind: "MultiLevel" };
}

export function isRetiredSystemSubdomain(subdomain: string): boolean {
  const lower = subdomain.toLowerCase();
  return RETIRED_SYSTEM_SUBDOMAINS.includes(lower);
}

export function retiredSystemResponse(): Response {
  return new Response(RETIRED_SYSTEM_BODY, {
    status: 410,
    headers: { "content-type": RETIRED_SYSTEM_CONTENT_TYPE },
  });
}

export function backendHostFor(backend: BackendName | string): string {
  switch (backend) {
    case MAIN_BACKEND:
      return MAIN_BACKEND_HOST;
    case BLOSSOM_BACKEND:
      return BLOSSOM_BACKEND_HOST;
    case INVITE_BACKEND:
      return INVITE_BACKEND_HOST;
    case FUNNELCAKE_API_BACKEND:
      return FUNNELCAKE_BACKEND_HOST;
    case CANDIDATE_API_BACKEND:
      return CANDIDATE_BACKEND_HOST;
    case MOBILE_API_BACKEND:
      return MOBILE_API_BACKEND_HOST;
    case SOUND_PROXY_BACKEND:
      return SOUND_PROXY_BACKEND_HOST;
    case ACTIVITYPUB_BACKEND:
      return ACTIVITYPUB_BACKEND_HOST;
    case SHORTENER_BACKEND:
      return SHORTENER_BACKEND_HOST;
    default:
      return MAIN_BACKEND_HOST;
  }
}

export function routeDecisionFor(host: string, method: string, path: string): RouteDecision {
  if (isCandidateHost(host)) {
    return { kind: "Passthrough", backend: CANDIDATE_API_BACKEND };
  }

  if (isShortLinkRoute(host, path)) {
    return { kind: "Passthrough", backend: SHORTENER_BACKEND };
  }

  const hostnameOnly = stripPort(host);
  if (isOwnedApexDomain(hostnameOnly)) {
    if (path === "/.well-known/webfinger") {
      return { kind: "WebFinger" };
    }
    if (isActivityPubPath(path)) {
      return { kind: "Passthrough", backend: ACTIVITYPUB_BACKEND };
    }
  }

  const hostType = classifyHost(host);
  switch (hostType.kind) {
    case "Apex":
    case "MultiLevel":
      return { kind: "Passthrough", backend: MAIN_BACKEND };
    case "System":
      if (isRetiredSystemSubdomain(hostType.subdomain)) {
        return { kind: "RetiredSystem" };
      }
      if (BLOSSOM_SUBDOMAINS.has(hostType.subdomain)) {
        return { kind: "Passthrough", backend: BLOSSOM_BACKEND };
      }
      if (INVITE_SUBDOMAINS.has(hostType.subdomain)) {
        return { kind: "Passthrough", backend: INVITE_BACKEND };
      }
      if (hostType.subdomain === "api") {
        return { kind: "Passthrough", backend: apiBackendFor(host, method, path) };
      }
      return { kind: "Passthrough", backend: MAIN_BACKEND };
    case "Username":
      return { kind: "Username", username: hostType.username };
  }
}

export function passthroughHeaders(
  backend: BackendName | string,
  originalHost: string,
  originalProto: string,
): PassthroughHeaders {
  return {
    backendHost: backendHostFor(backend),
    originalHost,
    forwardedHost: originalHost,
    forwardedProto: originalProto,
  };
}

export function applyPassthroughHeaders(headers: Headers, spec: PassthroughHeaders): void {
  headers.set("host", spec.backendHost);
  headers.set("x-original-host", spec.originalHost);
  headers.set("x-forwarded-host", spec.forwardedHost);
  headers.set("x-forwarded-proto", spec.forwardedProto);
}

export function isPublicDivineHost(host: string): boolean {
  const hostname = stripPort(host);
  if (isOwnedApexDomain(hostname)) {
    return true;
  }
  return classifyHost(host).kind === "System";
}

export function shouldBypassCache(host: string, path: string): boolean {
  return isPublicDivineHost(host) && (path.startsWith("/.well-known/") || isActivityPubPath(path));
}

export function isRssFeedPath(path: string): boolean {
  return path.startsWith("/feed/");
}

export function apiCachePolicy(
  host: string,
  method: string,
  path: string,
  hasAuthorization: boolean,
  isWebsocketUpgrade: boolean,
): ApiCachePolicy {
  const classified = classifyHost(host);
  const isApiHost = classified.kind === "System" && classified.subdomain === "api";
  const isCacheableApiPath = path.startsWith("/api/") && !path.startsWith("/api/docs");

  if (
    !isApiHost ||
    !isCacheableApiPath ||
    method.toUpperCase() !== "GET" ||
    hasAuthorization ||
    isWebsocketUpgrade
  ) {
    return { cacheable: false, fallbackTtlSecs: null };
  }

  return { cacheable: true, fallbackTtlSecs: API_FALLBACK_TTL_SECS };
}

export function honorsOriginStaleIfError(
  host: string,
  method: string,
  path: string,
  hasAuthorization: boolean,
  isWebsocketUpgrade: boolean,
  policy: ApiCachePolicy,
): boolean {
  const classified = classifyHost(host);
  const isApiHost = classified.kind === "System" && classified.subdomain === "api";

  return (
    isApiHost &&
    method.toUpperCase() === "GET" &&
    !hasAuthorization &&
    !isWebsocketUpgrade &&
    (policy.cacheable || isRssFeedPath(path))
  );
}

export function staleIfErrorOverrideSecs(cacheMode: PassthroughCacheMode): number | null {
  if (cacheMode.kind === "Pass") {
    return null;
  }
  return cacheMode.honorsOriginStaleIfError ? EDGE_STALE_IF_ERROR_SECS : 0;
}

export function passthroughCacheMode(
  host: string,
  method: string,
  path: string,
  hasAuthorization: boolean,
  isWebsocketUpgrade: boolean,
  backend: BackendName | string,
): PassthroughCacheMode {
  if (isCandidateHost(host) || shouldBypassCache(host, path) || isWebsocketUpgrade) {
    return { kind: "Pass" };
  }

  if (
    backend === MOBILE_API_BACKEND ||
    backend === SOUND_PROXY_BACKEND ||
    backend === SHORTENER_BACKEND
  ) {
    return { kind: "Pass" };
  }

  const classified = classifyHost(host);
  const isApiHost = classified.kind === "System" && classified.subdomain === "api";
  const policy = apiCachePolicy(host, method, path, hasAuthorization, isWebsocketUpgrade);
  const honorsSie = honorsOriginStaleIfError(
    host,
    method,
    path,
    hasAuthorization,
    isWebsocketUpgrade,
    policy,
  );
  const isApiRssPath = isRssFeedPath(path) && isApiHost;

  if ((path.startsWith("/api/") && !policy.cacheable) || (isApiRssPath && !honorsSie)) {
    return { kind: "Pass" };
  }

  return {
    kind: "Cacheable",
    fallbackTtlSecs: policy.fallbackTtlSecs,
    honorsOriginStaleIfError: honorsSie,
  };
}

export function candidateCacheAction(
  honorsSie: boolean,
  isServerError: boolean,
  staleIfErrorAvailable: boolean,
  hasSurrogateControl: boolean,
  responseTtlSecs: number,
  fallbackTtlSecs: number | null,
): CandidateCacheAction {
  if (isServerError) {
    return honorsSie && staleIfErrorAvailable
      ? { kind: "ServeStale" }
      : { kind: "PreserveOrigin" };
  }

  if (!hasSurrogateControl && responseTtlSecs <= 0 && fallbackTtlSecs !== null) {
    return { kind: "SetFallbackTtl", ttlSecs: fallbackTtlSecs };
  }

  return { kind: "PreserveOrigin" };
}

export function shouldNormalizeAcceptEncoding(
  cacheMode: PassthroughCacheMode,
  backend: BackendName | string,
  host: string,
  path: string,
): boolean {
  const classified = classifyHost(host);
  return (
    cacheMode.kind === "Cacheable" &&
    backend === FUNNELCAKE_API_BACKEND &&
    classified.kind === "System" &&
    classified.subdomain === "api" &&
    path.startsWith("/api/")
  );
}

/**
 * Normalizes Accept-Encoding to a canonical single coding ("br" or "gzip") to
 * prevent cache key fragmentation across Dart/Chrome/curl clients while
 * respecting RFC 9110 q=0 refusals and wildcards.
 */
export function normalizedAcceptEncoding(header: string): "br" | "gzip" | null {
  let acceptsAny = false;
  let acceptsBrotli = false;
  let acceptsGzip = false;
  let refusesBrotli = false;
  let refusesGzip = false;

  for (const token of header.split(",")) {
    const parts = token.split(";");
    const coding = (parts[0] ?? "").trim().toLowerCase();
    let refused = false;

    for (let i = 1; i < parts.length; i++) {
      const param = parts[i].trim();
      const eqIdx = param.indexOf("=");
      if (eqIdx === -1) continue;
      const name = param.slice(0, eqIdx).trim().toLowerCase();
      if (name !== "q") continue;
      const q = Number.parseFloat(param.slice(eqIdx + 1).trim());
      if (!Number.isNaN(q) && q <= 0) {
        refused = true;
        break;
      }
    }

    if (coding === "br") {
      if (refused) refusesBrotli = true;
      else acceptsBrotli = true;
    } else if (coding === "gzip") {
      if (refused) refusesGzip = true;
      else acceptsGzip = true;
    } else if (coding === "*") {
      acceptsAny = !refused;
    }
  }

  if (acceptsBrotli || (acceptsAny && !refusesBrotli)) {
    return "br";
  }
  if (acceptsGzip || (acceptsAny && !refusesGzip)) {
    return "gzip";
  }
  return null;
}

export function parseWebFingerResource(resource: string): WebFingerLookup {
  const acct = resource.startsWith("acct:") ? resource.slice("acct:".length) : resource;
  const atIdx = acct.indexOf("@");
  const user = (atIdx === -1 ? acct : acct.slice(0, atIdx)).toLowerCase();

  if (!user) {
    return { kind: "BadRequest" };
  }

  if (atIdx !== -1) {
    const host = acct.slice(atIdx + 1);
    if (!isOwnedApexDomain(host)) {
      return { kind: "NotFound" };
    }
  }

  return { kind: "Lookup", user };
}

export function buildWebFingerJrd(user: string): Record<string, unknown> {
  const actor = `https://${CANONICAL_WEBFINGER_DOMAIN}/ap/users/${user}`;
  const profile = `https://${user}.${CANONICAL_WEBFINGER_DOMAIN}`;

  return {
    subject: `acct:${user}@${CANONICAL_WEBFINGER_DOMAIN}`,
    aliases: [profile, actor],
    links: [
      { rel: "http://webfinger.net/rel/profile-page", type: "text/html", href: profile },
      { rel: "self", type: "application/activity+json", href: actor },
    ],
  };
}

export function webFingerNotFoundResponse(): Response {
  return new Response('{"error":"not found"}', {
    status: 404,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
    },
  });
}

export function buildNip05Response(
  queriedName: string,
  userData: UsernameData | null | undefined,
): Nip05Response {
  if (userData && userData.status === "active") {
    const names: Record<string, string> = {
      [queriedName.toLowerCase()]: userData.pubkey,
    };
    const relays =
      userData.relays && userData.relays.length > 0
        ? { [userData.pubkey]: [...userData.relays] }
        : undefined;
    return relays ? { names, relays } : { names };
  }

  return { names: {} };
}

export function buildAtprotoDidResponse(userData: UsernameData | null | undefined): Response {
  if (
    userData &&
    userData.status === "active" &&
    userData.atproto_state === "ready" &&
    userData.atproto_did
  ) {
    return new Response(userData.atproto_did, {
      status: 200,
      headers: {
        "content-type": "text/plain",
        "access-control-allow-origin": "*",
        "cache-control": "no-store",
      },
    });
  }

  return new Response("", {
    status: 404,
    headers: {
      "content-type": "text/plain",
      "cache-control": "no-store",
    },
  });
}

export function buildUsernameNotFoundResponse(username: string): Response {
  const escaped = username
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");

  return new Response(
    `<!DOCTYPE html>
<html>
<head><title>Not Found</title></head>
<body>
<h1>@${escaped} not found</h1>
<p>This username is not registered on Divine.</p>
<p><a href="https://divine.video">Go to Divine</a></p>
</body>
</html>`,
    {
      status: 404,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    },
  );
}

/**
 * Extracts an effective max-age/s-maxage TTL in seconds from Cache-Control or
 * Surrogate-Control headers so Bunny middleware/standalone handlers know when
 * to inject the 30-second API fallback TTL.
 */
export function parseEffectiveCacheTtlSecs(headers: Headers): {
  hasSurrogateControl: boolean;
  ttlSecs: number;
  isExplicitlyUncacheable: boolean;
} {
  const surrogate = headers.get("surrogate-control");
  const hasSurrogateControl = surrogate !== null;
  const cc = headers.get("cache-control") ?? "";

  const parseMaxAge = (value: string, directive: string): number | null => {
    const re = new RegExp(`(?:^|,|\\s)${directive}\\s*=\\s*(\\d+)`, "i");
    const m = value.match(re);
    return m ? Number.parseInt(m[1], 10) : null;
  };

  const isUncacheableDirective = (value: string): boolean =>
    /(?:^|,|\s)(?:no-store|private|no-cache)(?:$|,|\s|=)/i.test(value);

  if (surrogate) {
    if (isUncacheableDirective(surrogate)) {
      return { hasSurrogateControl: true, ttlSecs: 0, isExplicitlyUncacheable: true };
    }
    const maxAge = parseMaxAge(surrogate, "max-age");
    if (maxAge !== null) {
      return {
        hasSurrogateControl: true,
        ttlSecs: maxAge,
        isExplicitlyUncacheable: isUncacheableDirective(cc),
      };
    }
  }

  if (isUncacheableDirective(cc)) {
    return { hasSurrogateControl, ttlSecs: 0, isExplicitlyUncacheable: true };
  }

  const sMaxAge = parseMaxAge(cc, "s-maxage");
  if (sMaxAge !== null) {
    return { hasSurrogateControl, ttlSecs: sMaxAge, isExplicitlyUncacheable: false };
  }

  const maxAge = parseMaxAge(cc, "max-age");
  if (maxAge !== null) {
    return { hasSurrogateControl, ttlSecs: maxAge, isExplicitlyUncacheable: false };
  }

  return { hasSurrogateControl, ttlSecs: 0, isExplicitlyUncacheable: false };
}

export type TvRequest = "Strict" | "UnsupportedView";

/**
 * Normalizes a request path identically to `normalized_api_path_segments` in
 * `src/main.rs` and NGINX Gateway (`merge_slashes`, URI decoding, dot-segment
 * resolution) so raw-path tricks like `/api//v2/videos` or `/api/v2/%76ideos`
 * cannot bypass the strict TV gate or caller-context checks.
 */
export function normalizedApiPathSegments(path: string): string[] {
  const decoded = decodeApiPath(path);
  const segments: string[] = [];
  for (const segment of decoded.split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }
  return segments;
}

// Decode valid escape runs without discarding the surrounding route when an
// opaque segment contains a literal percent or invalid UTF-8.
function decodeApiPath(path: string): string {
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
  return path.replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    }
    return decoder.decode(bytes);
  });
}

function rawSplitApiPathSegments(path: string): string[] {
  const segments: string[] = [];
  for (const rawSegment of path.split("/")) {
    const segment = decodeApiPath(rawSegment);
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      segments.pop();
    } else {
      segments.push(segment);
    }
  }
  return segments;
}

function matchStrictTvSupportsView(segments: string[]): boolean | null {
  if (
    (segments.length === 2 && segments[0] === "api" &&
      (segments[1] === "search" || segments[1] === "featured-tabs")) ||
    (segments.length === 3 && segments[0] === "api" &&
      segments[1] === "v2" && (segments[2] === "search" || segments[2] === "lists")) ||
    (segments.length === 4 && segments[0] === "api" &&
      segments[1] === "videos" && segments[3] === "comments") ||
    (segments.length === 5 && segments[0] === "api" &&
      segments[1] === "v2" && segments[2] === "videos" && segments[4] === "comments")
  ) {
    return false;
  }
  if (
    (segments.length === 2 && segments[0] === "api" &&
      segments[1] === "videos") ||
    (segments.length === 3 && segments[0] === "api" &&
      segments[1] === "v2" && segments[2] === "videos") ||
    (segments.length === 5 && segments[0] === "api" &&
      segments[1] === "lists" && segments[4] === "items") ||
    (segments.length === 6 && segments[0] === "api" &&
      segments[1] === "v2" && segments[2] === "lists" && segments[5] === "items") ||
    (segments.length === 4 && segments[0] === "api" &&
      segments[1] === "users" &&
      (segments[3] === "feed" || segments[3] === "recommendations")) ||
    (segments.length === 4 && segments[0] === "api" &&
      segments[1] === "featured-tabs" && segments[3] === "videos")
  ) {
    return true;
  }
  return null;
}

/**
 * Classifies strict TV API requests identically to `tv_request` in `src/main.rs`.
 * Search, comments, featured-tabs index, and public-list browse require
 * `moderation_profile=strict`; feed and item routes also accept `view=tv`.
 *
 * Matches against both full-decoded segments (catching `/api/v2%2Fvideos`) and
 * raw-slash-split per-segment-decoded segments (catching `%2F` inside a list
 * d-tag like `/api/v2/lists/<pubkey>/my%2Flist/items`).
 */
export function tvRequest(path: string, url: URL): TvRequest | null {
  const fullSegments = normalizedApiPathSegments(path);
  const rawSegments = rawSplitApiPathSegments(path);
  const supportsTvView =
    matchStrictTvSupportsView(fullSegments) ?? matchStrictTvSupportsView(rawSegments);

  if (supportsTvView === null) {
    return null;
  }

  let view = false;
  for (const [key, value] of url.searchParams.entries()) {
    if (key === "moderation_profile" && value === "strict") {
      return "Strict";
    }
    if (key === "view" && value === "tv") {
      view = true;
    }
  }

  if (!view) {
    return null;
  }
  return supportsTvView ? "Strict" : "UnsupportedView";
}

export function isStrictTvApiRequest(
  host: string,
  method: string,
  backend: BackendName | string,
): boolean {
  const classified = classifyHost(host);
  return (
    backend === FUNNELCAKE_API_BACKEND &&
    classified.kind === "System" &&
    classified.subdomain === "api" &&
    method.toUpperCase() === "GET"
  );
}

function isUserRecommendationsSegments(segments: string[]): boolean {
  return (
    segments.length === 4 &&
    segments[0] === "api" &&
    segments[1] === "users" &&
    segments[3] === "recommendations"
  );
}

export function strictTvUsesCallerContext(
  path: string,
  url: URL,
  hasPubkey: boolean,
): boolean {
  if (hasPubkey) {
    return true;
  }

  const isUserRecommendations =
    isUserRecommendationsSegments(normalizedApiPathSegments(path)) ||
    isUserRecommendationsSegments(rawSplitApiPathSegments(path));
  if (!isUserRecommendations) {
    return false;
  }

  for (const name of url.searchParams.keys()) {
    if (
      name === "followed_hashtags" ||
      name === "preferred_languages" ||
      name === "seed"
    ) {
      return true;
    }
  }
  return false;
}

export function strictTvResponseAllowed(
  status: number,
  policy: string | null,
): boolean {
  const isClientError = status >= 400 && status <= 499;
  const isServerError = status >= 500 && status <= 599;
  const isSuccess = status >= 200 && status <= 299;
  return isClientError || isServerError || (isSuccess && policy === STRICT_TV_POLICY);
}

export function strictTvCacheLeaseSecs(
  status: number,
  surrogateControl: string | null,
): number | null {
  if (status < 200 || status > 299 || surrogateControl === null) {
    return null;
  }

  let minMaxAge: bigint | null = null;
  for (const rawDirective of surrogateControl.split(",")) {
    const directive = rawDirective.trim();
    if (!directive) continue;
    const eqIdx = directive.indexOf("=");
    if (eqIdx === -1) {
      const token = directive.toLowerCase();
      if (token === "no-store" || token === "private" || token === "no-cache") {
        return null;
      }
      continue;
    }
    const name = directive.slice(0, eqIdx).trim().toLowerCase();
    if (name === "no-store" || name === "private" || name === "no-cache") {
      return null;
    }
    if (name !== "max-age") {
      continue;
    }
    const value = directive.slice(eqIdx + 1).trim();
    if (!/^\d+$/.test(value)) {
      continue;
    }
    const parsed = BigInt(value);
    if (minMaxAge === null || parsed < minMaxAge) {
      minMaxAge = parsed;
    }
  }

  if (minMaxAge === null || minMaxAge === 0n) {
    return null;
  }
  const cap = BigInt(STRICT_TV_MAX_AGE_SECS);
  return Number(minMaxAge < cap ? minMaxAge : cap);
}

/**
 * Parses an HTTP `Age` header for strict TV lease accounting.
 * Returns `0` when absent, a non-negative integer capped at `Number.MAX_SAFE_INTEGER`
 * when valid, or `null` when malformed (e.g. empty, list, or non-digit) so callers
 * fail closed per RFC 9111 §1.2.2.
 */
export function parseStrictTvAgeSecs(ageHeader: string | null): number | null {
  if (ageHeader === null) {
    return 0;
  }
  const trimmed = ageHeader.trim();
  if (!/^\d+$/.test(trimmed)) {
    return null;
  }
  const parsed = BigInt(trimmed);
  const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
  return Number(parsed > maxSafe ? maxSafe : parsed);
}

export function strictTvLeaseExpired(
  leaseSecs: number | null,
  ageSecs: number | null,
): boolean {
  if (leaseSecs === null) {
    return false;
  }
  if (ageSecs === null) {
    return true;
  }
  return ageSecs >= leaseSecs;
}

/**
 * Mirrors `strict_tv_pass_age_allowed` in `src/main.rs`: caller-private strict
 * reads only allow an absent or all-zero single delta-seconds `Age` value.
 */
export function strictTvPassAgeAllowed(ageHeader: string | null): boolean {
  if (ageHeader === null) {
    return true;
  }
  return /^0+$/.test(ageHeader);
}

/**
 * Validates Funnelcake's space-delimited `Surrogate-Key` header and returns
 * Bunny's `CDN-Tag` value (`"strict-tv"`).
 *
 * Bunny truncates `CDN-Tag` headers past 1024 bytes, whereas multi-video
 * Funnelcake feeds routinely emit >2 KB of per-event/per-author surrogate keys.
 * Emitting only the 9-byte `strict-tv` tag avoids silent truncation while
 * keeping exact `{"CacheTag": "strict-tv"}` purges reliable regardless of page
 * size. Fails closed (returns `null`) if the origin header is absent, omits
 * `strict-tv`, or contains non-visible-ASCII bytes or commas. Fetch joins
 * repeated header values with a comma, so the combined value is ambiguous.
 */
export function strictTvCdnTag(surrogateKeyHeader: string | null): string | null {
  if (surrogateKeyHeader === null) {
    return null;
  }
  for (let i = 0; i < surrogateKeyHeader.length; i++) {
    const code = surrogateKeyHeader.charCodeAt(i);
    if (code < 0x20 || code > 0x7e || code === 0x2c) {
      return null;
    }
  }

  for (const token of surrogateKeyHeader.split(" ")) {
    if (token === STRICT_TV_SURROGATE_KEY) {
      return STRICT_TV_SURROGATE_KEY;
    }
  }
  return null;
}

export function strictTvErrorResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "private, no-store",
      "cdn-cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}

export function strictTvBadRequestResponse(): Response {
  return strictTvErrorResponse(
    400,
    '{"error":"Use moderation_profile=strict on this endpoint"}',
  );
}

export function strictTvUnavailableResponse(): Response {
  return strictTvErrorResponse(
    503,
    '{"error":"Strict content check unavailable"}',
  );
}
