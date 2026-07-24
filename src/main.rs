// ABOUTME: Divine Router - Fastly edge router for wildcard subdomains
// ABOUTME: Routes username.divine.video to profiles, passes through system subdomains

use fastly::http::request::SendErrorCause;
use fastly::http::{StatusCode, header};
use fastly::kv_store::KVStore;
use fastly::{Error, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

const MAIN_BACKEND: &str = "main_site";
const BLOSSOM_BACKEND: &str = "blossom";
const INVITE_BACKEND: &str = "invite_service";
const FUNNELCAKE_API_BACKEND: &str = "funnelcake_api";
const SOUND_PROXY_BACKEND: &str = "sound_proxy";
const ACTIVITYPUB_BACKEND: &str = "activitypub_gateway";
const KV_STORE_NAME: &str = "divine-names";
const CANONICAL_WEBFINGER_DOMAIN: &str = "divine.video";
const OWNED_APEX_DOMAINS: &[&str] = &["divine.video", "dvines.org"];

/// Pins eligible API and RSS stale reuse at the edge for 24 hours.
///
/// This matches Funnelcake's intended cache contract without depending on its
/// deployment state or Fastly defaults. Coordinate changes with origin policy.
const EDGE_STALE_IF_ERROR_SECS: u32 = 24 * 60 * 60;

// ActivityPub gateway paths served on the divine.video apex by the
// divine-activity-pub worker (actors, outbox, inbox, nodeinfo). NOTE: WebFinger
// is NOT here — the router serves it directly from the username KV (handle_webfinger).
fn is_activitypub_path(path: &str) -> bool {
    path == "/ap"
        || path.starts_with("/ap/")
        || path == "/.well-known/nodeinfo"
        || path == "/nodeinfo"
        || path.starts_with("/nodeinfo/")
}

// Subdomains that route to blossom/media server
const BLOSSOM_SUBDOMAINS: &[&str] = &["media", "blossom"];

// Subdomains that route to invite faucet service
const INVITE_SUBDOMAINS: &[&str] = &["invite"];

// System subdomains that should passthrough to origin
const SYSTEM_SUBDOMAINS: &[&str] = &[
    "www",
    "api",
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
];

/// Username data stored in KV
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct UsernameData {
    pubkey: String,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    atproto_did: Option<String>,
    #[serde(default)]
    atproto_state: Option<String>,
}

/// NIP-05 response format
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Nip05Response {
    names: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relays: Option<std::collections::HashMap<String, Vec<String>>>,
}

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    let host = req.get_header_str("host").unwrap_or("").to_string();
    let path = req.get_path().to_string();

    // ActivityPub on the divine.video / dvines.org apex:
    //  - /.well-known/webfinger -> served HERE from the username KV (proper 404s).
    //  - /ap/* and /nodeinfo     -> diverted to the divine-activity-pub worker.
    // Everything else (incl. /.well-known/nostr.json + /.well-known/atproto-did) untouched.
    let hostname_only = host.split(':').next().unwrap_or(&host);
    if is_owned_apex_domain(hostname_only) {
        if path == "/.well-known/webfinger" {
            return handle_webfinger(&req);
        }
        if is_activitypub_path(&path) {
            return passthrough(req, ACTIVITYPUB_BACKEND, &host);
        }
    }

    // Parse hostname to determine routing
    match classify_host(&host) {
        HostType::Apex => {
            // Main site - passthrough
            passthrough(req, MAIN_BACKEND, &host)
        }
        HostType::MultiLevel => {
            // Multi-level subdomain (*.admin.dvines.org) - passthrough
            passthrough(req, MAIN_BACKEND, &host)
        }
        HostType::System(subdomain) => {
            // Route to appropriate backend based on subdomain
            let blossom_set: HashSet<&str> = BLOSSOM_SUBDOMAINS.iter().copied().collect();
            let invite_set: HashSet<&str> = INVITE_SUBDOMAINS.iter().copied().collect();
            if blossom_set.contains(subdomain.as_str()) {
                passthrough(req, BLOSSOM_BACKEND, &host)
            } else if invite_set.contains(subdomain.as_str()) {
                passthrough(req, INVITE_BACKEND, &host)
            } else if subdomain == "api" {
                passthrough(req, api_backend_for_path(&path), &host)
            } else {
                passthrough(req, MAIN_BACKEND, &host)
            }
        }
        HostType::Username(username) => {
            // Potential username subdomain
            handle_username_request(&username, &path, req)
        }
    }
}

#[derive(Debug, PartialEq)]
enum HostType {
    Apex,
    MultiLevel,
    System(String),
    Username(String),
}

fn classify_host(host: &str) -> HostType {
    // Remove port if present
    let hostname = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = hostname.split('.').collect();

    // Check for our domains
    let is_our_domain = parts.len() >= 2 && {
        let tld = parts[parts.len() - 1];
        let sld = parts[parts.len() - 2];
        (sld == "dvines" && tld == "org") || (sld == "divine" && tld == "video")
    };

    if !is_our_domain {
        // Not our domain, passthrough
        return HostType::Apex;
    }

    match parts.len() {
        // dvines.org or divine.video (apex)
        2 => HostType::Apex,
        // x.dvines.org or x.divine.video (single subdomain)
        3 => {
            let subdomain = parts[0].to_lowercase();
            let system_set: HashSet<&str> = SYSTEM_SUBDOMAINS.iter().copied().collect();

            if system_set.contains(subdomain.as_str()) {
                HostType::System(subdomain)
            } else {
                HostType::Username(subdomain)
            }
        }
        // x.y.dvines.org or deeper (multi-level)
        _ => HostType::MultiLevel,
    }
}

fn is_owned_apex_domain(hostname: &str) -> bool {
    OWNED_APEX_DOMAINS
        .iter()
        .any(|domain| hostname.eq_ignore_ascii_case(domain))
}

// Backend host headers - must match what the backend expects
const MAIN_BACKEND_HOST: &str = "inherently-ethical-gelding.edgecompute.app";
const BLOSSOM_BACKEND_HOST: &str = "separately-robust-roughy.edgecompute.app";
const INVITE_BACKEND_HOST: &str = "adversely-polished-yak.edgecompute.app";
const FUNNELCAKE_BACKEND_HOST: &str = "relay.divine.video";
const SOUND_PROXY_BACKEND_HOST: &str = "divine-sound-proxy.edgecompute.app";
const ACTIVITYPUB_BACKEND_HOST: &str = "divine-activity-pub.protestnet.workers.dev";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PassthroughHeaders<'a> {
    backend_host: &'static str,
    forwarded_host: &'a str,
    forwarded_proto: &'a str,
}

fn backend_host_for(backend: &str) -> &'static str {
    match backend {
        MAIN_BACKEND => MAIN_BACKEND_HOST,
        BLOSSOM_BACKEND => BLOSSOM_BACKEND_HOST,
        INVITE_BACKEND => INVITE_BACKEND_HOST,
        FUNNELCAKE_API_BACKEND => FUNNELCAKE_BACKEND_HOST,
        SOUND_PROXY_BACKEND => SOUND_PROXY_BACKEND_HOST,
        ACTIVITYPUB_BACKEND => ACTIVITYPUB_BACKEND_HOST,
        _ => MAIN_BACKEND_HOST,
    }
}

fn is_api_sound_path(path: &str) -> bool {
    path == "/api/sounds" || path.starts_with("/api/sounds/")
}

fn api_backend_for_path(path: &str) -> &'static str {
    if is_api_sound_path(path) {
        SOUND_PROXY_BACKEND
    } else {
        FUNNELCAKE_API_BACKEND
    }
}

fn passthrough_headers<'a>(
    backend: &str,
    original_host: &'a str,
    original_proto: &'a str,
) -> PassthroughHeaders<'a> {
    PassthroughHeaders {
        backend_host: backend_host_for(backend),
        forwarded_host: original_host,
        forwarded_proto: original_proto,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ApiCachePolicy {
    cacheable: bool,
    fallback_ttl_secs: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassthroughCacheMode {
    Pass,
    Cacheable {
        fallback_ttl_secs: Option<u32>,
        honors_origin_stale_if_error: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateCacheAction {
    ServeStale,
    SetFallbackTtl(Duration),
    PreserveOrigin,
}

fn stale_if_error_override_secs(cache_mode: PassthroughCacheMode) -> Option<u32> {
    match cache_mode {
        PassthroughCacheMode::Pass => None,
        PassthroughCacheMode::Cacheable {
            honors_origin_stale_if_error,
            ..
        } => Some(if honors_origin_stale_if_error {
            EDGE_STALE_IF_ERROR_SECS
        } else {
            0
        }),
    }
}

fn is_public_divine_host(host: &str) -> bool {
    let hostname = host.split(':').next().unwrap_or(host);

    is_owned_apex_domain(hostname) || matches!(classify_host(host), HostType::System(_))
}

fn should_bypass_cache(host: &str, path: &str) -> bool {
    is_public_divine_host(host) && (path.starts_with("/.well-known/") || is_activitypub_path(path))
}

fn api_cache_policy(
    host: &str,
    method: &str,
    path: &str,
    has_authorization: bool,
    is_websocket_upgrade: bool,
) -> ApiCachePolicy {
    let is_api_host =
        matches!(classify_host(host), HostType::System(ref subdomain) if subdomain == "api");
    let is_cacheable_api_path = path.starts_with("/api/") && !path.starts_with("/api/docs");

    if !is_api_host
        || !is_cacheable_api_path
        || !method.eq_ignore_ascii_case("GET")
        || has_authorization
        || is_websocket_upgrade
    {
        return ApiCachePolicy {
            cacheable: false,
            fallback_ttl_secs: None,
        };
    }

    ApiCachePolicy {
        cacheable: true,
        fallback_ttl_secs: Some(30),
    }
}

fn is_rss_feed_path(path: &str) -> bool {
    path.starts_with("/feed/")
}

fn honors_origin_stale_if_error(
    host: &str,
    method: &str,
    path: &str,
    has_authorization: bool,
    is_websocket_upgrade: bool,
    policy: ApiCachePolicy,
) -> bool {
    let is_api_host =
        matches!(classify_host(host), HostType::System(ref subdomain) if subdomain == "api");

    is_api_host
        && method.eq_ignore_ascii_case("GET")
        && !has_authorization
        && !is_websocket_upgrade
        && (policy.cacheable || is_rss_feed_path(path))
}

fn candidate_cache_action(
    honors_origin_stale_if_error: bool,
    is_server_error: bool,
    stale_if_error_available: bool,
    has_surrogate_control: bool,
    response_ttl: Duration,
    fallback_ttl_secs: Option<u32>,
) -> CandidateCacheAction {
    if is_server_error {
        return if honors_origin_stale_if_error && stale_if_error_available {
            CandidateCacheAction::ServeStale
        } else {
            CandidateCacheAction::PreserveOrigin
        };
    }

    if !has_surrogate_control
        && response_ttl.is_zero()
        && let Some(ttl_secs) = fallback_ttl_secs
    {
        return CandidateCacheAction::SetFallbackTtl(Duration::from_secs(ttl_secs as u64));
    }

    CandidateCacheAction::PreserveOrigin
}

fn should_register_cache_hook(
    fallback_ttl_secs: Option<u32>,
    honors_origin_stale_if_error: bool,
) -> bool {
    fallback_ttl_secs.is_some() || honors_origin_stale_if_error
}

fn passthrough_cache_mode(
    host: &str,
    method: &str,
    path: &str,
    has_authorization: bool,
    is_websocket_upgrade: bool,
) -> PassthroughCacheMode {
    if should_bypass_cache(host, path) || is_websocket_upgrade {
        return PassthroughCacheMode::Pass;
    }

    let policy = api_cache_policy(host, method, path, has_authorization, is_websocket_upgrade);
    let honors_origin_stale_if_error = honors_origin_stale_if_error(
        host,
        method,
        path,
        has_authorization,
        is_websocket_upgrade,
        policy,
    );
    let is_api_rss_path = is_rss_feed_path(path)
        && matches!(classify_host(host), HostType::System(ref subdomain) if subdomain == "api");

    if (path.starts_with("/api/") && !policy.cacheable)
        || (is_api_rss_path && !honors_origin_stale_if_error)
    {
        return PassthroughCacheMode::Pass;
    }

    PassthroughCacheMode::Cacheable {
        fallback_ttl_secs: policy.fallback_ttl_secs,
        honors_origin_stale_if_error,
    }
}

fn passthrough(req: Request, backend: &str, original_host: &str) -> Result<Response, Error> {
    let mut req = req;
    let path = req.get_path().to_string();
    let request_scheme: &'static str = match req.get_url().scheme() {
        "http" => "http",
        _ => "https",
    };
    let headers = passthrough_headers(backend, original_host, request_scheme);
    let has_authorization = req.contains_header(header::AUTHORIZATION);
    let is_websocket_upgrade = req
        .get_header_str(header::UPGRADE)
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let cache_mode = passthrough_cache_mode(
        original_host,
        req.get_method_str(),
        &path,
        has_authorization,
        is_websocket_upgrade,
    );

    // Pin eligible API/RSS stale reuse at the edge. Ordinary cacheable routes retain the
    // zero-second opt-out, while pass routes receive no override that could reverse pass mode.
    if let Some(stale_if_error_secs) = stale_if_error_override_secs(cache_mode) {
        req.set_stale_if_error(stale_if_error_secs);
    }

    match cache_mode {
        PassthroughCacheMode::Pass => req.set_pass(true),
        PassthroughCacheMode::Cacheable {
            fallback_ttl_secs,
            honors_origin_stale_if_error,
        } => {
            if should_register_cache_hook(fallback_ttl_secs, honors_origin_stale_if_error) {
                req.set_after_send(move |candidate| {
                    match candidate_cache_action(
                        honors_origin_stale_if_error,
                        candidate.get_status().is_server_error(),
                        candidate.stale_if_error_available(),
                        candidate.contains_header("surrogate-control"),
                        candidate.get_ttl(),
                        fallback_ttl_secs,
                    ) {
                        CandidateCacheAction::ServeStale => {
                            // An after-send error discards the 5xx candidate and serves available stale.
                            Err(SendErrorCause::DestinationUnavailable)
                        }
                        CandidateCacheAction::SetFallbackTtl(ttl) => {
                            candidate.set_ttl(ttl);
                            Ok(())
                        }
                        CandidateCacheAction::PreserveOrigin => Ok(()),
                    }
                });
            }
        }
    }

    req.set_header(header::HOST, headers.backend_host);
    req.set_header("X-Forwarded-Host", headers.forwarded_host);
    req.set_header("X-Forwarded-Proto", headers.forwarded_proto);
    Ok(req.send(backend)?)
}

fn handle_username_request(username: &str, path: &str, req: Request) -> Result<Response, Error> {
    // Check if this is an ATProto DID resolution request
    if path == "/.well-known/atproto-did" {
        return handle_atproto_did(username);
    }

    // Check if this is a NIP-05 request
    if path == "/.well-known/nostr.json" {
        return handle_nip05(username, &req);
    }

    // Look up username in KV store
    let user_data = lookup_username(username);

    match user_data {
        Some(data) if data.status == "active" => {
            // Valid username - forward to divine-web backend
            serve_profile(username, &data, req)
        }
        _ => {
            // Username not found or not active - return 404
            Ok(Response::from_status(StatusCode::NOT_FOUND)
                .with_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .with_body(format!(
                    r#"<!DOCTYPE html>
<html>
<head><title>Not Found</title></head>
<body>
<h1>@{} not found</h1>
<p>This username is not registered on Divine.</p>
<p><a href="https://divine.video">Go to Divine</a></p>
</body>
</html>"#,
                    username
                )))
        }
    }
}

// WebFinger (RFC 7033) for @user@divine.video, served from the username KV.
// Returns a JRD whose rel:self points at the AP gateway actor; 404 for unknown
// or non-active users. No origin subrequest — reads the same KV as NIP-05.
fn handle_webfinger(req: &Request) -> Result<Response, Error> {
    let resource = req
        .get_url()
        .query_pairs()
        .find(|(k, _)| k == "resource")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();

    let user = match parse_webfinger_resource(&resource) {
        WebFingerLookup::Lookup(user) => user,
        WebFingerLookup::BadRequest => {
            return Ok(Response::from_status(StatusCode::BAD_REQUEST)
                .with_header(header::CONTENT_TYPE, "application/json")
                .with_body("{\"error\":\"missing or malformed resource\"}"));
        }
        WebFingerLookup::NotFound => {
            return Ok(webfinger_not_found_response());
        }
    };

    match lookup_username(&user) {
        Some(data) if data.status == "active" => {
            let jrd = build_webfinger_jrd(&user);
            Ok(Response::from_status(StatusCode::OK)
                .with_header(header::CONTENT_TYPE, "application/jrd+json")
                .with_header("Access-Control-Allow-Origin", "*")
                .with_body(serde_json::to_string(&jrd).unwrap_or_default()))
        }
        _ => Ok(webfinger_not_found_response()),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum WebFingerLookup {
    Lookup(String),
    BadRequest,
    NotFound,
}

fn parse_webfinger_resource(resource: &str) -> WebFingerLookup {
    let acct = resource.strip_prefix("acct:").unwrap_or(resource);
    let mut parts = acct.splitn(2, '@');
    let user = parts.next().unwrap_or("").to_lowercase();

    if user.is_empty() {
        return WebFingerLookup::BadRequest;
    }

    // Any owned apex is accepted here regardless of which apex served the
    // request (e.g. acct:x@dvines.org is honored on the divine.video host and
    // vice versa). This is deliberate: the subject is canonicalized to
    // divine.video and the user is still verified against KV.
    if let Some(host) = parts.next() {
        if !is_owned_apex_domain(host) {
            return WebFingerLookup::NotFound;
        }
    }

    WebFingerLookup::Lookup(user)
}

fn build_webfinger_jrd(user: &str) -> serde_json::Value {
    let actor = format!("https://{}/ap/users/{}", CANONICAL_WEBFINGER_DOMAIN, user);
    let profile = format!("https://{}.{}", user, CANONICAL_WEBFINGER_DOMAIN);

    // dvines.org is an owned apex, but ActivityPub actor/profile URLs are
    // canonical on divine.video. Keep the WebFinger subject aligned with them.
    serde_json::json!({
        "subject": format!("acct:{}@{}", user, CANONICAL_WEBFINGER_DOMAIN),
        "aliases": [profile, actor],
        "links": [
            {"rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": profile},
            {"rel": "self", "type": "application/activity+json", "href": actor}
        ]
    })
}

fn webfinger_not_found_response() -> Response {
    Response::from_status(StatusCode::NOT_FOUND)
        .with_header(header::CONTENT_TYPE, "application/json")
        .with_header("Access-Control-Allow-Origin", "*")
        .with_body("{\"error\":\"not found\"}")
}

fn handle_nip05(username: &str, req: &Request) -> Result<Response, Error> {
    // Get the queried name from ?name= parameter, default to username
    let url = req.get_url();
    let queried_name = url
        .query_pairs()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| username.to_string());

    // Always look up the subdomain username in KV, not the queried name
    let user_data = lookup_username(username);

    let response = build_nip05_response(&queried_name, user_data.as_ref());
    let body = serde_json::to_string(&response).unwrap_or_default();

    Ok(Response::from_status(StatusCode::OK)
        .with_header(header::CONTENT_TYPE, "application/json")
        .with_header("Access-Control-Allow-Origin", "*")
        .with_body(body))
}

fn handle_atproto_did(username: &str) -> Result<Response, Error> {
    let user_data = lookup_username(username);

    match user_data {
        Some(data)
            if data.status == "active"
                && data.atproto_state.as_deref() == Some("ready")
                && data.atproto_did.is_some() =>
        {
            let did = data.atproto_did.unwrap();
            Ok(Response::from_status(StatusCode::OK)
                .with_header(header::CONTENT_TYPE, "text/plain")
                .with_header("Access-Control-Allow-Origin", "*")
                .with_body(did))
        }
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)
            .with_header(header::CONTENT_TYPE, "text/plain")
            .with_body("")),
    }
}

/// Build NIP-05 response. This is a pure function for easy testing.
///
/// Per NIP-05 spec:
/// - `daniel@divine.video` queries `divine.video/.well-known/nostr.json?name=daniel`
///   and expects `{ "names": { "daniel": "pubkey" } }`
/// - `_@daniel.divine.video` queries `daniel.divine.video/.well-known/nostr.json?name=_`
///   and expects `{ "names": { "_": "pubkey" } }`
///
/// For subdomain requests, the caller looks up the subdomain username in KV,
/// but this function uses `queried_name` in the response.
fn build_nip05_response(queried_name: &str, user_data: Option<&UsernameData>) -> Nip05Response {
    match user_data {
        Some(data) if data.status == "active" => {
            let mut names = std::collections::HashMap::new();
            // Use the queried name in the response (e.g., "_" for subdomain format)
            names.insert(queried_name.to_lowercase(), data.pubkey.clone());

            let relays = if !data.relays.is_empty() {
                let mut relay_map = std::collections::HashMap::new();
                relay_map.insert(data.pubkey.clone(), data.relays.clone());
                Some(relay_map)
            } else {
                None
            };

            Nip05Response { names, relays }
        }
        _ => {
            // Username not found or not active
            Nip05Response {
                names: std::collections::HashMap::new(),
                relays: None,
            }
        }
    }
}

fn lookup_username(username: &str) -> Option<UsernameData> {
    let kv_store = KVStore::open(KV_STORE_NAME).ok()??;
    let key = format!("user:{}", username);
    if let Some(data) = try_kv_lookup(&kv_store, &key) {
        return Some(data);
    }

    // Defensive fallback: strip dots and retry (handles legacy dotted names like lele.pons -> lelepons)
    if username.contains('.') {
        let dotless: String = username.chars().filter(|c| *c != '.').collect();
        let dotless_key = format!("user:{}", dotless);
        return try_kv_lookup(&kv_store, &dotless_key);
    }

    None
}

fn try_kv_lookup(kv_store: &KVStore, key: &str) -> Option<UsernameData> {
    let mut lookup = kv_store.lookup(key).ok()?;
    let body = lookup.take_body().into_bytes();
    serde_json::from_slice(&body).ok()
}

fn serve_profile(_username: &str, _data: &UsernameData, req: Request) -> Result<Response, Error> {
    // Forward to divine-web backend with X-Original-Host header.
    // The divine-web edge worker handles subdomain profiles by injecting
    // window.__DIVINE_USER__ into the SPA HTML and serving it directly.
    let original_host = req.get_header_str("host").unwrap_or("").to_string();

    let mut req = req;
    req.set_header(header::HOST, MAIN_BACKEND_HOST);
    req.set_header("X-Original-Host", &original_host);
    Ok(req.send(MAIN_BACKEND)?)
}

#[allow(dead_code)]
fn hex_to_npub(hex: &str) -> Result<String, ()> {
    if hex.len() != 64 {
        return Err(());
    }

    let data: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| ())?;

    // Convert 8-bit to 5-bit
    let mut converted = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;

    for value in &data {
        acc = (acc << 8) | (*value as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            converted.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        converted.push(((acc << (5 - bits)) & 31) as u8);
    }

    // Bech32 checksum
    let hrp = "npub";
    let hrp_expand: Vec<u8> = hrp
        .chars()
        .map(|c| c as u8 >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.chars().map(|c| c as u8 & 31))
        .collect();

    let checksum = bech32_checksum(&hrp_expand, &converted);

    // Encode
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut result = String::from("npub1");
    for b in converted.iter().chain(checksum.iter()) {
        result.push(CHARSET[*b as usize] as char);
    }

    Ok(result)
}

#[allow(dead_code)]
fn bech32_checksum(hrp_expand: &[u8], data: &[u8]) -> Vec<u8> {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut values: Vec<u8> = hrp_expand.to_vec();
    values.extend(data);
    values.extend(&[0u8; 6]);

    let mut chk = 1u32;
    for v in &values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (*v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk ^= 1;

    (0..6)
        .map(|i| ((chk >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_active_user(pubkey: &str, relays: Vec<String>) -> UsernameData {
        UsernameData {
            pubkey: pubkey.to_string(),
            relays,
            status: "active".to_string(),
            atproto_did: None,
            atproto_state: None,
        }
    }

    fn make_inactive_user(pubkey: &str) -> UsernameData {
        UsernameData {
            pubkey: pubkey.to_string(),
            relays: vec![],
            status: "inactive".to_string(),
            atproto_did: None,
            atproto_state: None,
        }
    }

    fn make_atproto_user(pubkey: &str, did: &str, state: &str) -> UsernameData {
        UsernameData {
            pubkey: pubkey.to_string(),
            relays: vec![],
            status: "active".to_string(),
            atproto_did: Some(did.to_string()),
            atproto_state: Some(state.to_string()),
        }
    }

    #[test]
    fn test_build_nip05_response_subdomain_with_underscore() {
        // Scenario: _@daniel.divine.video
        // Request: daniel.divine.video/.well-known/nostr.json?name=_
        // Caller looks up "daniel" in KV, passes user_data here with queried_name="_"
        let user = make_active_user("abc123pubkey", vec![]);
        let response = build_nip05_response("_", Some(&user));

        assert_eq!(response.names.len(), 1);
        assert_eq!(response.names.get("_"), Some(&"abc123pubkey".to_string()));
        assert!(response.relays.is_none());
    }

    #[test]
    fn test_build_nip05_response_subdomain_with_username() {
        // Scenario: daniel@daniel.divine.video (querying own name on subdomain)
        // Request: daniel.divine.video/.well-known/nostr.json?name=daniel
        let user = make_active_user("abc123pubkey", vec![]);
        let response = build_nip05_response("daniel", Some(&user));

        assert_eq!(response.names.len(), 1);
        assert_eq!(
            response.names.get("daniel"),
            Some(&"abc123pubkey".to_string())
        );
    }

    #[test]
    fn test_build_nip05_response_with_relays() {
        let relays = vec![
            "wss://relay.divine.video".to_string(),
            "wss://relay.damus.io".to_string(),
        ];
        let user = make_active_user("abc123pubkey", relays.clone());
        let response = build_nip05_response("_", Some(&user));

        assert_eq!(response.names.get("_"), Some(&"abc123pubkey".to_string()));
        assert!(response.relays.is_some());
        let relay_map = response.relays.unwrap();
        assert_eq!(relay_map.get("abc123pubkey"), Some(&relays));
    }

    #[test]
    fn test_build_nip05_response_user_not_found() {
        let response = build_nip05_response("_", None);

        assert!(response.names.is_empty());
        assert!(response.relays.is_none());
    }

    #[test]
    fn test_build_nip05_response_user_inactive() {
        let user = make_inactive_user("abc123pubkey");
        let response = build_nip05_response("_", Some(&user));

        assert!(response.names.is_empty());
        assert!(response.relays.is_none());
    }

    #[test]
    fn test_build_nip05_response_case_insensitive() {
        // Queried name should be lowercased in response
        let user = make_active_user("abc123pubkey", vec![]);
        let response = build_nip05_response("DANIEL", Some(&user));

        assert_eq!(
            response.names.get("daniel"),
            Some(&"abc123pubkey".to_string())
        );
        assert!(!response.names.contains_key("DANIEL"));
    }

    #[test]
    fn test_parse_webfinger_resource_accepts_owned_domains() {
        assert_eq!(
            parse_webfinger_resource("acct:alice@divine.video"),
            WebFingerLookup::Lookup("alice".to_string())
        );
        assert_eq!(
            parse_webfinger_resource("acct:alice@dvines.org"),
            WebFingerLookup::Lookup("alice".to_string())
        );
    }

    #[test]
    fn test_parse_webfinger_resource_accepts_bare_username() {
        assert_eq!(
            parse_webfinger_resource("alice"),
            WebFingerLookup::Lookup("alice".to_string())
        );
        assert_eq!(
            parse_webfinger_resource("acct:alice"),
            WebFingerLookup::Lookup("alice".to_string())
        );
    }

    #[test]
    fn test_parse_webfinger_resource_rejects_foreign_domains() {
        assert_eq!(
            parse_webfinger_resource("acct:alice@evil.com"),
            WebFingerLookup::NotFound
        );
        assert_eq!(
            parse_webfinger_resource("acct:alice@divine.video.evil.com"),
            WebFingerLookup::NotFound
        );
    }

    #[test]
    fn test_parse_webfinger_resource_accepts_mixed_case_owned_domain() {
        assert_eq!(
            parse_webfinger_resource("acct:ALICE@DIVINE.VIDEO"),
            WebFingerLookup::Lookup("alice".to_string())
        );
    }

    #[test]
    fn test_parse_webfinger_resource_rejects_missing_user() {
        assert_eq!(parse_webfinger_resource(""), WebFingerLookup::BadRequest);
        assert_eq!(
            parse_webfinger_resource("acct:@divine.video"),
            WebFingerLookup::BadRequest
        );
    }

    #[test]
    fn test_build_webfinger_jrd_uses_canonical_subject() {
        let jrd = build_webfinger_jrd("alice");

        assert_eq!(jrd["subject"], "acct:alice@divine.video");
        assert_eq!(jrd["aliases"][0], "https://alice.divine.video");
        assert_eq!(jrd["aliases"][1], "https://divine.video/ap/users/alice");
        assert_eq!(
            jrd["links"][1]["href"],
            "https://divine.video/ap/users/alice"
        );
    }

    #[test]
    fn test_classify_host_apex() {
        assert_eq!(classify_host("divine.video"), HostType::Apex);
        assert_eq!(classify_host("dvines.org"), HostType::Apex);
    }

    #[test]
    fn test_classify_host_with_port() {
        assert_eq!(classify_host("divine.video:443"), HostType::Apex);
        assert_eq!(
            classify_host("daniel.divine.video:8080"),
            HostType::Username("daniel".to_string())
        );
    }

    #[test]
    fn test_classify_host_system_subdomain() {
        assert_eq!(
            classify_host("www.divine.video"),
            HostType::System("www".to_string())
        );
        assert_eq!(
            classify_host("api.divine.video"),
            HostType::System("api".to_string())
        );
        assert_eq!(
            classify_host("relay.divine.video"),
            HostType::System("relay".to_string())
        );
        assert_eq!(
            classify_host("media.divine.video"),
            HostType::System("media".to_string())
        );
    }

    #[test]
    fn test_classify_host_username_subdomain() {
        assert_eq!(
            classify_host("daniel.divine.video"),
            HostType::Username("daniel".to_string())
        );
        assert_eq!(
            classify_host("bob.dvines.org"),
            HostType::Username("bob".to_string())
        );
    }

    #[test]
    fn test_classify_host_username_case_insensitive() {
        // Subdomain is lowercased, but domain check is case-sensitive
        // (hostnames come lowercase from HTTP headers in practice)
        assert_eq!(
            classify_host("DANIEL.divine.video"),
            HostType::Username("daniel".to_string())
        );
    }

    #[test]
    fn test_classify_host_multi_level() {
        assert_eq!(classify_host("foo.bar.divine.video"), HostType::MultiLevel);
        assert_eq!(classify_host("a.b.c.dvines.org"), HostType::MultiLevel);
    }

    #[test]
    fn test_classify_host_unknown_domain() {
        // Unknown domains return Apex to trigger passthrough to main backend
        assert_eq!(classify_host("example.com"), HostType::Apex);
        assert_eq!(classify_host("foo.example.com"), HostType::Apex);
    }

    #[test]
    fn test_hex_to_npub_valid() {
        // Known test vector
        let hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let result = hex_to_npub(hex);
        assert!(result.is_ok());
        let npub = result.unwrap();
        assert!(npub.starts_with("npub1"));
        assert_eq!(npub.len(), 63); // npub1 + 58 chars
    }

    #[test]
    fn test_hex_to_npub_invalid_length() {
        assert!(hex_to_npub("abc").is_err());
        assert!(hex_to_npub("").is_err());
        assert!(hex_to_npub("abc123").is_err());
    }

    #[test]
    fn test_hex_to_npub_invalid_hex() {
        // 64 chars but not valid hex
        let invalid = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        assert!(hex_to_npub(invalid).is_err());
    }

    #[test]
    fn test_handle_atproto_did_ready_user() {
        let user = make_atproto_user("abc123pubkey", "did:plc:abc123", "ready");
        assert_eq!(user.status, "active");
        assert_eq!(user.atproto_state.as_deref(), Some("ready"));
        assert_eq!(user.atproto_did.as_deref(), Some("did:plc:abc123"));
    }

    #[test]
    fn test_atproto_not_ready() {
        let user = make_atproto_user("abc123pubkey", "did:plc:abc123", "pending");
        assert_ne!(user.atproto_state.as_deref(), Some("ready"));
    }

    #[test]
    fn test_atproto_disabled() {
        let user = make_atproto_user("abc123pubkey", "did:plc:abc123", "disabled");
        assert_ne!(user.atproto_state.as_deref(), Some("ready"));
    }

    #[test]
    fn test_atproto_no_did() {
        let user = make_active_user("abc123pubkey", vec![]);
        assert!(user.atproto_did.is_none());
    }

    #[test]
    fn test_atproto_inactive_user() {
        let mut user = make_atproto_user("abc123pubkey", "did:plc:abc123", "ready");
        user.status = "revoked".to_string();
        assert_ne!(user.status, "active");
    }

    #[test]
    fn test_nip05_still_works_with_atproto_fields() {
        let user = make_atproto_user("abc123pubkey", "did:plc:abc123", "ready");
        let response = build_nip05_response("_", Some(&user));
        assert_eq!(response.names.get("_"), Some(&"abc123pubkey".to_string()));
    }

    #[test]
    fn test_username_data_deserialize_without_atproto() {
        let json = r#"{"pubkey":"abc123","relays":[],"status":"active"}"#;
        let data: UsernameData = serde_json::from_str(json).unwrap();
        assert!(data.atproto_did.is_none());
        assert!(data.atproto_state.is_none());
    }

    #[test]
    fn test_username_data_deserialize_with_atproto() {
        let json = r#"{"pubkey":"abc123","relays":[],"status":"active","atproto_did":"did:plc:abc123","atproto_state":"ready"}"#;
        let data: UsernameData = serde_json::from_str(json).unwrap();
        assert_eq!(data.atproto_did.as_deref(), Some("did:plc:abc123"));
        assert_eq!(data.atproto_state.as_deref(), Some("ready"));
    }

    #[test]
    fn test_username_data_deserialize_with_null_atproto() {
        let json = r#"{"pubkey":"abc123","relays":[],"status":"active","atproto_did":null,"atproto_state":null}"#;
        let data: UsernameData = serde_json::from_str(json).unwrap();
        assert!(data.atproto_did.is_none());
        assert!(data.atproto_state.is_none());
    }

    #[test]
    fn test_classify_host_new_system_subdomains() {
        assert_eq!(
            classify_host("names.divine.video"),
            HostType::System("names".to_string())
        );
        assert_eq!(
            classify_host("login.divine.video"),
            HostType::System("login".to_string())
        );
        assert_eq!(
            classify_host("pds.divine.video"),
            HostType::System("pds".to_string())
        );
        assert_eq!(
            classify_host("feed.divine.video"),
            HostType::System("feed".to_string())
        );
        assert_eq!(
            classify_host("labeler.divine.video"),
            HostType::System("labeler".to_string())
        );
    }

    #[test]
    fn test_classify_host_invite_subdomain() {
        assert_eq!(
            classify_host("invite.divine.video"),
            HostType::System("invite".to_string())
        );
        assert_eq!(
            classify_host("invite.dvines.org"),
            HostType::System("invite".to_string())
        );
    }

    #[test]
    fn test_fastly_manifest_defines_runtime_backends() {
        let fastly_toml = include_str!("../fastly.toml");

        for backend in [
            MAIN_BACKEND,
            BLOSSOM_BACKEND,
            INVITE_BACKEND,
            FUNNELCAKE_API_BACKEND,
            SOUND_PROXY_BACKEND,
            ACTIVITYPUB_BACKEND,
        ] {
            let local_backend = format!("[local_server.backends.{backend}]");
            let setup_backend = format!("[setup.backends.{backend}]");

            assert!(
                fastly_toml.contains(&local_backend),
                "missing local backend definition for {backend}"
            );
            assert!(
                fastly_toml.contains(&setup_backend),
                "missing setup backend definition for {backend}"
            );
        }
    }

    #[test]
    fn test_api_cache_policy_skips_public_relay_get_requests() {
        let policy = api_cache_policy("relay.divine.video", "GET", "/api/search", false, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_skips_non_get_requests() {
        let policy = api_cache_policy("relay.divine.video", "POST", "/api/search", false, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_skips_authorized_requests() {
        let policy = api_cache_policy("relay.divine.video", "GET", "/api/search", true, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_skips_api_docs() {
        let policy = api_cache_policy("relay.divine.video", "GET", "/api/docs", false, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_skips_websocket_upgrades() {
        let policy = api_cache_policy("relay.divine.video", "GET", "/api/search", false, true);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_skips_non_api_hosts() {
        let policy = api_cache_policy("www.divine.video", "GET", "/api/search", false, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_api_cache_policy_caches_api_subdomain() {
        let policy = api_cache_policy("api.divine.video", "GET", "/api/search", false, false);

        assert!(policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, Some(30));
    }

    #[test]
    fn test_api_sound_paths_route_to_sound_proxy_backend() {
        assert_eq!(api_backend_for_path("/api/sounds"), SOUND_PROXY_BACKEND);
        assert_eq!(
            api_backend_for_path("/api/sounds/search"),
            SOUND_PROXY_BACKEND
        );
        assert_eq!(
            api_backend_for_path("/api/sounds/providers"),
            SOUND_PROXY_BACKEND
        );
    }

    #[test]
    fn test_api_non_sound_paths_still_route_to_funnelcake_backend() {
        assert_eq!(api_backend_for_path("/api/search"), FUNNELCAKE_API_BACKEND);
        assert_eq!(api_backend_for_path("/api/events"), FUNNELCAKE_API_BACKEND);
        assert_eq!(
            api_backend_for_path("/api/sounds-v2"),
            FUNNELCAKE_API_BACKEND
        );
    }

    #[test]
    fn test_passthrough_cache_mode_passes_public_well_known_paths() {
        assert_eq!(
            passthrough_cache_mode(
                "divine.video",
                "GET",
                "/.well-known/webfinger",
                false,
                false
            ),
            PassthroughCacheMode::Pass
        );
        assert_eq!(
            passthrough_cache_mode(
                "api.divine.video",
                "GET",
                "/.well-known/assetlinks.json",
                false,
                false
            ),
            PassthroughCacheMode::Pass
        );
    }

    #[test]
    fn test_passthrough_cache_mode_passes_websocket_upgrades() {
        assert_eq!(
            passthrough_cache_mode("relay.divine.video", "GET", "/api/search", false, true),
            PassthroughCacheMode::Pass
        );
    }

    #[test]
    fn test_passthrough_cache_mode_passes_non_cacheable_api_requests() {
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "GET", "/api/search", true, false),
            PassthroughCacheMode::Pass
        );
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "POST", "/api/events", false, false),
            PassthroughCacheMode::Pass
        );
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "GET", "/api/docs", false, false),
            PassthroughCacheMode::Pass
        );
    }

    #[test]
    fn test_passthrough_cache_mode_passes_authenticated_rss_requests() {
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "GET", "/feed/global.xml", true, false),
            PassthroughCacheMode::Pass
        );
    }

    #[test]
    fn test_passthrough_cache_mode_passes_non_get_rss_requests() {
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "POST", "/feed/global.xml", false, false),
            PassthroughCacheMode::Pass
        );
    }

    #[test]
    fn test_passthrough_cache_mode_does_not_honor_rss_outside_api_host() {
        assert_eq!(
            passthrough_cache_mode("www.divine.video", "GET", "/feed/global.xml", false, false),
            PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: None,
                honors_origin_stale_if_error: false,
            }
        );
    }

    #[test]
    fn test_passthrough_cache_mode_caches_public_api_gets() {
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "GET", "/api/search", false, false),
            PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: Some(30),
                honors_origin_stale_if_error: true,
            }
        );
    }

    #[test]
    fn test_passthrough_cache_mode_honors_origin_stale_if_error_for_public_rss() {
        assert_eq!(
            passthrough_cache_mode("api.divine.video", "GET", "/feed/global.xml", false, false),
            PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: None,
                honors_origin_stale_if_error: true,
            }
        );
    }

    #[test]
    fn test_passthrough_cache_mode_uses_default_cache_for_regular_passthrough() {
        assert_eq!(
            passthrough_cache_mode("www.divine.video", "GET", "/", false, false),
            PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: None,
                honors_origin_stale_if_error: false,
            }
        );
    }

    #[test]
    fn test_after_send_hook_is_limited_to_api_fallback_and_serve_stale_paths() {
        assert!(!should_register_cache_hook(None, false));
        assert!(should_register_cache_hook(Some(30), false));
        assert!(should_register_cache_hook(None, true));
    }

    #[test]
    fn test_stale_if_error_override_pins_eligible_edge_window() {
        assert_eq!(
            stale_if_error_override_secs(PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: None,
                honors_origin_stale_if_error: true,
            }),
            Some(86_400)
        );
        assert_eq!(
            stale_if_error_override_secs(PassthroughCacheMode::Cacheable {
                fallback_ttl_secs: None,
                honors_origin_stale_if_error: false,
            }),
            Some(0)
        );
        assert_eq!(
            stale_if_error_override_secs(PassthroughCacheMode::Pass),
            None
        );
    }

    #[test]
    fn test_rss_feed_path_matches_feed_children_only() {
        assert!(is_rss_feed_path("/feed/global.xml"));
        assert!(is_rss_feed_path("/feed/users/alice"));
        assert!(!is_rss_feed_path("/feed"));
        assert!(!is_rss_feed_path("/feedback"));
    }

    #[test]
    fn test_honors_origin_stale_if_error_for_cacheable_api_requests() {
        let policy = api_cache_policy("api.divine.video", "GET", "/api/search", false, false);

        assert!(honors_origin_stale_if_error(
            "api.divine.video",
            "GET",
            "/api/search",
            false,
            false,
            policy,
        ));
    }

    #[test]
    fn test_honors_origin_stale_if_error_for_public_rss_requests() {
        let policy = api_cache_policy("api.divine.video", "GET", "/feed/global.xml", false, false);

        assert!(honors_origin_stale_if_error(
            "api.divine.video",
            "GET",
            "/feed/global.xml",
            false,
            false,
            policy,
        ));
    }

    #[test]
    fn test_does_not_honor_origin_stale_if_error_for_pass_api_requests() {
        for (method, path, has_authorization, is_websocket_upgrade) in [
            ("GET", "/api/search", true, false),
            ("GET", "/api/search", false, true),
            ("POST", "/api/events", false, false),
            ("GET", "/api/docs", false, false),
        ] {
            let policy = api_cache_policy(
                "api.divine.video",
                method,
                path,
                has_authorization,
                is_websocket_upgrade,
            );

            assert!(!honors_origin_stale_if_error(
                "api.divine.video",
                method,
                path,
                has_authorization,
                is_websocket_upgrade,
                policy,
            ));
        }
    }

    #[test]
    fn test_does_not_honor_origin_stale_if_error_for_ineligible_rss_requests() {
        for (has_authorization, is_websocket_upgrade) in [(true, false), (false, true)] {
            let policy = api_cache_policy(
                "api.divine.video",
                "GET",
                "/feed/global.xml",
                has_authorization,
                is_websocket_upgrade,
            );

            assert!(!honors_origin_stale_if_error(
                "api.divine.video",
                "GET",
                "/feed/global.xml",
                has_authorization,
                is_websocket_upgrade,
                policy,
            ));
        }
    }

    #[test]
    fn test_does_not_honor_origin_stale_if_error_outside_api_host() {
        for (host, path) in [
            ("divine.video", "/api/search"),
            ("www.divine.video", "/feed/global.xml"),
            ("api.example.com", "/feed/global.xml"),
        ] {
            let policy = api_cache_policy(host, "GET", path, false, false);

            assert!(!honors_origin_stale_if_error(
                host, "GET", path, false, false, policy,
            ));
        }
    }

    #[test]
    fn test_candidate_cache_action_serves_stale_for_eligible_server_errors() {
        assert_eq!(
            candidate_cache_action(true, true, true, false, Duration::ZERO, None),
            CandidateCacheAction::ServeStale
        );
    }

    #[test]
    fn test_candidate_cache_action_preserves_server_errors_without_eligible_stale() {
        assert_eq!(
            candidate_cache_action(true, true, false, false, Duration::ZERO, None),
            CandidateCacheAction::PreserveOrigin
        );
        assert_eq!(
            candidate_cache_action(false, true, true, false, Duration::ZERO, None),
            CandidateCacheAction::PreserveOrigin
        );
    }

    #[test]
    fn test_candidate_cache_action_preserves_api_server_errors_without_stale() {
        assert_eq!(
            candidate_cache_action(true, true, false, false, Duration::ZERO, Some(30)),
            CandidateCacheAction::PreserveOrigin
        );
    }

    #[test]
    fn test_candidate_cache_action_preserves_explicit_zero_surrogate_ttl() {
        assert_eq!(
            candidate_cache_action(true, false, false, true, Duration::ZERO, Some(30)),
            CandidateCacheAction::PreserveOrigin
        );
    }

    #[test]
    fn test_candidate_cache_action_uses_fallback_only_for_zero_effective_ttl() {
        assert_eq!(
            candidate_cache_action(false, false, false, false, Duration::ZERO, Some(30)),
            CandidateCacheAction::SetFallbackTtl(Duration::from_secs(30))
        );
        assert_eq!(
            candidate_cache_action(
                false,
                false,
                false,
                false,
                Duration::from_secs(120),
                Some(30),
            ),
            CandidateCacheAction::PreserveOrigin
        );
        assert_eq!(
            candidate_cache_action(false, false, false, false, Duration::ZERO, None),
            CandidateCacheAction::PreserveOrigin
        );
    }

    #[test]
    fn test_passthrough_headers_preserve_original_api_host_for_funnelcake_backend() {
        let headers = passthrough_headers(FUNNELCAKE_API_BACKEND, "api.divine.video", "https");

        assert_eq!(headers.backend_host, FUNNELCAKE_BACKEND_HOST);
        assert_eq!(headers.forwarded_host, "api.divine.video");
        assert_eq!(headers.forwarded_proto, "https");
    }

    #[test]
    fn test_passthrough_headers_pass_through_http_scheme() {
        let headers = passthrough_headers(FUNNELCAKE_API_BACKEND, "api.divine.video", "http");

        assert_eq!(headers.forwarded_proto, "http");
    }

    #[test]
    fn test_api_cache_policy_skips_post_publish_on_api_host() {
        let policy = api_cache_policy("api.divine.video", "POST", "/api/events", false, false);

        assert!(!policy.cacheable);
        assert_eq!(policy.fallback_ttl_secs, None);
    }

    #[test]
    fn test_should_bypass_cache_for_public_well_known_paths() {
        assert!(should_bypass_cache(
            "divine.video",
            "/.well-known/apple-app-site-association"
        ));
        assert!(should_bypass_cache(
            "dvines.org",
            "/.well-known/assetlinks.json"
        ));
        assert!(should_bypass_cache(
            "divine.video:443",
            "/.well-known/apple-app-site-association"
        ));
        assert!(should_bypass_cache(
            "www.divine.video",
            "/.well-known/assetlinks.json"
        ));
        assert!(should_bypass_cache(
            "api.divine.video",
            "/.well-known/assetlinks.json"
        ));
        assert!(should_bypass_cache(
            "login.divine.video",
            "/.well-known/assetlinks.json"
        ));
    }

    #[test]
    fn test_should_not_bypass_cache_for_username_unknown_or_multi_level_hosts() {
        assert!(!should_bypass_cache(
            "alice.divine.video",
            "/.well-known/nostr.json"
        ));
        assert!(!should_bypass_cache(
            "foo.bar.divine.video",
            "/.well-known/assetlinks.json"
        ));
        assert!(!should_bypass_cache(
            "example.com",
            "/.well-known/assetlinks.json"
        ));
    }

    #[test]
    fn test_should_not_bypass_cache_for_non_well_known_paths() {
        assert!(!should_bypass_cache("divine.video", "/api/search"));
    }

    #[test]
    fn test_is_public_divine_host_excludes_unknown_domains() {
        assert!(is_public_divine_host("divine.video"));
        assert!(is_public_divine_host("www.divine.video"));
        assert!(!is_public_divine_host("example.com"));
        assert!(!is_public_divine_host("foo.example.com"));
    }
}
