// ABOUTME: Divine Router - Fastly edge router for wildcard subdomains
// ABOUTME: Routes username.divine.video to profiles, passes through system subdomains

use fastly::http::{header, StatusCode};
use fastly::kv_store::KVStore;
use fastly::{Error, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAIN_BACKEND: &str = "main_site";
const BLOSSOM_BACKEND: &str = "blossom";
const KV_STORE_NAME: &str = "usernames";

// Subdomains that route to blossom/media server
const BLOSSOM_SUBDOMAINS: &[&str] = &["media", "blossom"];

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
];

/// Username data stored in KV
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct UsernameData {
    pubkey: String,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    status: String,
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

    // Parse hostname to determine routing
    match classify_host(&host) {
        HostType::Apex => {
            // Main site - passthrough
            passthrough(req, MAIN_BACKEND)
        }
        HostType::MultiLevel => {
            // Multi-level subdomain (*.admin.dvines.org) - passthrough
            passthrough(req, MAIN_BACKEND)
        }
        HostType::System(subdomain) => {
            // Route to appropriate backend based on subdomain
            let blossom_set: HashSet<&str> = BLOSSOM_SUBDOMAINS.iter().copied().collect();
            if blossom_set.contains(subdomain.as_str()) {
                passthrough(req, BLOSSOM_BACKEND)
            } else {
                passthrough(req, MAIN_BACKEND)
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
        (sld == "dvines" && tld == "org")
            || (sld == "divine" && tld == "video")
            || (sld == "dvine" && tld == "video")
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

// Backend host headers - must match what the backend expects
const MAIN_BACKEND_HOST: &str = "inherently-ethical-gelding.edgecompute.app";
const BLOSSOM_BACKEND_HOST: &str = "separately-robust-roughy.edgecompute.app";

fn passthrough(req: Request, backend: &str) -> Result<Response, Error> {
    // Set the Host header to what the backend expects
    let backend_host = match backend {
        MAIN_BACKEND => MAIN_BACKEND_HOST,
        BLOSSOM_BACKEND => BLOSSOM_BACKEND_HOST,
        _ => MAIN_BACKEND_HOST,
    };

    let mut req = req;
    req.set_header(header::HOST, backend_host);
    Ok(req.send(backend)?)
}

fn handle_username_request(username: &str, path: &str, req: Request) -> Result<Response, Error> {
    // Check if this is a NIP-05 request
    if path == "/.well-known/nostr.json" {
        return handle_nip05(username, &req);
    }

    // Look up username in KV store
    let user_data = lookup_username(username);

    match user_data {
        Some(data) if data.status == "active" => {
            // Valid username - serve profile or redirect
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
fn build_nip05_response(
    queried_name: &str,
    user_data: Option<&UsernameData>,
) -> Nip05Response {
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
    let mut lookup = kv_store.lookup(username).ok()?;
    let body = lookup.take_body().into_bytes();
    serde_json::from_slice(&body).ok()
}

fn serve_profile(username: &str, data: &UsernameData, _req: Request) -> Result<Response, Error> {
    // Generate an HTML page that:
    // 1. Sets window.__DIVINE_USER__ with user data
    // 2. Redirects to the profile page via client-side navigation
    // This ensures the user data is available when the SPA loads

    let npub = hex_to_npub(&data.pubkey).unwrap_or_else(|_| data.pubkey.clone());

    let user_data_json = serde_json::json!({
        "subdomain": username,
        "pubkey": data.pubkey,
        "npub": npub,
        "username": username,
        "nip05": format!("{}@divine.video", username)
    });

    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loading {0}...</title>
    <meta property="og:title" content="{0} on diVine" />
    <meta property="og:url" content="https://{0}.divine.video/" />
    <meta property="og:type" content="profile" />
    <script>
        window.__DIVINE_USER__ = {1};
        // Store in sessionStorage for SPA to read after redirect
        sessionStorage.setItem('divine_user', JSON.stringify(window.__DIVINE_USER__));
        // Redirect to profile page
        window.location.replace('/profile/' + window.__DIVINE_USER__.npub);
    </script>
</head>
<body>
    <p>Loading profile...</p>
</body>
</html>"#, username, user_data_json);

    Ok(Response::from_status(StatusCode::OK)
        .with_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .with_header(header::CACHE_CONTROL, "no-cache, no-store")
        .with_body(html))
}

fn hex_to_npub(hex: &str) -> Result<String, ()> {
    if hex.len() != 64 {
        return Err(());
    }

    let data: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16))
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
    let hrp_expand: Vec<u8> = hrp.chars()
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

    (0..6).map(|i| ((chk >> (5 * (5 - i))) & 31) as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_active_user(pubkey: &str, relays: Vec<String>) -> UsernameData {
        UsernameData {
            pubkey: pubkey.to_string(),
            relays,
            status: "active".to_string(),
        }
    }

    fn make_inactive_user(pubkey: &str) -> UsernameData {
        UsernameData {
            pubkey: pubkey.to_string(),
            relays: vec![],
            status: "inactive".to_string(),
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
        assert_eq!(response.names.get("daniel"), Some(&"abc123pubkey".to_string()));
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

        assert_eq!(response.names.get("daniel"), Some(&"abc123pubkey".to_string()));
        assert!(!response.names.contains_key("DANIEL"));
    }

    #[test]
    fn test_classify_host_apex() {
        assert_eq!(classify_host("divine.video"), HostType::Apex);
        assert_eq!(classify_host("dvine.video"), HostType::Apex);
        assert_eq!(classify_host("dvines.org"), HostType::Apex);
    }

    #[test]
    fn test_classify_host_with_port() {
        assert_eq!(classify_host("divine.video:443"), HostType::Apex);
        assert_eq!(classify_host("daniel.divine.video:8080"), HostType::Username("daniel".to_string()));
    }

    #[test]
    fn test_classify_host_system_subdomain() {
        assert_eq!(classify_host("www.divine.video"), HostType::System("www".to_string()));
        assert_eq!(classify_host("api.divine.video"), HostType::System("api".to_string()));
        assert_eq!(classify_host("relay.divine.video"), HostType::System("relay".to_string()));
        assert_eq!(classify_host("media.divine.video"), HostType::System("media".to_string()));
    }

    #[test]
    fn test_classify_host_username_subdomain() {
        assert_eq!(classify_host("daniel.divine.video"), HostType::Username("daniel".to_string()));
        assert_eq!(classify_host("alice.dvine.video"), HostType::Username("alice".to_string()));
        assert_eq!(classify_host("bob.dvines.org"), HostType::Username("bob".to_string()));
    }

    #[test]
    fn test_classify_host_username_case_insensitive() {
        // Subdomain is lowercased, but domain check is case-sensitive
        // (hostnames come lowercase from HTTP headers in practice)
        assert_eq!(classify_host("DANIEL.divine.video"), HostType::Username("daniel".to_string()));
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
}
