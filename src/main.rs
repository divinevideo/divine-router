// ABOUTME: Divine Router - Fastly edge router for wildcard subdomains
// ABOUTME: Routes username.divine.video to profiles, passes through system subdomains

use fastly::http::{header, StatusCode};
use fastly::kv_store::KVStore;
use fastly::{Error, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAIN_BACKEND: &str = "main_site";
const USERNAME_BACKEND: &str = "username_handler";
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
#[derive(Serialize, Deserialize, Debug)]
struct UsernameData {
    pubkey: String,
    #[serde(default)]
    relays: Vec<String>,
    #[serde(default)]
    status: String,
}

/// NIP-05 response format
#[derive(Serialize)]
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

#[derive(Debug)]
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
    // NIP-05 can also have ?name= query param
    let url = req.get_url();
    let queried_name = url
        .query_pairs()
        .find(|(k, _)| k == "name")
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| username.to_string());

    let lookup_name = queried_name.to_lowercase();

    match lookup_username(&lookup_name) {
        Some(data) if data.status == "active" => {
            let mut names = std::collections::HashMap::new();
            names.insert(lookup_name.clone(), data.pubkey.clone());

            let relays = if !data.relays.is_empty() {
                let mut relay_map = std::collections::HashMap::new();
                relay_map.insert(data.pubkey, data.relays);
                Some(relay_map)
            } else {
                None
            };

            let response = Nip05Response { names, relays };
            let body = serde_json::to_string(&response).unwrap_or_default();

            Ok(Response::from_status(StatusCode::OK)
                .with_header(header::CONTENT_TYPE, "application/json")
                .with_header("Access-Control-Allow-Origin", "*")
                .with_body(body))
        }
        _ => {
            // Username not found
            let response = Nip05Response {
                names: std::collections::HashMap::new(),
                relays: None,
            };
            let body = serde_json::to_string(&response).unwrap_or_default();

            Ok(Response::from_status(StatusCode::OK)
                .with_header(header::CONTENT_TYPE, "application/json")
                .with_header("Access-Control-Allow-Origin", "*")
                .with_body(body))
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
