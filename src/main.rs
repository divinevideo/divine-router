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

fn serve_profile(username: &str, _data: &UsernameData, req: Request) -> Result<Response, Error> {
    // Pass through to main_backend (divine-web) which will serve the SPA
    // with injected user data. We pass the original hostname in a custom header
    // so divine-web knows this is a subdomain profile request.
    let original_host = req.get_header_str("host").unwrap_or("").to_string();

    let mut req = req;
    req.set_header(header::HOST, MAIN_BACKEND_HOST);
    // Pass original host and username for divine-web to handle
    req.set_header("X-Original-Host", original_host.as_str());
    req.set_header("X-Username", username);

    Ok(req.send(MAIN_BACKEND)?)
}
