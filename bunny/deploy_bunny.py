#!/usr/bin/env python3
# ABOUTME: Deploys the bundled Deno/TS divine-router script to Bunny Edge Scripting and configures its Pull Zone.
# ABOUTME: Reads API key from BUNNY_API_KEY env var or ~/.config/divine-cdn/bunny-api-key; never prints credentials.

"""Deploy divine-router to Bunny Edge Scripting (Standalone or Pull Zone Middleware).

Examples:
    # Deploy Standalone Edge Script for api.divine.video staging evaluation:
    python3 bunny/deploy_bunny.py \\
        --name divine-router-api-standalone \\
        --mode standalone \\
        --bundle bunny/dist/standalone.js \\
        --env PUBLIC_HOST_OVERRIDE=api.divine.video

    # Deploy Pull Zone Middleware Edge Script (cache HITs cost $0 compute):
    python3 bunny/deploy_bunny.py \\
        --name divine-router-api-middleware \\
        --mode middleware \\
        --bundle bunny/dist/middleware.js \\
        --origin https://relay.divine.video \\
        --env PUBLIC_HOST_OVERRIDE=api.divine.video
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

API_BASE = "https://api.bunny.net"
DEFAULT_KEY_PATH = Path.home() / ".config" / "divine-cdn" / "bunny-api-key"

SCRIPT_TYPE_MAP = {
    "standalone": 1,
    "middleware": 2,
}


def load_api_key() -> str:
    env_key = os.environ.get("BUNNY_API_KEY", "").strip()
    if env_key:
        return env_key
    if DEFAULT_KEY_PATH.exists():
        key = DEFAULT_KEY_PATH.read_text().strip()
        if key:
            return key
    raise RuntimeError(
        f"Missing Bunny API key. Set BUNNY_API_KEY or create {DEFAULT_KEY_PATH}"
    )


class BunnyClient:
    def __init__(self, api_key: str):
        self._api_key = api_key

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{API_BASE}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "AccessKey": self._api_key,
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Bunny API {method} {path} failed ({exc.code}): {detail}") from exc


def find_script_by_name(client: BunnyClient, name: str) -> Optional[Dict[str, Any]]:
    resp = client.request("GET", "/compute/script")
    items = resp.get("Items", resp) if isinstance(resp, dict) else resp
    for item in items or []:
        if item.get("Name") == name:
            return item
    return None


def find_pull_zone_by_name(client: BunnyClient, name: str) -> Optional[Dict[str, Any]]:
    pzs = client.request("GET", "/pullzone")
    for pz in pzs or []:
        if pz.get("Name") == name:
            return pz
    return None


def upsert_env_vars(client: BunnyClient, script_id: int, env_vars: Dict[str, str]) -> None:
    """Upsert non-secret Edge Script variables (Bunny reads the runtime value from DefaultValue).

    Do not pass credentials via --env; store secrets in Bunny Edge Script Secrets instead.
    """
    if not env_vars:
        return
    script = client.request("GET", f"/compute/script/{script_id}")
    existing_items = script.get("EdgeScriptVariables") or []
    by_name = {item.get("Name"): item for item in existing_items}

    for k, v in env_vars.items():
        if k in by_name:
            var_id = by_name[k]["Id"]
            client.request(
                "POST",
                f"/compute/script/{script_id}/variables/{var_id}",
                {"Name": k, "Required": False, "DefaultValue": v},
            )
        else:
            client.request(
                "POST",
                f"/compute/script/{script_id}/variables/add",
                {"Name": k, "Required": False, "DefaultValue": v},
            )


def configure_api_pull_zone(
    client: BunnyClient,
    pull_zone_id: int,
    *,
    middleware_script_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Configure a Bunny Standard Pull Zone to mirror divine-router's API cache contract."""
    update: Dict[str, Any] = {
        "Type": 0,  # Standard (119+ PoPs: US, EU, Tokyo, Sydney)
        "UseStaleWhileUpdating": True,
        "UseStaleWhileOffline": True,
        "EnableRequestCoalescing": True,
        "EnableSmartCache": False,
        "IgnoreQueryStrings": False,
        "EnableCacheSlice": False,
        "CacheControlMaxAgeOverride": -1,  # Respect origin Cache-Control
        "CacheControlPublicMaxAgeOverride": -1,
        "EnableWebSocket": True,
        "EnableHostnameVary": True,
        "EnableCountryCodeVary": False,
        "DisableCookies": False,
        "OriginRetries": 1,
        "OriginConnectTimeout": 10,
        "OriginResponseTimeout": 30,
    }
    if middleware_script_id is not None:
        update["MiddlewareScriptId"] = middleware_script_id

    updated = client.request("POST", f"/pullzone/{pull_zone_id}", update)

    # Ensure cache-bypass Edge Rules exist so authenticated, mutating, and
    # delegated routes never serve cached or stale responses.
    pz = client.request("GET", f"/pullzone/{pull_zone_id}")
    existing_rules = {r.get("Description"): r for r in (pz.get("EdgeRules") or [])}

    desired_rules: List[Dict[str, Any]] = [
        {
            "Description": "divine-router: bypass cache when Authorization header is present",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 1,  # RequestHeader
                    "PatternMatchingType": 0,  # MatchAny
                    "Parameter1": "Authorization",
                    "PatternMatches": ["*"],
                }
            ],
        },
        {
            "Description": "divine-router: mark Authorization responses private no-store",
            "Enabled": True,
            "ActionType": 5,  # SetResponseHeader
            "ActionParameter1": "Cache-Control",
            "ActionParameter2": "private, no-store",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 1,  # RequestHeader
                    "PatternMatchingType": 0,  # MatchAny
                    "Parameter1": "Authorization",
                    "PatternMatches": ["*"],
                }
            ],
        },
        {
            "Description": "divine-router: bypass cache for candidate hosts",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "https://api2.divine.video/*",
                        "http://api2.divine.video/*",
                        "https://relay2.divine.video/*",
                        "http://relay2.divine.video/*",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for non-GET methods",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 9,  # RequestMethod
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for HEAD requests",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 9,  # RequestMethod
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": ["HEAD"],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for well-known, AP, and docs routes",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://*/.well-known/*",
                        "*://*/ap",
                        "*://*/ap/*",
                        "*://*/nodeinfo",
                        "*://*/api/docs*",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for exact mobile API routes",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://*/v1/account/moderation-status",
                        "*://*/v1/minor-review-cases/greenlight",
                        "*://*/v1/minor-review-cases/*/parent-contact",
                        "*://*/v1/minor-review-cases/*/parent-consent",
                        "*://*/api/zendesk/pre-auth",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for short links (/l)",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://divine.video/l",
                        "*://divine.video/l/*",
                        "*://www.divine.video/l",
                        "*://www.divine.video/l/*",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for short links (/api/links)",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://divine.video/api/links",
                        "*://divine.video/api/links/*",
                        "*://www.divine.video/api/links",
                        "*://www.divine.video/api/links/*",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for exact sound proxy routes",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://*/api/sounds/providers",
                        "*://*/api/sounds/providers?*",
                        "*://*/api/sounds/trending",
                        "*://*/api/sounds/trending?*",
                        "*://*/api/sounds/*/videos",
                    ],
                },
            ],
        },
        {
            "Description": "divine-router: bypass cache for sound proxy videos with query",
            "Enabled": True,
            "ActionType": 3,  # OverrideCacheTime
            "ActionParameter1": "0",
            "TriggerMatchingType": 0,  # MatchAny
            "Triggers": [
                {
                    "Type": 0,  # Url
                    "PatternMatchingType": 0,  # MatchAny
                    "PatternMatches": [
                        "*://*/api/sounds/*/videos?*",
                        "*://*/nodeinfo/*",
                    ],
                },
            ],
        },
    ]

    desired_descriptions = {r["Description"] for r in desired_rules}
    for desc, existing in existing_rules.items():
        if desc and desc.startswith("divine-router:") and desc not in desired_descriptions:
            guid = existing.get("Guid")
            if guid:
                client.request("DELETE", f"/pullzone/{pull_zone_id}/edgerules/{guid}")

    for rule in desired_rules:
        if rule["Description"] in existing_rules:
            rule["Guid"] = existing_rules[rule["Description"]]["Guid"]
        client.request("POST", f"/pullzone/{pull_zone_id}/edgerules/addOrUpdate", rule)

    return client.request("GET", f"/pullzone/{pull_zone_id}")


def parse_env_pair(item: str) -> Tuple[str, str]:
    if "=" not in item:
        raise argparse.ArgumentTypeError(f"--env expects KEY=VALUE, got {item!r}")
    k, v = item.split("=", 1)
    if not k:
        raise argparse.ArgumentTypeError(f"--env key must not be empty, got {item!r}")
    return k, v


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="Bunny Edge Script (and Pull Zone) name")
    ap.add_argument("--mode", choices=["standalone", "middleware"], required=True)
    ap.add_argument("--bundle", required=True, help="Path to bundled JS file")
    ap.add_argument("--origin", default="https://relay.divine.video", help="Origin URL for middleware Pull Zone")
    ap.add_argument("--env", action="append", type=parse_env_pair, help="Environment variable KEY=VALUE (repeatable)")
    ap.add_argument("--hostname", action="append", help="Attach custom hostname to Pull Zone (repeatable)")
    ap.add_argument(
        "--load-free-cert",
        action="store_true",
        help="Request Let's Encrypt TLS cert and enable ForceSSL for each --hostname (requires DNS CNAME pointing to Pull Zone)",
    )
    ap.add_argument("--note", default="deploy from divine-router", help="Release note")
    args = ap.parse_args(argv)

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        print(f"error: bundle not found: {bundle_path}", file=sys.stderr)
        return 2
    code = bundle_path.read_text(encoding="utf-8")
    env_vars = dict(args.env or [])

    client = BunnyClient(load_api_key())
    script = find_script_by_name(client, args.name)

    if script is None:
        script_type = SCRIPT_TYPE_MAP[args.mode]
        payload: Dict[str, Any] = {
            "Name": args.name,
            "ScriptType": script_type,
            "CreateLinkedPullZone": args.mode == "standalone",
        }
        script = client.request("POST", "/compute/script", payload)
        print(f"Created Edge Script id={script['Id']} name={script['Name']} type={script.get('ScriptType')}")
    else:
        print(f"Reusing Edge Script id={script['Id']} name={script['Name']} type={script.get('ScriptType')}")

    script_id = int(script["Id"])
    upsert_env_vars(client, script_id, env_vars)
    client.request("POST", f"/compute/script/{script_id}/code", {"Code": code})
    client.request("POST", f"/compute/script/{script_id}/publish", {"Note": args.note})
    script = client.request("GET", f"/compute/script/{script_id}")
    print(f"Published Edge Script id={script_id} defaultHostname={script.get('DefaultHostname')}")

    pull_zone_id: Optional[int] = None
    linked = script.get("LinkedPullZones") or []
    if linked:
        pull_zone_id = int(linked[0]["Id"])

    if args.mode == "middleware" and pull_zone_id is None:
        pz = find_pull_zone_by_name(client, args.name)
        if pz is None:
            pz = client.request(
                "POST",
                "/pullzone",
                {
                    "Name": args.name,
                    "OriginUrl": args.origin,
                    "Type": 0,  # Standard
                    "MiddlewareScriptId": script_id,
                },
            )
            print(f"Created Pull Zone id={pz['Id']} name={pz['Name']}")
        pull_zone_id = int(pz["Id"])

    if pull_zone_id is not None:
        pz = configure_api_pull_zone(
            client,
            pull_zone_id,
            middleware_script_id=script_id if args.mode == "middleware" else None,
        )
        existing_hostnames = {h.get("Value") for h in (pz.get("Hostnames") or [])}
        for hostname in args.hostname or []:
            if hostname not in existing_hostnames:
                client.request("POST", f"/pullzone/{pull_zone_id}/addHostname", {"Hostname": hostname})
                print(f"Added custom hostname {hostname} to Pull Zone {pull_zone_id}")
            if args.load_free_cert:
                encoded_host = urllib.parse.quote(hostname, safe="")
                client.request("GET", f"/pullzone/loadFreeCertificate?hostname={encoded_host}")
                client.request(
                    "POST",
                    f"/pullzone/{pull_zone_id}/setForceSSL",
                    {"Hostname": hostname, "ForceSSL": True},
                )
                print(f"Loaded free TLS cert and enabled ForceSSL for {hostname}")
        if args.hostname:
            pz = client.request("GET", f"/pullzone/{pull_zone_id}")
        hostnames = [h.get("Value") for h in (pz.get("Hostnames") or [])]
        print(
            json.dumps(
                {
                    "script_id": script_id,
                    "script_name": args.name,
                    "mode": args.mode,
                    "default_hostname": script.get("DefaultHostname"),
                    "pull_zone_id": pull_zone_id,
                    "pull_zone_hostnames": hostnames,
                    "stale_while_updating": pz.get("UseStaleWhileUpdating"),
                    "stale_while_offline": pz.get("UseStaleWhileOffline"),
                    "request_coalescing": pz.get("EnableRequestCoalescing"),
                    "edge_rules_count": len(pz.get("EdgeRules") or []),
                },
                indent=2,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
