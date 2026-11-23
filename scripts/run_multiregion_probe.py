#!/usr/bin/env python3
# ABOUTME: Runs scripts/probe_router_edge.py across multiple GCE regions using throwaway credential-free e2-small VMs.
# ABOUTME: Collects JSON output from each VM's serial console and deletes all VMs unconditionally in finally.

"""Run multi-region router benchmarks against Fastly and Bunny from GCE VMs.

Example:
    python3 scripts/run_multiregion_probe.py \\
        --project <gcp-project-id> \\
        --edge fastly=https://api.divine.video \\
        --edge bunny-middleware=https://<pull-zone>.b-cdn.net \\
        --baseline fastly
"""

import argparse
import base64
import json
import shlex
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_ZONES = [
    ("us-central1", "us-central1-a"),
    ("tokyo", "asia-northeast1-a"),
    ("london", "europe-west2-a"),
    ("sydney", "australia-southeast1-a"),
]

MARKER_BEGIN = "===PROBE_JSON_BEGIN==="
MARKER_END = "===PROBE_JSON_END==="


def build_startup_script(
    probe_source: str,
    region: str,
    edges: List[str],
    paths: List[str],
    baseline: str,
    iterations: int,
    warmup: int,
) -> str:
    encoded = base64.b64encode(probe_source.encode("utf-8")).decode("ascii")
    cmd_parts = ["python3", "/tmp/probe_router_edge.py"]
    for e in edges:
        cmd_parts.extend(["--edge", e])
    for p in paths:
        cmd_parts.extend(["--path", p])
    cmd_parts.extend([
        "--baseline", baseline,
        "--region", region,
        "--iterations", str(iterations),
        "--warmup", str(warmup),
        "--json", "/tmp/probe_out.json",
    ])
    cmd = " ".join(shlex.quote(c) for c in cmd_parts)

    return f"""#!/usr/bin/env bash
set -uo pipefail
exec > /dev/ttyS0 2>&1
base64 -d <<'EOF' > /tmp/probe_router_edge.py
{encoded}
EOF
{cmd} || true
echo "{MARKER_BEGIN}"
if [ -f /tmp/probe_out.json ]; then
  python3 -c 'import json; d=json.load(open("/tmp/probe_out.json")); d.pop("samples", None); print(json.dumps(d, separators=(",", ":")))' | base64 -w0
else
  printf '{{"error":"missing probe_out.json","region":"{region}"}}' | base64 -w0
fi
echo ""
echo "{MARKER_END}"
"""


def run_region(
    project: str,
    run_id: str,
    region: str,
    zone: str,
    startup_script: str,
    timeout_secs: int,
) -> Tuple[str, Optional[Dict[str, Any]], str]:
    vm_name = f"router-probe-{region}-{run_id}"[:62]
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tf:
        tf.write(startup_script)
        script_path = tf.name

    try:
        subprocess.run(
            [
                "gcloud", "-q", "compute", "instances", "create", vm_name,
                "--project", project,
                "--zone", zone,
                "--machine-type", "e2-small",
                "--image-family", "debian-12",
                "--image-project", "debian-cloud",
                "--no-service-account",
                "--no-scopes",
                "--metadata-from-file", f"startup-script={script_path}",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(f"[{region}] created {vm_name} in {zone}", file=sys.stderr)

        deadline = time.time() + timeout_secs
        last_output = ""
        while time.time() < deadline:
            time.sleep(10)
            res = subprocess.run(
                [
                    "gcloud", "-q", "compute", "instances", "get-serial-port-output", vm_name,
                    "--project", project,
                    "--zone", zone,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if res.returncode == 0:
                last_output = res.stdout
                if MARKER_BEGIN in last_output and MARKER_END in last_output:
                    start = last_output.index(MARKER_BEGIN) + len(MARKER_BEGIN)
                    end = last_output.index(MARKER_END, start)
                    b64_payload = "".join(last_output[start:end].split())
                    try:
                        raw_json = base64.b64decode(b64_payload).decode("utf-8")
                        parsed = json.loads(raw_json)
                        if not isinstance(parsed, dict) or parsed.get("error") or not parsed.get("summaries"):
                            err_msg = parsed.get("error") if isinstance(parsed, dict) else "unexpected payload"
                            return region, None, f"probe failed on VM: {err_msg or 'missing summaries'}"
                        return region, parsed, ""
                    except Exception as exc:  # noqa: BLE001
                        return region, None, f"decode/parse error: {exc}\n{b64_payload[:300]}"
        return region, None, f"timed out after {timeout_secs}s"
    except subprocess.CalledProcessError as exc:
        return region, None, f"gcloud error: {exc.stderr.strip()}"
    finally:
        Path(script_path).unlink(missing_ok=True)
        del_res = subprocess.run(
            [
                "gcloud", "-q", "compute", "instances", "delete", vm_name,
                "--project", project,
                "--zone", zone,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        status = "deleted" if del_res.returncode == 0 else f"delete-warn({del_res.returncode})"
        print(f"[{region}] {status} {vm_name}", file=sys.stderr)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True, help="GCP project ID for throwaway probe VMs")
    ap.add_argument("--edge", action="append", required=True)
    ap.add_argument("--path", action="append", default=None, help="Paths to probe (defaults to /api/videos and /api/videos?limit=20)")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--iterations", type=int, default=15)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--json", metavar="FILE", help="write combined multi-region JSON results")
    args = ap.parse_args(argv)
    paths = args.path or ["/api/videos", "/api/videos?limit=20"]

    probe_path = Path(__file__).with_name("probe_router_edge.py")
    probe_source = probe_path.read_text(encoding="utf-8")
    run_id = str(int(time.time()))[-6:]

    results: Dict[str, Any] = {}
    errors: Dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(DEFAULT_ZONES)) as pool:
        futs = {}
        for region, zone in DEFAULT_ZONES:
            startup = build_startup_script(
                probe_source, region, args.edge, paths, args.baseline, args.iterations, args.warmup
            )
            futs[pool.submit(run_region, args.project, run_id, region, zone, startup, args.timeout)] = region

        for fut in as_completed(futs):
            region, payload, err = fut.result()
            if payload is not None:
                results[region] = payload
            else:
                errors[region] = err

    any_probe_failed = False
    print("\n=== Multi-Region Router Benchmark Summary ===")
    print(f"{'Region':<12} {'Edge':<18} {'Conn':>6} {'p50':>7} {'p95':>7} {'ColdMiss':>9} {'Auth':>6} {'AE':>5} {'Err':>4}  Verdict")
    print("-" * 94)
    for region, _zone in DEFAULT_ZONES:
        if region in errors:
            print(f"{region:<12} ERROR: {errors[region]}")
            continue
        payload = results.get(region) or {}
        summaries = payload.get("summaries") or {}
        verdicts = {v["edge"]: v for v in (payload.get("verdicts") or [])}
        contracts = payload.get("contracts") or {}
        for edge_name, s in summaries.items():
            conn = f"{s['connect_p50_ms']:.0f}ms" if s.get("connect_p50_ms") is not None else "-"
            p50 = f"{s['ttfb_p50_ms']:.0f}ms" if s.get("ttfb_p50_ms") is not None else "-"
            p95 = f"{s['ttfb_p95_ms']:.0f}ms" if s.get("ttfb_p95_ms") is not None else "-"
            c = contracts.get(edge_name) or {}
            cold = f"{c['cold_miss_ttfb_ms']:.0f}ms" if c.get("cold_miss_ttfb_ms") is not None else "-"
            auth = "OK" if c.get("auth_bypass_ok") is True else ("FAIL" if c.get("auth_bypass_ok") is False else "-")
            ae = "OK" if c.get("encoding_dedup_ok") is True else ("FAIL" if c.get("encoding_dedup_ok") is False else "-")
            verdict = "baseline" if edge_name == args.baseline else verdicts.get(edge_name, {}).get("verdict", "-")
            if edge_name != args.baseline and (
                verdict != "PASS"
                or c.get("auth_bypass_ok") is not True
                or c.get("encoding_dedup_ok") is not True
            ):
                any_probe_failed = True
            print(f"{region:<12} {edge_name:<18} {conn:>6} {p50:>7} {p95:>7} {cold:>9} {auth:>6} {ae:>5} {s.get('errors', 0):>4}  {verdict}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"regions": results, "errors": errors}, fh, indent=2)
        print(f"\nWrote {args.json}", file=sys.stderr)

    return 0 if (not errors and not any_probe_failed) else 1


if __name__ == "__main__":
    sys.exit(main())
