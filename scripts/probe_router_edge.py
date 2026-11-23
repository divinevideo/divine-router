#!/usr/bin/env python3
# ABOUTME: Compares divine-router edge candidates (Bunny vs Fastly) on TTFB, caching, and Accept-Encoding parity.
# ABOUTME: Standard library only; run from regional VMs (US, Tokyo, EU, Sydney) to validate latency and cache behavior.

"""Benchmark and validate a candidate divine-router edge against Fastly.

Modeled on divine-blossom/scripts/probe_cdn_delivery.py, extended for API and
router contracts:
  - Separates DNS+TCP+TLS connect latency from established-connection TTFB.
  - Compares candidate p95 TTFB against a baseline edge with margin + floor.
  - Checks Accept-Encoding cache fragmentation (Dart `gzip` vs Chrome `gzip, deflate, br, zstd` vs `br`).
  - Checks Authorization cache bypass (authenticated requests must not hit shared cache).
  - Checks HTTP status and JSON payload shape parity across edges.

Example:

    python3 scripts/probe_router_edge.py \\
        --edge fastly=https://api.divine.video \\
        --edge bunny=https://api-bunny-test.divine.video \\
        --path /api/videos --path "/api/videos?limit=20" \\
        --baseline fastly --region us-central1 --iterations 15
"""

import argparse
import gzip
import http.client
import json
import ssl
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

READ_CHUNK = 65536
DEFAULT_TIMEOUT = 30.0
DEFAULT_FLOOR_MS = 10.0
CACHE_HEADER_NAMES = ("cdn-cache", "cf-cache-status", "x-cache")
ACCEPT_ENCODING_VARIANTS = (
    ("br", "br"),
    ("chrome", "gzip, deflate, br, zstd"),
    ("dart", "gzip"),
    ("gzip_deflate", "gzip, deflate"),
)


@dataclass
class Sample:
    edge: str
    region: str
    ttfb_ms: float
    total_ms: float
    bytes_read: int
    error: Optional[str] = None
    path: str = ""
    status: Optional[int] = None
    cache_status: Optional[str] = None
    cache_headers: Dict[str, str] = field(default_factory=dict)
    content_encoding: Optional[str] = None
    cache_control: Optional[str] = None
    served_by: Optional[str] = None
    connect_ms: Optional[float] = None


@dataclass
class Summary:
    edge: str
    region: str
    n: int
    errors: int
    ttfb_p50_ms: Optional[float] = None
    ttfb_p95_ms: Optional[float] = None
    ttfb_p99_ms: Optional[float] = None
    total_p95_ms: Optional[float] = None
    connect_p50_ms: Optional[float] = None
    connect_p95_ms: Optional[float] = None
    bytes_total: int = 0
    cache_statuses: Dict[str, int] = field(default_factory=dict)


@dataclass
class Verdict:
    edge: str
    region: str
    verdict: str  # PASS | FAIL | NO_DATA
    delta_pct: Optional[float]
    reason: str


@dataclass
class EncodingCheckResult:
    label: str
    accept_encoding: str
    status: Optional[int]
    content_encoding: Optional[str]
    cache_status: Optional[str]
    bytes_read: int
    ttfb_ms: float
    error: Optional[str] = None


@dataclass
class ContractCheckReport:
    edge: str
    encoding_variants: List[EncodingCheckResult] = field(default_factory=list)
    encoding_dedup_ok: Optional[bool] = None
    auth_bypass_cache_status: Optional[str] = None
    auth_bypass_ok: Optional[bool] = None
    cold_miss_ttfb_ms: Optional[float] = None
    cold_miss_cache_status: Optional[str] = None


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (p / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] + frac * (ordered[high] - ordered[low])


def capture_cache_headers(headers) -> Dict[str, str]:
    captured: Dict[str, str] = {}
    for name in CACHE_HEADER_NAMES:
        value = headers.get(name)
        if value:
            captured[name] = value
    return captured


def select_cache_status(headers) -> Optional[str]:
    captured = capture_cache_headers(headers)
    for name in CACHE_HEADER_NAMES:
        if name in captured:
            return captured[name]
    return None


def is_cache_hit(cache_status: Optional[str]) -> bool:
    if not cache_status:
        return False
    tokens = [t.strip().upper() for t in cache_status.split(",")]
    return any(t == "HIT" or t.startswith("HIT") for t in tokens)


def summarize(edge: str, region: str, samples: List[Sample]) -> Summary:
    ok = [s for s in samples if s.error is None]
    errors = len(samples) - len(ok)

    cache_statuses: Dict[str, int] = {}
    for s in ok:
        if s.cache_status:
            key = s.cache_status.strip().lower()
            cache_statuses[key] = cache_statuses.get(key, 0) + 1

    return Summary(
        edge=edge,
        region=region,
        n=len(samples),
        errors=errors,
        connect_p50_ms=percentile([s.connect_ms for s in ok if s.connect_ms is not None], 50),
        connect_p95_ms=percentile([s.connect_ms for s in ok if s.connect_ms is not None], 95),
        ttfb_p50_ms=percentile([s.ttfb_ms for s in ok], 50),
        ttfb_p95_ms=percentile([s.ttfb_ms for s in ok], 95),
        ttfb_p99_ms=percentile([s.ttfb_ms for s in ok], 99),
        total_p95_ms=percentile([s.total_ms for s in ok], 95),
        bytes_total=sum(s.bytes_read for s in ok),
        cache_statuses=cache_statuses,
    )


def compare_to_baseline(
    candidate: Summary,
    baseline: Summary,
    margin_pct: float,
    floor_ms: float = DEFAULT_FLOOR_MS,
) -> Verdict:
    if candidate.n == 0:
        return Verdict(candidate.edge, candidate.region, "NO_DATA", None, "no samples collected")
    if candidate.errors:
        return Verdict(
            candidate.edge,
            candidate.region,
            "FAIL",
            None,
            f"{candidate.errors}/{candidate.n} requests failed",
        )
    if candidate.ttfb_p95_ms is None:
        return Verdict(candidate.edge, candidate.region, "NO_DATA", None, "no successful samples")
    if baseline.ttfb_p95_ms is None or baseline.ttfb_p95_ms <= 0:
        return Verdict(candidate.edge, candidate.region, "NO_DATA", None, "baseline has no usable timings")

    delta_ms = candidate.ttfb_p95_ms - baseline.ttfb_p95_ms
    delta = delta_ms / baseline.ttfb_p95_ms * 100.0

    if delta <= margin_pct:
        return Verdict(
            candidate.edge,
            candidate.region,
            "PASS",
            delta,
            f"p95 {delta:+.1f}% ({delta_ms:+.1f}ms) vs baseline",
        )
    if delta_ms <= floor_ms:
        return Verdict(
            candidate.edge,
            candidate.region,
            "PASS",
            delta,
            f"p95 {delta:+.1f}% but only {delta_ms:+.1f}ms, within the {floor_ms:.0f}ms floor",
        )
    return Verdict(
        candidate.edge,
        candidate.region,
        "FAIL",
        delta,
        f"p95 {delta:+.1f}% ({delta_ms:+.1f}ms) vs baseline, outside {margin_pct:.0f}% margin and {floor_ms:.0f}ms floor",
    )


class EdgeSession:
    """Holds one keep-alive connection per edge so response latency excludes handshake."""

    def __init__(
        self,
        base_url: str,
        timeout: float,
        reuse: bool = True,
        host_header: Optional[str] = None,
    ):
        p = urllib.parse.urlparse(base_url)
        self.scheme = p.scheme or "https"
        self.netloc = p.netloc
        self.host_header = host_header or p.netloc
        self.timeout = timeout
        self.reuse = reuse
        self.ctx = ssl.create_default_context()
        self.conn: Optional[http.client.HTTPConnection] = None
        self.connect_samples: List[float] = []

    def measure_connect(self, rounds: int = 3) -> None:
        for _ in range(rounds):
            self.close()
            self._connect()
        self.close()

    def _connect(self) -> float:
        started = time.perf_counter()
        if self.scheme == "http":
            self.conn = http.client.HTTPConnection(self.netloc, timeout=self.timeout)
        else:
            self.conn = http.client.HTTPSConnection(
                self.netloc, context=self.ctx, timeout=self.timeout
            )
        self.conn.connect()
        elapsed = (time.perf_counter() - started) * 1000.0
        self.connect_samples.append(elapsed)
        return elapsed

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:  # noqa: BLE001
                pass
            self.conn = None

    def fetch(
        self,
        path: str,
        edge: str,
        region: str,
        extra_headers: Optional[Dict[str, str]] = None,
        capture_body: bool = False,
    ) -> Tuple[Sample, Optional[bytes]]:
        connect_ms = None
        for attempt in range(2):
            reused = self.conn is not None and self.reuse
            try:
                if self.conn is None or not self.reuse:
                    self.close()
                    connect_ms = self._connect()

                req_headers = {
                    "Host": self.host_header,
                    "User-Agent": "divine-router-probe/1",
                    "Accept-Encoding": "gzip",
                    "Connection": "keep-alive",
                }
                if extra_headers:
                    req_headers.update(extra_headers)

                started = time.perf_counter()
                self.conn.request("GET", path, headers=req_headers)
                resp = self.conn.getresponse()
                ttfb = (time.perf_counter() - started) * 1000.0

                chunks: List[bytes] = []
                read = 0
                while True:
                    chunk = resp.read(READ_CHUNK)
                    if not chunk:
                        break
                    read += len(chunk)
                    if capture_body:
                        chunks.append(chunk)
                total = (time.perf_counter() - started) * 1000.0

                headers = resp.headers
                if resp.status >= 400:
                    self.close()
                    return (
                        Sample(
                            edge=edge,
                            region=region,
                            ttfb_ms=ttfb,
                            total_ms=total,
                            bytes_read=read,
                            error=f"HTTP {resp.status}",
                            path=path,
                            status=resp.status,
                            cache_status=select_cache_status(headers),
                            cache_headers=capture_cache_headers(headers),
                            content_encoding=headers.get("content-encoding"),
                            cache_control=headers.get("cache-control"),
                            served_by=headers.get("x-served-by") or headers.get("server"),
                            connect_ms=connect_ms,
                        ),
                        b"".join(chunks) if capture_body else None,
                    )

                return (
                    Sample(
                        edge=edge,
                        region=region,
                        ttfb_ms=ttfb,
                        total_ms=total,
                        bytes_read=read,
                        error=None,
                        path=path,
                        status=resp.status,
                        cache_status=select_cache_status(headers),
                        cache_headers=capture_cache_headers(headers),
                        content_encoding=headers.get("content-encoding"),
                        cache_control=headers.get("cache-control"),
                        served_by=headers.get("x-served-by") or headers.get("server"),
                        connect_ms=connect_ms,
                    ),
                    b"".join(chunks) if capture_body else None,
                )
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError):
                self.close()
                if reused and attempt == 0:
                    continue
                return (
                    Sample(
                        edge=edge,
                        region=region,
                        ttfb_ms=0.0,
                        total_ms=0.0,
                        bytes_read=0,
                        error="RemoteDisconnected",
                        path=path,
                        connect_ms=connect_ms,
                    ),
                    None,
                )
            except Exception as exc:  # noqa: BLE001
                self.close()
                return (
                    Sample(
                        edge=edge,
                        region=region,
                        ttfb_ms=0.0,
                        total_ms=0.0,
                        bytes_read=0,
                        error=type(exc).__name__,
                        path=path,
                        connect_ms=connect_ms,
                    ),
                    None,
                )
        return (
            Sample(edge=edge, region=region, ttfb_ms=0.0, total_ms=0.0, bytes_read=0, error="RetryExhausted", path=path),
            None,
        )


def run_contract_checks(
    session: EdgeSession,
    edge: str,
    region: str,
    path: str,
) -> ContractCheckReport:
    """Tests Accept-Encoding cache dedup, Authorization bypass, and cold-miss latency."""
    report = ContractCheckReport(edge=edge)

    # 1. Warm the path with gzip, then test client Accept-Encoding variants
    session.fetch(path, edge, region, extra_headers={"Accept-Encoding": "br"})
    session.fetch(path, edge, region, extra_headers={"Accept-Encoding": "gzip"})

    for label, ae in ACCEPT_ENCODING_VARIANTS:
        sample, _ = session.fetch(path, edge, region, extra_headers={"Accept-Encoding": ae})
        report.encoding_variants.append(
            EncodingCheckResult(
                label=label,
                accept_encoding=ae,
                status=sample.status,
                content_encoding=sample.content_encoding,
                cache_status=sample.cache_status,
                bytes_read=sample.bytes_read,
                ttfb_ms=round(sample.ttfb_ms, 1),
                error=sample.error,
            )
        )

    # Every client variant must be served from the object warmed above. A
    # missing cache-status header or any non-HIT means Accept-Encoding still
    # fragments the cache (or cannot be verified), so fail closed.
    report.encoding_dedup_ok = bool(report.encoding_variants) and all(
        ev.error is None and is_cache_hit(ev.cache_status)
        for ev in report.encoding_variants
    )

    # 2. Verify Authorization header bypasses shared cache
    auth_sample, _ = session.fetch(
        path,
        edge,
        region,
        extra_headers={
            "Authorization": "Nostr probe-bypass-check",
            "Accept-Encoding": "gzip",
        },
    )
    report.auth_bypass_cache_status = auth_sample.cache_status
    # Fail closed: require an HTTP response AND an explicit non-HIT cache-status header.
    report.auth_bypass_ok = (
        auth_sample.status is not None
        and auth_sample.cache_status is not None
        and not is_cache_hit(auth_sample.cache_status)
    )

    # 3. Cold miss measurement with a unique query parameter
    sep = "&" if "?" in path else "?"
    cold_path = f"{path}{sep}_probe_nocache={int(time.time() * 1000)}"
    cold_sample, _ = session.fetch(cold_path, edge, region, extra_headers={"Accept-Encoding": "gzip"})
    if cold_sample.error is None:
        report.cold_miss_ttfb_ms = round(cold_sample.ttfb_ms, 1)
        report.cold_miss_cache_status = cold_sample.cache_status

    return report


def decode_json_shape(raw: Optional[bytes], content_encoding: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    try:
        payload = gzip.decompress(raw) if (content_encoding or "").lower() == "gzip" else raw
        parsed = json.loads(payload.decode("utf-8"))
        if isinstance(parsed, dict):
            return f"object(keys={sorted(parsed.keys())[:8]})"
        if isinstance(parsed, list):
            return f"array(len={len(parsed)})"
        return type(parsed).__name__
    except Exception:  # noqa: BLE001
        return None


def parse_edge(spec: str) -> Tuple[str, str]:
    if "=" not in spec:
        raise argparse.ArgumentTypeError(f"--edge expects name=baseurl, got {spec!r}")
    name, base = spec.split("=", 1)
    if not name or not base.startswith(("http://", "https://")):
        raise argparse.ArgumentTypeError(f"--edge expects name=http(s)://host, got {spec!r}")
    return name, base.rstrip("/")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--edge", action="append", required=True, type=parse_edge, metavar="NAME=BASEURL")
    ap.add_argument("--path", action="append", required=True, metavar="/path")
    ap.add_argument("--baseline", required=True, help="edge name to compare others against")
    ap.add_argument("--region", default="unknown", help="label for where this probe is running")
    ap.add_argument("--iterations", type=int, default=15, help="measured fetches per path per edge")
    ap.add_argument("--warmup", type=int, default=2, help="unmeasured fetches per path per edge first")
    ap.add_argument("--margin-pct", type=float, default=20.0, help="allowed p95 TTFB regression")
    ap.add_argument("--floor-ms", type=float, default=DEFAULT_FLOOR_MS)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--no-reuse", action="store_true", help="force fresh connection per request")
    ap.add_argument("--host-header", help="override HTTP Host header on candidate requests")
    ap.add_argument(
        "--skip-contracts",
        action="store_true",
        help="skip Accept-Encoding / Authorization bypass / cold-miss checks",
    )
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON")
    args = ap.parse_args(argv)

    edges = dict(args.edge)
    if args.baseline not in edges:
        print(f"error: --baseline {args.baseline!r} is not one of {sorted(edges)}", file=sys.stderr)
        return 2

    by_edge: Dict[str, List[Sample]] = {name: [] for name in edges}
    connect_by_edge: Dict[str, List[float]] = {}
    contracts: Dict[str, ContractCheckReport] = {}
    shapes: Dict[str, Optional[str]] = {}

    for name, base in edges.items():
        host_hdr = args.host_header if (args.host_header and name != args.baseline) else None
        session = EdgeSession(base, args.timeout, reuse=not args.no_reuse, host_header=host_hdr)
        try:
            session.measure_connect()
            for idx, path in enumerate(args.path):
                for _ in range(max(0, args.warmup)):
                    session.fetch(path, name, args.region)
                for i in range(args.iterations):
                    capture = idx == 0 and i == 0
                    sample, body = session.fetch(path, name, args.region, capture_body=capture)
                    by_edge[name].append(sample)
                    if capture:
                        shapes[name] = decode_json_shape(body, sample.content_encoding)
            if not args.skip_contracts:
                contracts[name] = run_contract_checks(session, name, args.region, args.path[0])
        finally:
            connect_by_edge[name] = list(session.connect_samples)
            session.close()
        print(f"probed {name}: {len(by_edge[name])} samples", file=sys.stderr)

    summaries = {name: summarize(name, args.region, s) for name, s in by_edge.items()}
    for name, csamples in connect_by_edge.items():
        if csamples:
            summaries[name].connect_p50_ms = percentile(csamples, 50)
            summaries[name].connect_p95_ms = percentile(csamples, 95)

    baseline = summaries[args.baseline]
    verdicts = [
        compare_to_baseline(s, baseline, args.margin_pct, args.floor_ms)
        for name, s in summaries.items()
        if name != args.baseline
    ]

    width = max(len(n) for n in edges)
    print(
        f"\nregion={args.region}  baseline={args.baseline}  "
        f"margin={args.margin_pct:.0f}%  floor={args.floor_ms:.0f}ms\n"
    )
    print(
        f"{'edge'.ljust(width)}  {'connect':>8}  {'p50':>7}  {'p95':>7}  {'p99':>7}  {'err':>4}  {'cache':<18}  verdict"
    )
    for name, s in summaries.items():
        conn = f"{s.connect_p50_ms:.0f}ms" if s.connect_p50_ms is not None else "-"
        p50 = f"{s.ttfb_p50_ms:.0f}ms" if s.ttfb_p50_ms is not None else "-"
        p95 = f"{s.ttfb_p95_ms:.0f}ms" if s.ttfb_p95_ms is not None else "-"
        p99 = f"{s.ttfb_p99_ms:.0f}ms" if s.ttfb_p99_ms is not None else "-"
        cache_str = ",".join(f"{k}:{v}" for k, v in sorted(s.cache_statuses.items())) or "-"
        verdict = (
            "baseline"
            if name == args.baseline
            else next(v.verdict for v in verdicts if v.edge == name)
        )
        print(
            f"{name.ljust(width)}  {conn:>8}  {p50:>7}  {p95:>7}  {p99:>7}  {s.errors:>4}  {cache_str[:18]:<18}  {verdict}"
        )

    for v in verdicts:
        print(f"\n{v.edge}: {v.verdict} — {v.reason}")

    if contracts:
        print("\nContract checks (first path):")
        for name, report in contracts.items():
            shape = shapes.get(name) or "n/a"
            cold = (
                f"{report.cold_miss_ttfb_ms}ms ({report.cold_miss_cache_status or '-'})"
                if report.cold_miss_ttfb_ms is not None
                else "n/a"
            )
            auth = (
                f"{'OK' if report.auth_bypass_ok else 'FAIL'} ({report.auth_bypass_cache_status or '-'})"
                if report.auth_bypass_ok is not None
                else "n/a"
            )
            dedup = "n/a" if report.encoding_dedup_ok is None else ("OK" if report.encoding_dedup_ok else "FAIL")
            print(f"  {name}: shape={shape}  cold_miss={cold}  auth_bypass={auth}  ae_dedup={dedup}")
            for ev in report.encoding_variants:
                print(
                    f"    AE[{ev.label:<12}] status={ev.status} ce={ev.content_encoding or '-':<4} "
                    f"cache={ev.cache_status or '-':<8} bytes={ev.bytes_read:<7} ttfb={ev.ttfb_ms}ms"
                )

    if args.json:
        payload = {
            "region": args.region,
            "baseline": args.baseline,
            "margin_pct": args.margin_pct,
            "summaries": {k: asdict(v) for k, v in summaries.items()},
            "verdicts": [asdict(v) for v in verdicts],
            "contracts": {k: asdict(v) for k, v in contracts.items()},
            "shapes": shapes,
            "samples": {k: [asdict(s) for s in v] for k, v in by_edge.items()},
        }
        with open(args.json, "w") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nwrote {args.json}", file=sys.stderr)

    contracts_ok = all(
        report.auth_bypass_ok is True and report.encoding_dedup_ok is True
        for name, report in contracts.items()
        if name != args.baseline
    )
    return 0 if (all(v.verdict == "PASS" for v in verdicts) and contracts_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
