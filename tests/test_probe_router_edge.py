# ABOUTME: Unit tests for scripts/probe_router_edge.py using local HTTP servers and synthetic samples.
# ABOUTME: Offline only; validates percentile math, verdict gating, cache-status parsing, and contract probes.

import gzip
import http.server
import json
import threading
import unittest

import scripts.probe_router_edge as probe


class ProbeMathAndVerdictTests(unittest.TestCase):
    def test_percentile_interpolation(self):
        self.assertIsNone(probe.percentile([], 95))
        self.assertEqual(probe.percentile([42.0], 95), 42.0)
        self.assertAlmostEqual(probe.percentile([10.0, 20.0, 30.0, 40.0], 50), 25.0)
        self.assertAlmostEqual(probe.percentile([10.0, 20.0, 30.0, 40.0], 95), 38.5)

    def test_compare_to_baseline_respects_margin_floor_and_errors(self):
        base = probe.Summary("fastly", "us", n=10, errors=0, ttfb_p95_ms=20.0)
        within_margin = probe.Summary("bunny", "us", n=10, errors=0, ttfb_p95_ms=23.0)
        self.assertEqual(probe.compare_to_baseline(within_margin, base, 20.0).verdict, "PASS")

        fast_base = probe.Summary("fastly", "syd", n=10, errors=0, ttfb_p95_ms=3.0)
        within_floor = probe.Summary("bunny", "syd", n=10, errors=0, ttfb_p95_ms=8.0)
        self.assertEqual(probe.compare_to_baseline(within_floor, fast_base, 20.0, floor_ms=10.0).verdict, "PASS")

        too_slow = probe.Summary("bunny", "us", n=10, errors=0, ttfb_p95_ms=50.0)
        self.assertEqual(probe.compare_to_baseline(too_slow, base, 20.0, floor_ms=10.0).verdict, "FAIL")

        errored = probe.Summary("bunny", "us", n=10, errors=1, ttfb_p95_ms=15.0)
        self.assertEqual(probe.compare_to_baseline(errored, base, 20.0).verdict, "FAIL")

        total_outage = probe.Summary("bunny", "us", n=10, errors=10, ttfb_p95_ms=None)
        self.assertEqual(probe.compare_to_baseline(total_outage, base, 20.0).verdict, "FAIL")

        empty = probe.Summary("bunny", "us", n=0, errors=0, ttfb_p95_ms=None)
        self.assertEqual(probe.compare_to_baseline(empty, base, 20.0).verdict, "NO_DATA")

    def test_select_cache_status_and_is_cache_hit(self):
        self.assertEqual(
            probe.select_cache_status({"cdn-cache": "HIT", "x-cache": "MISS"}),
            "HIT",
        )
        self.assertTrue(probe.is_cache_hit("HIT"))
        self.assertTrue(probe.is_cache_hit("MISS, HIT"))
        self.assertFalse(probe.is_cache_hit("MISS"))
        self.assertFalse(probe.is_cache_hit("BYPASS"))
        self.assertFalse(probe.is_cache_hit(None))


class LocalHttpProbeTests(unittest.TestCase):
    def setUp(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            seen_paths = set()

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                auth = self.headers.get("Authorization")
                ae = self.headers.get("Accept-Encoding", "")
                if auth:
                    cache_state = "BYPASS"
                elif "_probe_nocache=" in self.path:
                    cache_state = "MISS"
                elif self.path in Handler.seen_paths:
                    cache_state = "HIT"
                else:
                    Handler.seen_paths.add(self.path)
                    cache_state = "MISS"

                raw = json.dumps({"videos": [1, 2, 3]}).encode("utf-8")
                if "gzip" in ae:
                    body = gzip.compress(raw)
                    ce = "gzip"
                else:
                    body = raw
                    ce = None

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("CDN-Cache", cache_state)
                if ce:
                    self.send_header("Content-Encoding", ce)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_contract_checks_and_json_shape(self):
        session = probe.EdgeSession(f"http://127.0.0.1:{self.port}", timeout=5.0, reuse=True)
        try:
            sample, body = session.fetch("/api/videos", "local", "test", capture_body=True)
            self.assertIsNone(sample.error)
            self.assertEqual(sample.status, 200)
            self.assertEqual(probe.decode_json_shape(body, sample.content_encoding), "object(keys=['videos'])")

            report = probe.run_contract_checks(session, "local", "test", "/api/videos")
            self.assertTrue(report.auth_bypass_ok)
            self.assertEqual(report.auth_bypass_cache_status, "BYPASS")
            self.assertEqual(report.cold_miss_cache_status, "MISS")
            self.assertEqual(len(report.encoding_variants), 4)
            self.assertTrue(report.encoding_dedup_ok)
        finally:
            session.close()

    def test_encoding_dedup_fails_when_cache_fragments_by_accept_encoding(self):
        class FragmentingHandler(http.server.BaseHTTPRequestHandler):
            seen = set()

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                key = (self.path, self.headers.get("Accept-Encoding", ""))
                state = "HIT" if key in FragmentingHandler.seen else "MISS"
                FragmentingHandler.seen.add(key)
                body = b'{"videos":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("CDN-Cache", "BYPASS" if self.headers.get("Authorization") else state)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FragmentingHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        session = probe.EdgeSession(f"http://127.0.0.1:{srv.server_address[1]}", timeout=5.0, reuse=True)
        try:
            report = probe.run_contract_checks(session, "local", "test", "/api/videos")
            self.assertTrue(report.auth_bypass_ok)
            self.assertFalse(report.encoding_dedup_ok)
        finally:
            session.close()
            srv.shutdown()
            srv.server_close()

    def test_auth_bypass_fails_closed_when_cache_header_missing(self):
        class NoCacheHeaderHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                body = b'{"videos":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NoCacheHeaderHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        session = probe.EdgeSession(f"http://127.0.0.1:{srv.server_address[1]}", timeout=5.0, reuse=True)
        try:
            report = probe.run_contract_checks(session, "local", "test", "/api/videos")
            self.assertFalse(report.auth_bypass_ok)
            self.assertIsNone(report.auth_bypass_cache_status)
            self.assertFalse(report.encoding_dedup_ok)
        finally:
            session.close()
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
