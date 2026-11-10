"""Offline deployment tests: all provider operations and health traffic are mocked."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import contextlib
import io
import json
import os


SPEC = importlib.util.spec_from_file_location("deploy", Path(__file__).parents[1] / "scripts/deploy.py")
deploy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(deploy)

SHA = "a" * 40
ENV = {
    "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push",
    "GITHUB_SHA": SHA, "GITHUB_REPOSITORY": "example/router", "GITHUB_RUN_ID": "123",
    "FASTLY_CD_ENABLED": "true", "FASTLY_API_TOKEN": "synthetic-test-placeholder",
    "FASTLY_SERVICE_ID": "ExampleService", "FASTLY_CUSTOMER_ID": "ExampleAccount",
    "GH_TOKEN": "synthetic-test-placeholder",
}
MANIFEST = {"service_id": "ExampleService", "setup": {"backends": {"origin": {}}}}


class Provider:
    def __init__(self):
        self.calls = []
        self.active = {"number": 7, "comment": "previous", "backends": [{"name": "origin"}],
                       "domains": [{"name": "example-service.edgecompute.app"}]}
        self.resources = [{"name": "divine-names", "resource_type": "kv-store"}]
        self.customer = "ExampleAccount"
        self.main = SHA
        self.valid = "ok"
        self.failure = None
        self.change_main_at_validate = False
        self.change_active_at_validate = False
        self.ignore_activation = False
        self.retain_package = True

    def __call__(self, base, path, token, method="GET", data=None, content_type=None):
        self.calls.append((method, path))
        if self.failure == (method, path.rsplit("/", 1)[-1]):
            raise deploy.DeploymentError("synthetic provider failure")
        if base == "https://api.github.com":
            return {"object": {"sha": self.main}}
        if path.endswith("/details"):
            return {"customer_id": self.customer, "active_version": copy.deepcopy(self.active)}
        if path.endswith("/resource"):
            return self.resources
        if path.endswith("/clone"):
            assert path.endswith("/7/clone")  # never latest editable version
            return {"number": 8}
        if path.endswith("/package"):
            if method == "PUT":
                assert b'name="package"' in data and b"checked-package" in data
                return {"id": "uploaded-package"}
            return {"id": "uploaded-package" if self.retain_package else "old-package"}
        if path.endswith("/validate"):
            if self.change_main_at_validate:
                self.main = "b" * 40
            if self.change_active_at_validate:
                self.active["number"] = 9
            return {"status": self.valid}
        if path.endswith("/activate"):
            if not self.ignore_activation:
                self.active.update(number=8, comment=self.comment)
            return self.active
        if path.endswith("/purge_all"):
            return {"status": "ok"}
        if method == "PUT" and path.endswith("/8"):
            self.comment = deploy.urllib.parse.parse_qs(data.decode())["comment"][0]
            return {"number": 8}
        raise AssertionError((method, path))


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.provider = Provider()
        self.deployer = deploy.Deployer(dict(ENV), self.provider)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.package = Path(self.tmp.name) / "package.tar.gz"
        self.package.write_bytes(b"checked-package")

    def run_deploy(self):
        with patch.object(self.deployer, "health"):
            self.deployer.deploy(MANIFEST, self.package)

    def assert_no_writes(self):
        self.assertFalse([c for c in self.provider.calls if c[0] != "GET"])

    def test_success_records_source_version_and_package(self):
        self.run_deploy()
        self.assertEqual(self.deployer.receipt["result"], "success")
        self.assertEqual(self.deployer.receipt["source_sha"], SHA)
        self.assertEqual(self.deployer.receipt["previous_version"], 7)
        self.assertEqual(self.deployer.receipt["provider_version"], 8)
        self.assertEqual(self.deployer.receipt["package_id"], "uploaded-package")
        self.assertEqual(self.provider.active["comment"], f"git:{SHA} run:123")

    def test_disallowed_events_refs_and_disabled_cd_never_write(self):
        for setting, value in [("GITHUB_REF", "refs/heads/topic"), ("GITHUB_REF", "refs/pull/1/merge"),
                               ("GITHUB_EVENT_NAME", "pull_request"), ("FASTLY_CD_ENABLED", ""),
                               ("FASTLY_SERVICE_ID", "WrongService"), ("FASTLY_API_TOKEN", ""),
                               ("GITHUB_SHA", "not-a-sha")]:
            with self.subTest(setting=setting, value=value):
                self.deployer.env = dict(ENV, **{setting: value})
                with self.assertRaises(deploy.DeploymentError):
                    self.run_deploy()
                self.assert_no_writes()

    def test_manual_main_replay_is_allowed(self):
        self.deployer.env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        self.run_deploy()
        self.assertEqual(self.deployer.receipt["result"], "success")

    def test_stale_commit_never_writes(self):
        self.provider.main = "b" * 40
        with self.assertRaisesRegex(deploy.DeploymentError, "superseded"):
            self.run_deploy()
        self.assert_no_writes()

    def test_account_backends_and_kv_are_required(self):
        cases = [("customer", "WrongAccount"), ("resources", []),
                 ("resources", [{"name": "usernames", "resource_type": "kv-store"}]),
                 ("resources", [{"name": "divine-names", "resource_type": "secret-store"}])]
        for name, value in cases:
            with self.subTest(name=name):
                self.provider = Provider()
                setattr(self.provider, name, value)
                self.deployer.api = self.provider
                with self.assertRaises(deploy.DeploymentError):
                    self.run_deploy()
                self.assert_no_writes()
        self.provider = Provider()
        self.provider.active["backends"] = []
        self.deployer.api = self.provider
        with self.assertRaisesRegex(deploy.DeploymentError, "backends"):
            self.run_deploy()
        self.assert_no_writes()

    def test_failed_prerequisites_after_upload_never_activate(self):
        for name, value in [("valid", "error"), ("change_main_at_validate", True),
                            ("change_active_at_validate", True), ("retain_package", False)]:
            with self.subTest(name=name):
                self.provider = Provider()
                setattr(self.provider, name, value)
                self.deployer.api = self.provider
                with self.assertRaises(deploy.DeploymentError):
                    self.run_deploy()
                self.assertFalse(any(p.endswith("/activate") for _, p in self.provider.calls))

    def test_provider_write_failure_is_not_retried_or_successful(self):
        for method, suffix in [("PUT", "clone"), ("PUT", "package"), ("PUT", "8"),
                               ("PUT", "activate"), ("POST", "purge_all")]:
            with self.subTest(suffix=suffix):
                self.provider = Provider()
                self.provider.failure = (method, suffix)
                self.deployer = deploy.Deployer(dict(ENV), self.provider)
                with self.assertRaisesRegex(deploy.DeploymentError, "provider failure"):
                    self.run_deploy()
                self.assertEqual(self.deployer.receipt["result"], "failed")
                self.assertEqual(sum(m == method and p.endswith("/" + suffix)
                                     for m, p in self.provider.calls), 1)

    def test_activation_must_be_observed(self):
        self.provider.ignore_activation = True
        with self.assertRaisesRegex(deploy.DeploymentError, "active version"):
            self.run_deploy()
        self.assertEqual(self.deployer.receipt["result"], "failed")
        self.assertFalse(any(p.endswith("/purge_all") for _, p in self.provider.calls))

    def test_health_failure_is_not_success(self):
        with patch.object(self.deployer, "health", side_effect=deploy.DeploymentError("health failed")):
            with self.assertRaisesRegex(deploy.DeploymentError, "health failed"):
                self.deployer.deploy(MANIFEST, self.package)
        self.assertEqual(self.deployer.receipt["result"], "failed")
        self.assertEqual(self.deployer.receipt["provider_version"], 8)

    def test_health_is_head_only_bounded_and_does_not_follow_redirects(self):
        self.deployer.health_url = "https://example-service.edgecompute.app/"
        with patch.object(deploy.urllib.request, "build_opener") as opener, patch.object(deploy.time, "sleep"):
            opener.return_value.open.side_effect = urllib.error.HTTPError("url", 302, "redirect", {}, None)
            with self.assertRaises(deploy.DeploymentError):
                self.deployer.health()
            self.assertEqual(opener.return_value.open.call_count, 6)
            request = opener.return_value.open.call_args.args[0]
            self.assertEqual(request.method, "HEAD")
            self.assertIsNone(opener.call_args.args[0].redirect_request(None, None, 302, "", {}, "https://other/"))

    def test_api_error_is_redacted_and_redirects_are_disabled(self):
        with patch.object(deploy.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError(
                "https://api.fastly.com/", 403, "synthetic-sensitive-provider-body", {}, None)
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.request_json("https://api.fastly.com", "/service/test", "synthetic-sensitive-token")
            self.assertNotIn("synthetic-sensitive", str(caught.exception))
            self.assertIn("HTTP 403", str(caught.exception))
            self.assertIsNone(opener.call_args.args[0].redirect_request(None, None, 302, "", {}, "https://other/"))

    def test_main_failure_still_writes_failure_receipt(self):
        previous = os.getcwd()
        try:
            os.chdir(self.tmp.name)
            Path("fastly.toml").write_text('service_id = "ExampleService"\n')
            with patch.dict(os.environ, {"GITHUB_REF": "refs/heads/topic"}, clear=True):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(deploy.main(), 1)
            self.assertEqual(json.loads(Path("deployment.json").read_text())["result"], "failed")
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
