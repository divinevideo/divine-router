# ABOUTME: Offline tests for bunny/deploy_bunny.py using a fake Bunny API client.
# ABOUTME: Covers the script-type guard and the cache-bypass Edge Rules it reconciles.

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "deploy_bunny", Path(__file__).resolve().parent.parent / "bunny" / "deploy_bunny.py"
)
deploy_bunny = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(deploy_bunny)


class FakeClient:
    def __init__(self, scripts=None, pull_zone=None, variables=None):
        self.scripts = scripts or []
        self.pull_zone = pull_zone or {"Id": 7, "Hostnames": [], "EdgeRules": []}
        self.variables = variables or []
        self.calls = []

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/compute/script":
            return {"Items": self.scripts}
        if method == "GET" and path.startswith("/compute/script/"):
            return {"Id": 1, "Name": "x", "EdgeScriptVariables": self.variables, "LinkedPullZones": [{"Id": 7}]}
        if method == "GET" and path.startswith("/pullzone/"):
            return self.pull_zone
        return {}


class DeployBunnyTests(unittest.TestCase):
    def test_adds_and_updates_variables_with_bunny_schema(self):
        client = FakeClient(variables=[{"Id": 9, "Name": "PUBLIC_HOST_OVERRIDE"}])
        deploy_bunny.upsert_env_vars(client, 1, {
            "PUBLIC_HOST_OVERRIDE": "api.divine.video",
            "EVALUATION_LABEL": "test",
        })
        self.assertEqual(client.calls, [
            ("GET", "/compute/script/1", None),
            ("POST", "/compute/script/1/variables/9", {"DefaultValue": "api.divine.video"}),
            ("POST", "/compute/script/1/variables/add", {
                "Name": "EVALUATION_LABEL", "Required": False, "DefaultValue": "test",
            }),
        ])

    def _run(self, client, mode):
        with tempfile.NamedTemporaryFile("w", suffix=".js") as bundle:
            bundle.write("export default {}")
            bundle.flush()
            with mock.patch.object(deploy_bunny, "load_api_key", return_value="k"), mock.patch.object(
                deploy_bunny, "BunnyClient", return_value=client
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return deploy_bunny.main(["--name", "x", "--mode", mode, "--bundle", bundle.name])

    def test_refuses_to_overwrite_script_of_other_type(self):
        client = FakeClient(scripts=[{"Id": 1, "Name": "x", "ScriptType": 1}])
        self.assertEqual(self._run(client, "middleware"), 2)
        self.assertFalse(any(path.endswith("/code") for _, path, _ in client.calls))

    def test_reuses_script_of_matching_type_and_reconciles_rules(self):
        client = FakeClient(scripts=[{"Id": 1, "Name": "x", "ScriptType": 1}])
        self.assertEqual(self._run(client, "standalone"), 0)
        settings = next(body for method, path, body in client.calls if method == "POST" and path == "/pullzone/7")
        self.assertIs(settings["EnableWebSockets"], True)
        self.assertNotIn("EnableWebSocket", settings)
        rules = [body for method, path, body in client.calls if path.endswith("/edgerules/addOrUpdate")]
        descriptions = [r["Description"] for r in rules]
        self.assertEqual(len(descriptions), len(set(descriptions)))
        patterns = [p for r in rules for t in r["Triggers"] for p in t.get("PatternMatches", [])]
        for route in (
            "*://*/v1/account/moderation-status?*",
            "*://www.divine.video/api/links?*",
            "*://divine.video/l?*",
            "*://*/api/users/*/recommendations?*followed_hashtags*",
            "*://*/api/users/*/recommendations?*preferred_languages*",
            "*://*/api/users/*/recommendations?*seed*",
        ):
            self.assertIn(route, patterns)
        header_triggers = [
            (r["ActionType"], r["ActionParameter1"], t.get("Parameter1"))
            for r in rules
            for t in r["Triggers"]
            if t.get("Type") == 1
        ]
        self.assertIn((3, "0", "X-Pubkey"), header_triggers)
        self.assertIn((5, "Cache-Control", "X-Pubkey"), header_triggers)


if __name__ == "__main__":
    unittest.main()
