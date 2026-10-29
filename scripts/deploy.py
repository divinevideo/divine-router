"""Deploy one checked main commit to the existing Fastly service.

Invoked only by the production workflow. No automatic rollback or write retries:
an ambiguous provider response must be inspected before an operator replays it.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request


class DeploymentError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(base, path, token, method="GET", data=None, content_type=None):
    headers = {"Accept": "application/json"}
    if base == "https://api.fastly.com":
        headers["Fastly-Key"] = token
    else:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if content_type:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Do not print response bodies, request headers or credential values.
        status = error.code
        error.close()
        raise DeploymentError(f"{method} {path}: HTTP {status}") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise DeploymentError(f"{method} {path}: request failed; inspect provider state") from None


class Deployer:
    def __init__(self, env, api=request_json):
        self.env = env
        self.api = api
        self.receipt = {"environment": "production", "result": "failed"}

    def fastly(self, path, method="GET", data=None, content_type=None):
        return self.api("https://api.fastly.com", path, self.env["FASTLY_API_TOKEN"],
                        method, data, content_type)

    def current_main(self):
        repo = self.env["GITHUB_REPOSITORY"]
        data = self.api("https://api.github.com", f"/repos/{repo}/git/ref/heads/main",
                        self.env["GH_TOKEN"])
        if data["object"]["sha"] != self.env["GITHUB_SHA"]:
            raise DeploymentError("Refusing superseded commit: main has moved")

    def preflight(self, manifest):
        if (self.env.get("GITHUB_REF") != "refs/heads/main"
                or self.env.get("GITHUB_EVENT_NAME") not in {"push", "workflow_dispatch"}):
            raise DeploymentError("Production requires a push or manual run on main")
        if self.env.get("FASTLY_CD_ENABLED") != "true":
            raise DeploymentError("Production CD prerequisites have not been enabled")
        for name in ("FASTLY_API_TOKEN", "FASTLY_SERVICE_ID", "FASTLY_CUSTOMER_ID", "GH_TOKEN"):
            if not self.env.get(name):
                raise DeploymentError(f"Missing required setting: {name}")
        if not re.fullmatch(r"[0-9a-f]{40}", self.env.get("GITHUB_SHA", "")):
            raise DeploymentError("Invalid source SHA")
        self.service = self.env["FASTLY_SERVICE_ID"]
        if self.service != manifest["service_id"] or not re.fullmatch(r"[A-Za-z0-9]+", self.service):
            raise DeploymentError("Service must match the existing manifest association")
        self.current_main()
        details = self.fastly(f"/service/{self.service}/details")
        if details["customer_id"] != self.env["FASTLY_CUSTOMER_ID"]:
            raise DeploymentError("Service account does not match the confirmed account")
        active = details["active_version"]
        required = set(manifest["setup"]["backends"])
        if not required.issubset({backend["name"] for backend in active["backends"]}):
            raise DeploymentError("Active version is missing required static backends")
        resources = self.fastly(f"/service/{self.service}/version/{active['number']}/resource")
        if not any(r["name"] == "usernames" and r["resource_type"] == "kv-store" for r in resources):
            raise DeploymentError("Active version is missing the usernames KV binding")
        # Probe this service's existing default domain, not a user-controlled URL.
        domains = [d["name"] for d in active["domains"]
                   if re.fullmatch(r"[a-z0-9-]+\.edgecompute\.app", d["name"])]
        if len(domains) != 1:
            raise DeploymentError("Expected one existing Fastly default domain")
        self.health_url = f"https://{domains[0]}/"
        self.previous = active["number"]
        self.receipt.update(source_sha=self.env["GITHUB_SHA"], service_id=self.service,
                            previous_version=self.previous, health_url=self.health_url,
                            run_url=(f"https://github.com/{self.env['GITHUB_REPOSITORY']}/actions/runs/"
                                     f"{self.env['GITHUB_RUN_ID']}"))

    def deploy(self, manifest, package):
        self.preflight(manifest)
        package_bytes = Path(package).read_bytes()
        self.receipt["package_sha256"] = hashlib.sha256(package_bytes).hexdigest()
        prefix = f"/service/{self.service}/version"
        # Clone the active version so an unrelated editable draft is never activated.
        version = self.fastly(f"{prefix}/{self.previous}/clone", "PUT")["number"]
        self.receipt["provider_version"] = version
        path = f"{prefix}/{version}"
        boundary = "----divine-router-package-" + self.receipt["package_sha256"]
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"package\"; "
                'filename="package.tar.gz"\r\nContent-Type: application/gzip\r\n\r\n').encode()
        body += package_bytes + f"\r\n--{boundary}--\r\n".encode()
        uploaded = self.fastly(f"{path}/package", "PUT", body, f"multipart/form-data; boundary={boundary}")
        package_id = uploaded["id"]
        if not package_id or self.fastly(f"{path}/package")["id"] != package_id:
            raise DeploymentError("Uploaded package was not retained on the target version")
        self.receipt["package_id"] = package_id
        comment = f"git:{self.env['GITHUB_SHA']} run:{self.env['GITHUB_RUN_ID']}"
        self.fastly(path, "PUT", urllib.parse.urlencode({"comment": comment}).encode(),
                    "application/x-www-form-urlencoded")
        if self.fastly(f"{path}/validate").get("status") != "ok":
            raise DeploymentError("Fastly version validation failed")
        self.current_main()
        # Refuse an intervening out-of-band activation instead of overwriting it.
        if self.fastly(f"/service/{self.service}/details")["active_version"]["number"] != self.previous:
            raise DeploymentError("Active version changed during preparation")
        self.fastly(f"{path}/activate", "PUT")
        self.receipt["activation_requested"] = True
        self.verify_active(version, comment)
        self.fastly(f"/service/{self.service}/purge_all", "POST")
        self.health()
        self.verify_active(version, comment)
        self.receipt["result"] = "success"

    def verify_active(self, version, comment):
        active = self.fastly(f"/service/{self.service}/details")["active_version"]
        if active["number"] != version or active["comment"] != comment:
            raise DeploymentError("Production active version/source marker does not match")

    def health(self):
        # HEAD only, bounded retries, no redirects or side-effecting test traffic.
        opener = urllib.request.build_opener(NoRedirect())
        for attempt in range(6):
            try:
                with opener.open(urllib.request.Request(self.health_url, method="HEAD"), timeout=15) as response:
                    if response.status == 200:
                        self.receipt["health_status"] = 200
                        return
            except urllib.error.HTTPError as error:
                error.close()
            except (urllib.error.URLError, TimeoutError):
                pass
            if attempt < 5:
                time.sleep(10)
        raise DeploymentError("Production HEAD probe did not return 200")


def main():
    deployer = Deployer(os.environ)
    try:
        manifest = tomllib.loads(Path("fastly.toml").read_text())
        deployer.deploy(manifest, "pkg/divine-router.tar.gz")
    except (DeploymentError, KeyError, OSError, ValueError) as error:
        # Unexpected data errors are deliberately generic; never dump provider data.
        print(str(error) if isinstance(error, DeploymentError) else "Deployment failed: invalid data or local I/O", file=sys.stderr)
        return 1
    finally:
        Path("deployment.json").write_text(json.dumps(deployer.receipt, indent=2) + "\n")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as output:
                output.write("## Fastly production deployment\n```json\n"
                             + json.dumps(deployer.receipt, indent=2) + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
