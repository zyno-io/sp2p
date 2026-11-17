#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the actual sidecar and HTTPS caller without mounting a Docker socket."""

import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if check and result.returncode:
        raise RuntimeError(result.stderr)
    return result


class DeployHookTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Docker on macOS may share the workspace but not the system temp dir.
        cls.scratch = tempfile.TemporaryDirectory(prefix=".sp2p-hook-test-", dir=Path.cwd())
        cls.root = Path(cls.scratch.name)
        cls.secret = secrets.token_hex(32) + '"\\'
        (cls.root / "secret").write_text(cls.secret)
        (cls.root / "docker-compose.yml").write_text("services: {sp2p: {image: example.invalid/unused}}\n")
        stub = cls.root / "docker"
        stub.write_text("""#!/bin/sh
set -eu
printf '%s\\n' "$@" > /test/args
for arg do
    case "$arg" in /run/sp2p-deploy-override.*) cp "$arg" /test/override.json ;; esac
done
touch /test/started
while [ -f /test/block ]; do sleep 0.05; done
if [ -f /test/fail ]; then exit 17; fi
""")
        stub.chmod(0o755)
        cls.container = "sp2p-hook-test-" + secrets.token_hex(6)
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.addClassCleanup(lambda: docker("rm", "-f", cls.container, check=False))
        docker("run", "-d", "--name", cls.container, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--tmpfs", "/run", "--tmpfs", "/tmp",
               "-p", "127.0.0.1::9000", "-e", "SP2P_DEPLOY_DIR=/test",
               "-v", f"{cls.root}:/test", "-v", f"{stub}:/usr/local/bin/docker:ro",
               "-v", f"{cls.root / 'secret'}:/run/secrets/deploy_secret:ro",
               os.environ.get("DEPLOY_HOOK_TEST_IMAGE", "sp2p-deploy-hook:test"))
        port_result = docker("port", cls.container, "9000/tcp")
        cls.url = "http://" + port_result.stdout.strip() + "/hooks/sp2p-deploy"
        cls.wait_until(lambda: cls.request(b"{}", signed=False)[0] != 0)

        cls.cert = cls.root / "cert.pem"
        key = cls.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-keyout", str(key), "-out", str(cls.cert)],
                       check=True, capture_output=True)
        owner = cls

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path == "/redirect":
                    self.send_response(307)
                    self.send_header("Location", owner.https_url)
                    self.end_headers()
                    return
                body = self.rfile.read(int(self.headers["Content-Length"]))
                status, data = owner.request(body, signature=self.headers.get("X-Sp2p-Signature", ""))
                self.send_response(status)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        cls.proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.proxy.socket = context.wrap_socket(cls.proxy.socket, server_side=True)
        cls.https_url = f"https://127.0.0.1:{cls.proxy.server_port}/hooks/sp2p-deploy"
        threading.Thread(target=cls.proxy.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.proxy.server_close)
        cls.addClassCleanup(cls.proxy.shutdown)

    @classmethod
    def request(cls, body, signed=True, signature=None, method="POST"):
        headers = {"Content-Type": "application/json"}
        if signature is not None:
            headers["X-Sp2p-Signature"] = signature
        elif signed:
            headers["X-Sp2p-Signature"] = "sha256=" + hmac.new(cls.secret.encode(), body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(cls.url, data=body if method == "POST" else None,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except urllib.error.URLError:
            return 0, b""

    @staticmethod
    def wait_until(predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError("Timed out waiting for the test sidecar")

    def setUp(self):
        for name in ["block", "fail", "started", "args", "override.json"]:
            (self.root / name).unlink(missing_ok=True)

    def tearDown(self):
        (self.root / "block").unlink(missing_ok=True)
        self.wait_until(lambda: docker("exec", self.container, "flock", "-n", "/run/sp2p-deploy.lock", "true", check=False).returncode == 0)

    def payload(self, version="0.7.1", timestamp=None):
        return json.dumps({"version": version, "timestamp": str(timestamp or int(time.time()))}).encode()

    def assert_no_deploy(self):
        time.sleep(0.2)
        self.assertFalse((self.root / "started").exists())

    def test_unsigned_and_tampered_requests_cannot_deploy(self):
        body = self.payload()
        self.assertNotEqual(self.request(body, signed=False)[0], 202)
        self.assertNotEqual(self.request(body, signature="sha256=" + "0" * 64)[0], 202)
        self.assert_no_deploy()

    def test_get_cannot_deploy(self):
        self.assertEqual(self.request(self.payload(), method="GET")[0], 405)
        self.assert_no_deploy()

    def test_request_cannot_choose_a_repository_or_shell_command(self):
        for version in ["latest", "other/image:1.0.0", "0.7.1;touch /test/pwned", "0.7.1\n--privileged"]:
            self.assertNotEqual(self.request(self.payload(version))[0], 202)
        self.assert_no_deploy()

    def test_stale_and_future_requests_cannot_deploy(self):
        for timestamp in [int(time.time()) - 600, int(time.time()) + 600]:
            self.request(self.payload(timestamp=timestamp))
        self.assert_no_deploy()

    def test_signed_request_updates_only_the_fixed_service_and_image(self):
        self.assertEqual(self.request(self.payload())[0], 202)
        self.wait_until(lambda: (self.root / "started").exists())
        args = (self.root / "args").read_text().splitlines()
        self.assertEqual(args[:5], ["compose", "--project-directory", "/test", "--file", "docker-compose.yml"])
        self.assertEqual(args[-7:], ["up", "--detach", "--no-deps", "--no-build", "--pull", "always", "sp2p"])
        override = json.loads((self.root / "override.json").read_text())
        self.assertEqual(override, {"services": {"sp2p": {"image": "ghcr.io/zyno-io/sp2p-server:0.7.1"}}})

    def test_concurrent_request_does_not_start_a_second_deploy(self):
        (self.root / "block").touch()
        self.request(self.payload())
        self.wait_until(lambda: (self.root / "started").exists())
        (self.root / "started").unlink()
        self.request(self.payload("0.7.0"))
        self.assert_no_deploy()
        override = json.loads((self.root / "override.json").read_text())
        self.assertTrue(override["services"]["sp2p"]["image"].endswith(":0.7.1"))

    def test_failed_command_releases_lock_and_removes_override(self):
        (self.root / "fail").touch()
        result = docker("exec", self.container, "/usr/local/bin/sp2p-deploy", "0.7.1", str(int(time.time())), check=False)
        self.assertEqual(result.returncode, 17, result.stderr)
        remaining = docker("exec", self.container, "find", "/run", "-name", "sp2p-deploy-override.*")
        self.assertEqual(remaining.stdout.strip(), "")

    def caller(self, url=None, trust=True):
        env = dict(os.environ, DEPLOY_WEBHOOK_URL=url or self.https_url,
                   DEPLOY_WEBHOOK_SECRET=self.secret, DEPLOY_VERSION="0.7.1")
        if trust:
            env["SSL_CERT_FILE"] = str(self.cert)
        script = Path(__file__).resolve().parents[2] / "scripts" / "request-deploy.py"
        return subprocess.run(["python3", str(script)], env=env, capture_output=True, text=True)

    def test_production_caller_signs_request_over_verified_https(self):
        result = self.caller()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.wait_until(lambda: (self.root / "started").exists())

    def test_production_caller_rejects_http_redirects_and_untrusted_tls(self):
        for url, trust in [(self.url, True), (self.https_url, False),
                           (self.https_url.replace("/hooks/sp2p-deploy", "/redirect"), True)]:
            result = self.caller(url, trust)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(self.secret, result.stdout + result.stderr)
        self.assert_no_deploy()


if __name__ == "__main__":
    unittest.main()
