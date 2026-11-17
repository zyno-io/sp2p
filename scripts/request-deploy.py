#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Request a fixed sp2p deployment; production smoke confirms completion."""

import hashlib
import hmac
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def main():
    url = os.environ.get("DEPLOY_WEBHOOK_URL", "")
    secret = os.environ.get("DEPLOY_WEBHOOK_SECRET", "").rstrip("\n")
    version = os.environ.get("DEPLOY_VERSION", "")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("DEPLOY_WEBHOOK_URL must be an HTTPS URL without credentials, query, or fragment")
    if len(secret) < 32:
        raise ValueError("DEPLOY_WEBHOOK_SECRET must contain at least 32 characters")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?", version):
        raise ValueError("DEPLOY_VERSION must be a release version such as 0.7.1")

    body = json.dumps({"version": version, "timestamp": str(int(time.time()))}, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Sp2p-Signature": "sha256=" + signature,
        "User-Agent": "sp2p-release-deploy",
    })

    # A redirect must not forward the authenticated request to another endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    # Explicitly honor custom CA files on macOS LibreSSL as well as OpenSSL.
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or None)
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    with opener.open(request, timeout=30) as response:
        if response.status != 202:
            raise ValueError("Deployment endpoint did not return HTTP 202")
    print(f"Deployment of {version} requested; production smoke must confirm completion.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, urllib.error.URLError, TimeoutError) as error:
        # Do not print request headers, payloads, or server response bodies.
        if isinstance(error, urllib.error.HTTPError):
            print(f"Deployment request failed: HTTP {error.code}", file=sys.stderr)
        else:
            print("Deployment request failed: check configuration and HTTPS connectivity", file=sys.stderr)
        sys.exit(1)
