# HTTPS deployment hook

The release workflow publishes signed artifacts and the server image, then sends
an authenticated HTTPS request to a separate deployment sidecar. The sidecar
uses the host's Docker socket to update the existing `sp2p` Compose service.
sp2p's existing HTTPS listener forwards only this hook path to the private
sidecar. SSH remains private to Tailscale, and Tailnet Lock needs no changes.

The sidecar uses [webhook](https://github.com/adnanh/webhook), Docker CLI, and
Compose. Its Docker socket access gives it control of the host's containers;
the deployment secret therefore grants administrative access.

## Request and deployment behavior

`POST /hooks/sp2p-deploy` accepts a JSON object containing a release `version`
(for example, `0.7.1`) and a Unix `timestamp` string. `X-Sp2p-Signature` must
contain `sha256=` followed by the hexadecimal HMAC-SHA256 of the exact body,
using the shared deployment secret. The worker refuses requests older than
five minutes or more than 30 seconds in the future.

The only operation is the equivalent of:

```sh
docker compose up --detach --no-deps --no-build --pull always sp2p
```

A temporary Compose override selects
`ghcr.io/zyno-io/sp2p-server:<version>`. The production Compose file still owns
the service's environment, ports, volumes, and other settings. Requests cannot
select another image repository, service, command, or Compose file. The sidecar
does not update itself, the reverse proxy, or TURN services.

HTTP 202 means the authenticated request was accepted for execution, **not**
that deployment succeeded. The existing production smoke workflow waits for
the exact release version and web bundle, then tests real transfers. A failed
worker command leaves smoke failing rather than reporting a successful deploy.
Worker output is available through the sidecar's container logs.

A file lock prevents overlapping deployments. The Docker command has a
ten-minute limit. The release and manual deployment workflows also share a
concurrency group, with cancellation disabled, through production smoke.

## One-time installation

Install the sidecar through an existing trusted Tailscale connection. The host
must have an existing production Compose service named `sp2p`. The repository's
root `docker-compose.yml` is a local development example; use the actual
production file on the server.

1. Copy [deploy/webhook](../deploy/webhook/) to a separate directory on the
   server, such as `/opt/sp2p-deploy`.
2. Generate a private secret outside the source checkout:

   ```sh
   install -d -m 700 /etc/sp2p-deploy
   (umask 077; openssl rand -hex 32 > /etc/sp2p-deploy/secret)
   ```

3. Configure the sidecar's deployment target and start it:

   ```sh
   export SP2P_DEPLOY_SECRET_FILE=/etc/sp2p-deploy/secret
   export SP2P_DEPLOY_DIR=/opt/sp2p
   export SP2P_DEPLOY_COMPOSE_FILE=docker-compose.yml
   docker compose -f /opt/sp2p-deploy/compose.yml up -d --build
   ```

   Set the directory and filename to the actual production installation. The
   directory is mounted read-only at the identical absolute path inside the
   sidecar, preserving relative bind-mount resolution. Compose reads the
   production `.env` and project name as it did when run through SSH. Include
   any additional configuration files referenced by that production file.

4. Set `SP2P_DEPLOY_WEBHOOK_URL=http://sp2p-deploy:9000` in the existing
   production `sp2p` service's environment. This enables only
   `POST /hooks/sp2p-deploy`, limits its body to 4 KiB, and forwards the exact
   signed bytes. The route is disabled by default. Existing TLS/ACME settings
   remain authoritative; the application never receives the Docker socket or
   deployment secret.

   The sidecar joins the existing `sp2p_default` Docker network with the alias
   `sp2p-deploy`, and publishes no host ports. Set `SP2P_DEPLOY_NETWORK` to the
   actual production network name if different. No separate HTTPS proxy or
   public SSH access is required.

5. In the GitHub `release` environment, store the same secret as
   `DEPLOY_WEBHOOK_SECRET`, and set the environment variable
   `DEPLOY_WEBHOOK_URL` to `https://sp2p.io/hooks/sp2p-deploy`. Keep the secret
   out of source control, URLs, and logs. Old SSH deployment secrets are no
   longer used by the updated release workflow.
6. Allow the `main` branch in the environment's deployment branch policies
   for the manual deployment workflow, retaining its existing `v*` tag rule.
   Use the environment's existing approval policy for deployments.

The forwarding route requires server 0.7.2 or newer. For the initial upgrade
from a server without it, publish the new image first, then run the fixed
worker once through trusted Tailscale SSH:

```sh
docker compose -f /opt/sp2p-deploy/compose.yml exec -T deploy \
    /usr/local/bin/sp2p-deploy 0.7.2 "$(date +%s)"
```

This applies the configured server environment along with the new image,
bringing the public HTTPS forwarding route online. Run the manual deployment
workflow to verify the HTTPS path and production smoke, or re-run a release's
failed deployment job after bootstrap so its smoke job completes. Keep release
tags unchanged.

## Deploy an already published release

Run [Deploy published release](../.github/workflows/deploy.yml) from `main`,
providing a full release tag such as `v0.7.1`. It verifies that the GitHub
Release is published, requests that exact server image version, and runs the
production smoke workflow. It neither rebuilds artifacts nor publishes OS
packages. This path can also deploy an older published image for a rollback.
Rolling back to a server older than 0.7.2 removes the forwarding route; use
the trusted SSH bootstrap command to upgrade again in that case.

Future full releases invoke the same HTTPS request helper automatically after
publication. A server-only release requests deployment but still needs the
separate production smoke workflow with a suitable CLI tag, as before.

## Local verification

```sh
docker build -t sp2p-deploy-hook:test deploy/webhook
python3 deploy/webhook/test_webhook.py
```

The tests run the actual sidecar with a fake Docker executable and **no Docker
socket** mounted. They exercise signed requests, rejection of invalid requests,
request age, deployment serialization, command failure cleanup, the fixed
service/image selection, and the caller's HTTPS certificate and redirect
handling. Test containers, generated certificates, and scratch files are
removed afterward.
