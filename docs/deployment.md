# HTTPS deployment hook

The release workflow publishes signed artifacts and the server image, then sends
an authenticated HTTPS request to a separate deployment sidecar. The sidecar
uses the host's Docker socket to update the existing `sp2p` Compose service.
The sidecar publishes no host ports; the Cloudflare Tunnel connector reaches it
over a Docker network and routes the public hook path to it. sp2p itself has
no knowledge of the hook. SSH
remains private to Tailscale, and Tailnet Lock needs no changes.

The sidecar uses [webhook](https://github.com/adnanh/webhook), Docker CLI, and
Compose. Its Docker socket access gives it control of the host's containers;
the deployment secret therefore grants administrative access.

webhook reads whole request bodies before checking signatures and has no size
limit, so the tunnel never reaches it directly. A small gate container
([deploy/webhook/gate](../deploy/webhook/gate/)) is the only listener on the
shared network. It accepts only `POST /hooks/sp2p-deploy`, rejects bodies over
4 KiB with 413, times out slow clients, holds at most 32 connections open, and forwards the rest to webhook over a
private internal network. The gate has no shell, Docker socket, or secret.

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
After a successful update, the local `:latest` alias points to the deployed
image too, so a manual Compose restart uses the same image. The production
service's base image should remain `ghcr.io/zyno-io/sp2p-server:latest`.

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

   The gate joins the Docker network named by `SP2P_DEPLOY_NETWORK`
   (default `sp2p_default`) with the alias `sp2p-deploy`; neither container
   publishes host ports. Set it to the network the tunnel connector shares
   with sp2p. The webhook container is attached only to the gate's internal
   network, which has no outbound access; the host's Docker daemon still pulls
   images. Both containers are memory-capped as defense in depth.

4. Route the hook path through the Cloudflare Tunnel. Production runs a
   standalone cloudflared container that joins a dedicated network shared with
   the `sp2p` service and the sidecar, so routes use container names. Put the
   exact path **above** the catch-all `sp2p.io` route, since cloudflared uses
   the first match:

   ```yaml
   ingress:
     - hostname: sp2p.io
       path: ^/hooks/sp2p-deploy$
       service: http://sp2p-deploy:9000
     - hostname: sp2p.io
       service: http://sp2p:8080
     - service: http_status:404
   ```

   For a dashboard-managed tunnel, add the equivalent routes in that order.
   sp2p serves plain HTTP behind the tunnel; set `SP2P_TRUSTED_PROXIES` to the
   shared network's subnet so rate limits see real client addresses.
   The tunnel forwards the signed body unchanged. The application never
   receives the Docker socket, the deployment secret, or the hook traffic.

5. In the GitHub `release` environment, store the same secret as
   `DEPLOY_WEBHOOK_SECRET`, and set the environment variable
   `DEPLOY_WEBHOOK_URL` to `https://sp2p.io/hooks/sp2p-deploy`. Keep the secret
   out of source control, URLs, and logs. Old SSH deployment secrets are no
   longer used by the updated release workflow.
6. Allow the `main` branch in the environment's deployment branch policies
   for the manual deployment workflow, retaining its existing `v*` tag rule.
   Use the environment's existing approval policy for deployments.

The hook path is independent of the sp2p server version. To run the fixed
worker manually, for example if the tunnel is down, use trusted Tailscale SSH:

```sh
docker compose -f /opt/sp2p-deploy/compose.yml exec -T deploy \
    /usr/local/bin/sp2p-deploy 0.7.2 "$(date +%s)"
```

Run the manual deployment workflow afterward to verify the HTTPS path and
production smoke.

## Migrating from the server-forwarded hook (0.7.2–0.7.3)

Servers 0.7.2 and 0.7.3 forwarded the hook themselves through
`SP2P_DEPLOY_WEBHOOK_URL`; later servers do not. Switch the routing **before** deploying a server without the
forwarding route, or the next hook request reaches sp2p and returns 404:

1. Attach the tunnel connector, `sp2p`, and the sidecar to a shared network
   and add the routes from step 4.
2. Copy the updated [deploy/webhook](../deploy/webhook/) over the installed
   copy, set `SP2P_DEPLOY_NETWORK` to that network along with the other
   `SP2P_DEPLOY_*` variables from step 3, and run
   `docker compose -f /opt/sp2p-deploy/compose.yml up -d --build`.
3. Confirm that an unsigned `POST` to the hook returns 403 **without** a
   `Cache-Control: no-store` header (that header comes from the old in-server
   forwarding), then run the manual deployment workflow.
4. Remove `SP2P_DEPLOY_WEBHOOK_URL` from the production `sp2p` service. A
   leftover environment variable is ignored, but a leftover
   `-deploy-webhook-url` command-line flag stops newer servers from starting.

If the hook path is broken, use the trusted SSH command below to deploy.

## Adding the request-size gate

Sidecars installed before the gate exposed webhook to the tunnel directly.
Copy the updated [deploy/webhook](../deploy/webhook/) over the installed copy
and rerun step 3's `docker compose ... up -d --build` with the same
`SP2P_DEPLOY_*` variables. Compose starts the gate under the existing
`sp2p-deploy` alias and moves webhook to the internal network; the tunnel
routes do not change. Confirm that an unsigned `POST` to the hook still
returns 403 and that a body over 4 KiB returns 413, then run the manual
deployment workflow.

## Deploy an already published release

Run [Deploy published release](../.github/workflows/deploy.yml) from `main`,
providing a full release tag such as `v0.7.1`. It verifies that the GitHub
Release is published, requests that exact server image version, and runs the
production smoke workflow. It neither rebuilds artifacts nor publishes OS
packages. This path can also deploy an older published image for a rollback,
to any server version.

Future full releases invoke the same HTTPS request helper automatically after
publication. A server-only release requests deployment but still needs the
separate production smoke workflow with a suitable CLI tag, as before.

## Local verification

```sh
docker build -t sp2p-deploy-hook:test deploy/webhook
docker build --target gate -t sp2p-deploy-gate:test deploy/webhook
python3 deploy/webhook/test_webhook.py
go test ./deploy/webhook/gate
```

The tests run the actual gate and sidecar, connected as in production, with a
fake Docker executable and **no Docker socket** mounted. They exercise the
4 KiB body limit, signed requests, rejection of invalid requests,
request age, deployment serialization, command failure cleanup, the fixed
service/image selection, and the caller's HTTPS certificate and redirect
handling. Test containers, generated certificates, and scratch files are
removed afterward.
