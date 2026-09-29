# Team Mode Behind A Login Proxy

The Workbench is single-user by default: `vpw serve` binds to loopback and
serves one trusted operator without login. Team mode lets a small team share one
instance without the Workbench managing accounts.

In team mode, a reverse proxy you already run signs people in. Examples are
authentik, Authelia, oauth2-proxy, or Keycloak behind oauth2-proxy. The proxy
tells the Workbench who is signed in through a request header. The Workbench
stores no passwords, sends no reset mails, and has no user administration.
Grafana, Gitea/Forgejo, and Paperless-ngx offer the same "auth proxy" model.

## What Changes

- Every API request and WebSocket connection must come from a trusted proxy
  and name a signed-in user. Everything else gets `401 Sign-in required`.
- Health and status routes stay public for container health checks:
  `/api/v1/utils/health-check/`, `/api/v1/workbench/health`, and
  `/api/v1/workbench/status`.
- Audit events and finding status changes record the signed-in user.
- The sidebar shows that user and, when configured, a sign-out link that points
  to the proxy.
- Everyone who can sign in has full access to every project. There are no
  roles. Use the proxy's access rules to decide who may sign in.

## Configure The Workbench

In `vpw.toml` (in the data directory, or passed with `--config`):

```toml
[serve]
# The proxy runs on this machine and forwards to loopback.
host = "127.0.0.1"
# The public name the proxy forwards in the Host header.
allowed_hosts = ["workbench.example.com"]

[auth]
mode = "proxy"
trusted_proxies = ["127.0.0.1"]
user_header = "Remote-Email"       # default
name_header = "Remote-Name"        # default, optional
logout_url = "https://auth.example.com/logout"
```

Containers can use environment variables instead. Environment variables win
over `vpw.toml`.

| Environment variable | `vpw.toml` setting |
| --- | --- |
| `AUTH_MODE=proxy` | `[auth] mode` |
| `TRUSTED_PROXY_CIDRS=172.30.0.0/24` | `[auth] trusted_proxies` |
| `AUTH_PROXY_USER_HEADER` | `[auth] user_header` |
| `AUTH_PROXY_NAME_HEADER` | `[auth] name_header` |
| `AUTH_PROXY_LOGOUT_URL` | `[auth] logout_url` |
| `VPW_ALLOWED_HOSTS=workbench.example.com` | `[serve] allowed_hosts` |

`vpw serve` refuses to start in team mode without trusted proxies. On start it
prints the header it reads the user from.

## Requirements For The Proxy

1. **Sign in every request** to the Workbench, including `/api/` calls and
   WebSocket upgrades.
2. **Set the identity header itself and replace any value a client sent.**
   Traefik ForwardAuth (`authResponseHeaders`) and Caddy `forward_auth`
   (`copy_headers`) replace it; with nginx use `proxy_set_header`. The
   Workbench rejects requests that carry the header more than once.
3. **Preserve the `Host` header** and list the public name in `allowed_hosts`.
   The host check and the cross-site request guard then see the public origin.
4. **Be the only way to reach the Workbench.** If the proxy runs on the same
   host, bind `vpw serve` to loopback. With containers, publish no Workbench
   port and put both containers on one Docker network. `trusted_proxies`
   should name only the proxy's address or its network, because every process
   there can claim to be any user.
5. **Terminate TLS** for the public name.

## Header Names By Proxy

| Proxy | `user_header` | `name_header` |
| --- | --- | --- |
| Authelia (forward auth) | `Remote-Email` | `Remote-Name` |
| authentik (proxy outpost) | `X-authentik-email` | `X-authentik-name` |
| oauth2-proxy (`--set-xauthrequest`) | `X-Auth-Request-Email` | `X-Auth-Request-Preferred-Username` |

## Examples

### Tested Reference Setup: Caddy With Authelia

[`examples/team-mode`](https://github.com/Noetheon/vuln-prioritizer-workbench/tree/main/examples/team-mode) is a complete Docker Compose setup with
Caddy, Authelia, and the Workbench image. `setup.sh` creates random secrets and
the first user, so there is no default login. The Docker workflow starts this
setup on every relevant change and checks it from outside:

- Without a sign-in, API requests get `401` and browsers go to the portal.
- A signed-in user reaches the Workbench under their own name, and identity
  headers sent by the client are replaced.
- A user outside the permitted group gets `403`, and cross-site writes are
  refused.
- WebSocket updates pass through the proxy only after sign-in.
- A request that bypasses the proxy cannot name a user.

The snippets below are starting points for other proxies and are not run in
CI. Follow your proxy's own guide for sessions, cookies, and sign-in redirects.

### Caddy With Authelia

```text
workbench.example.com {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
    }
    reverse_proxy workbench:8765
}
```

### Traefik With Authelia (Docker Compose)

```yaml
services:
  workbench:
    image: ghcr.io/noetheon/vuln-prioritizer-workbench:latest
    environment:
      AUTH_MODE: proxy
      TRUSTED_PROXY_CIDRS: 172.30.0.0/24
      VPW_ALLOWED_HOSTS: workbench.example.com
      AUTH_PROXY_LOGOUT_URL: https://auth.example.com/logout
    volumes:
      - vpw-data:/data
    networks: [proxy]
    labels:
      traefik.enable: "true"
      traefik.http.routers.workbench.rule: Host(`workbench.example.com`)
      traefik.http.routers.workbench.entrypoints: websecure
      traefik.http.routers.workbench.tls: "true"
      traefik.http.routers.workbench.middlewares: authelia@docker
      traefik.http.services.workbench.loadbalancer.server.port: "8765"

# The Authelia service defines the middleware, for example:
#   traefik.http.middlewares.authelia.forwardAuth.address:
#     http://authelia:9091/api/authz/forward-auth
#   traefik.http.middlewares.authelia.forwardAuth.authResponseHeaders:
#     Remote-User,Remote-Groups,Remote-Email,Remote-Name

networks:
  proxy:
    ipam:
      config:
        - subnet: 172.30.0.0/24

volumes:
  vpw-data:
```

### oauth2-proxy Or authentik

- **oauth2-proxy:**
  - Run it with `--reverse-proxy --set-xauthrequest`.
  - Point the ForwardAuth address at `http://oauth2-proxy:4180/oauth2/auth`.
  - Copy `X-Auth-Request-Email,X-Auth-Request-Preferred-Username`.
  - Set `logout_url = "/oauth2/sign_out"`.
- **authentik:**
  - Use the embedded outpost's ForwardAuth endpoint.
  - Copy the `X-authentik-*` headers.

## Automation With `vpw import`

CI imports must pass the proxy too, in one of two ways:

- **Through the proxy:** use the proxy's token support, if it has one. For
  example, oauth2-proxy accepts JWT bearer tokens:

  ```bash
  vpw import scan.json --project web --input-type trivy-json \
    --url https://workbench.example.com \
    --header "Authorization: Bearer $WORKBENCH_TOKEN"
  ```

- **On the Workbench host itself, when loopback is a trusted proxy:** name the
  automation user directly:

  ```bash
  vpw import scan.json --project web --input-type trivy-json \
    --header "Remote-Email: ci@example.com"
  ```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `401 Sign-in required. Requests must come through the configured login proxy.` | The proxy's address is not in `trusted_proxies` (check `docker network inspect`), or the request reached the Workbench directly. |
| `401 Sign-in required. The login proxy did not send one valid … header.` | The header name differs from `user_header`, or the header arrives twice. |
| `400 Invalid host header` | The public name is missing from `allowed_hosts`. |
| `403 Cross-site requests to the Workbench API are not allowed.` | The proxy rewrites `Host`; preserve it. |

The trust boundary is described in the
[threat model](workbench-threat-model.md#team-mode).
