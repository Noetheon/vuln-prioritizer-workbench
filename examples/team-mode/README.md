# Team Mode Reference Deployment

This directory runs the Workbench in
[team mode](../../docs/team-mode.md) behind a login proxy:

- **Caddy** terminates TLS and asks Authelia about every Workbench request.
- **Authelia** signs people in and tells Caddy who they are.
- **The Workbench** accepts the identity headers only from Caddy's fixed
  address and has no published port of its own.

The Docker workflow starts this exact setup on every relevant change
(`scripts/team_mode_example_smoke.sh`, `make team-mode-example-smoke`). It
checks the following from outside the containers:

- Without a sign-in, API requests get `401`, and browsers are sent to the
  sign-in portal.
- An identity header sent by a client without a sign-in is refused.
- A signed-in user reaches the Workbench under their own name. Identity
  headers the client adds are replaced by the proxy.
- A signed-in user outside the `workbench` group gets `403`.
- Writes from the Workbench's own origin work; cross-site writes get `403`.
- WebSocket connections for live workflow updates need a sign-in.
- A request that bypasses Caddy cannot name a user, even with a forged header.

## Try It Locally

Requirements: Docker with Compose, `openssl`, and port 443 free on
`127.0.0.1`.

1. Point the example names at your machine by adding this line to
   `/etc/hosts`:

   ```text
   127.0.0.1 workbench.example.test auth.example.test
   ```

2. Create the secrets and the first user. The script asks for a password and
   hashes it with Authelia, so no default login exists:

   ```bash
   ./setup.sh alice alice@example.com "Alice Example"
   ```

3. Start everything:

   ```bash
   docker compose up -d --wait
   ```

4. Open `https://workbench.example.test` and sign in. Caddy issues the
   certificate from its own local authority, so the browser warns until you
   import that authority into your browser or system trust store:

   ```bash
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt caddy-root.crt
   ```

`docker compose down` stops the setup; `docker compose down --volumes` also
deletes the Workbench data, the Authelia sessions, and Caddy's certificates.

Add more people with `./setup.sh <username> <email> "Display Name"`, then run
`docker compose restart authelia`. A user created with other groups, for
example `./setup.sh bob bob@example.com "Bob" contractors`, can sign in to
Authelia but not open the Workbench.

Scripts can send the same username and password as HTTP Basic credentials.
Authelia accepts them at the forward-auth endpoint, so `vpw import` works with
`--header "Authorization: Basic <base64 of user:password>"`.

## Use It For Real

- Replace `example.test` with your domain in `Caddyfile`,
  `authelia/configuration.yml`, and the `workbench` environment in
  `compose.yml`.
- Remove `local_certs` and `skip_install_trust` from `Caddyfile`, and publish
  port 443 on all interfaces. Caddy then obtains public certificates.
- Pin the Workbench image to the version you tested, for example
  `ghcr.io/noetheon/vuln-prioritizer-workbench:1.4.0`.
- Consider `policy: two_factor` in Authelia and an SMTP notifier, so that
  people can register a second factor and reset passwords.
- Back up the `vpw-data` volume (`vpw backup`) and the `authelia-data` volume,
  and keep `secrets/` and `authelia/users_database.yml` private. `setup.sh`
  creates them with owner-only permissions.
- If `172.30.0.0/24` overlaps a network you use, change the subnet, Caddy's
  `ipv4_address`, and `TRUSTED_PROXY_CIDRS` together.

The rest of the trust model, including what the proxy must guarantee, is in
[Team Mode Behind A Login Proxy](../../docs/team-mode.md) and the
[threat model](../../docs/workbench-threat-model.md#team-mode).
