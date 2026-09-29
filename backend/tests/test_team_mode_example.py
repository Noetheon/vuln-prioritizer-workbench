"""Guard the security properties of the team-mode reference deployment."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path

import yaml

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "team-mode"


def _compose() -> dict:
    return yaml.safe_load((EXAMPLE / "compose.yml").read_text(encoding="utf-8"))


def test_workbench_trusts_only_caddy_and_publishes_no_port() -> None:
    compose = _compose()
    services = compose["services"]
    workbench = services["workbench"]
    caddy_address = services["caddy"]["networks"]["app"]["ipv4_address"]
    subnet = ip_network(compose["networks"]["app"]["ipam"]["config"][0]["subnet"])

    assert "ports" not in workbench
    assert workbench["networks"] == ["app"]
    assert workbench["environment"]["AUTH_MODE"] == "proxy"
    assert workbench["environment"]["TRUSTED_PROXY_CIDRS"] == f"{caddy_address}/32"
    assert ip_address(caddy_address) in subnet
    # Authelia sits on its own network, so it cannot reach the Workbench directly.
    assert services["authelia"]["networks"] == ["auth"]
    assert services["caddy"]["ports"] == ["127.0.0.1:443:443"]


def test_third_party_images_are_pinned_and_secrets_stay_out_of_git() -> None:
    services = _compose()["services"]
    authelia = services["authelia"]
    configuration = (EXAMPLE / "authelia" / "configuration.yml").read_text(encoding="utf-8")
    ignored = (EXAMPLE / ".gitignore").read_text(encoding="utf-8").splitlines()

    assert "@sha256:" in services["caddy"]["image"]
    assert "@sha256:" in authelia["image"]
    assert authelia["environment"]["AUTHELIA_SESSION_SECRET_FILE"].startswith("/run/secrets/")
    assert authelia["environment"]["AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE"].startswith(
        "/run/secrets/"
    )
    for key in ("secret:", "encryption_key:", "jwt_secret:", "password:"):
        assert key not in configuration
    assert "/secrets/" in ignored
    assert "/authelia/users_database.yml" in ignored


def test_authelia_denies_by_default_and_caddy_copies_the_workbench_headers() -> None:
    configuration = yaml.safe_load(
        (EXAMPLE / "authelia" / "configuration.yml").read_text(encoding="utf-8")
    )
    caddyfile = (EXAMPLE / "Caddyfile").read_text(encoding="utf-8")
    environment = _compose()["services"]["workbench"]["environment"]

    access = configuration["access_control"]
    assert access["default_policy"] == "deny"
    assert access["rules"] == [
        {
            "domain": environment["VPW_ALLOWED_HOSTS"],
            "policy": "one_factor",
            "subject": "group:workbench",
        }
    ]
    # The Workbench reads Remote-Email and Remote-Name by default.
    assert "copy_headers Remote-User Remote-Groups Remote-Email Remote-Name" in caddyfile
    assert "uri /api/authz/forward-auth" in caddyfile
